#!/usr/bin/env python3
# =============================================================================
#  wgm-panel.py - painel web minimo para o wg-server-manager
#  EdenCore / Sagarys  |  Licenca MIT  |  v1.0.0
#
#  Seguranca por Design
#  - So biblioteca padrao do Python: nada de pip, nada para atualizar fora da distro.
#  - Sobe sob demanda (socket do systemd) e encerra quando fica ocioso:
#    no resto do tempo nao ocupa RAM nem tem processo para atacar.
#  - Escuta em 127.0.0.1 por padrao. Acesso por tunel SSH ou pelo nginx com allowlist.
#  - Toda alteracao passa pelo wg-server-manager, com lista de argumentos e sem
#    shell: validacao de conflitos, backup e lock ficam num lugar so.
#  - Senha PBKDF2-SHA256 (600 mil iteracoes), comparacao em tempo constante,
#    bloqueio por IP apos 5 falhas, sessao curta, cookie HttpOnly + Secure +
#    SameSite=Strict e token CSRF em todo POST.
#  - Sem JavaScript; CSP sem recurso externo; Cache-Control no-store, porque
#    paginas de peer podem conter chave privada.
#  - Chave privada so aparece em bloco recolhido, por pedido explicito.
#  - Log de auditoria no journald (usuario, IP de origem, acao) para o SOC.
# =============================================================================
import base64
import getpass
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlsplit

VERSION = "1.0.0"
CONF_PATH = os.environ.get("WGM_PANEL_CONF", "/etc/wgm-panel/panel.conf")
DEFAULTS = {
    "manager": "/usr/local/sbin/wg-server-manager",
    "listen": "127.0.0.1:8751",     # usado so quando o systemd nao entrega o socket
    "base_path": "/",               # ex.: /wgm/ atras do nginx
    "idle_timeout": "600",          # segundos sem acesso ate encerrar (so com socket do systemd)
    "session_ttl": "1800",
    "cookie_secure": "true",
    "trusted_proxies": "127.0.0.1",
    "wg_dir": "",                   # vazio = padrao do script (/etc/wireguard)
    "user": "admin",
    "password_hash": "",
}
RE_IFACE = re.compile(r"^[a-z][a-z0-9_-]{0,14}$")
RE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")
RE_MSG = re.compile(r"^\[(ok|i|!|erro)\]\s?(.*)$")
RE_ANSI = re.compile(r"\x1b\[[0-9;]*m")
RE_IP = re.compile(r"^[0-9a-fA-F:.]{2,45}$")
PBKDF2_ITER = 600_000
MAX_FAILS, LOCK_SECS = 5, 300
MSG_CLASS = {"ok": "ok", "i": "i", "!": "warn", "erro": "err"}
ENV = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
       "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}

CFG = {}
TRUSTED = set()
SESSIONS = {}
FAILS = {}
LOCK = threading.Lock()
ACTIVITY = {"last": time.monotonic(), "active": 0}


# --------------------------------------------------------------- config -----
def load_conf(path):
    conf = dict(DEFAULTS)
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = (x.strip() for x in line.split("=", 1))
                if k in conf:
                    conf[k] = v
    except FileNotFoundError:
        pass
    return conf


def hash_password(pw):
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, PBKDF2_ITER)
    return "pbkdf2_sha256${}${}${}".format(
        PBKDF2_ITER, base64.b64encode(salt).decode(), base64.b64encode(dk).decode())


def check_password(pw, stored):
    try:
        algo, it, salt, dk = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        calc = hashlib.pbkdf2_hmac("sha256", pw.encode(), base64.b64decode(salt), int(it))
        return hmac.compare_digest(calc, base64.b64decode(dk))
    except (ValueError, TypeError):
        return False


def set_password(path):
    pw = getpass.getpass("Nova senha do painel (minimo 12 caracteres): ")
    if len(pw) < 12:
        sys.exit("Senha curta demais.")
    if getpass.getpass("Repita a senha: ") != pw:
        sys.exit("As senhas nao conferem.")
    lines = []
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            lines = [ln.rstrip("\n") for ln in f if not ln.strip().startswith("password_hash")]
    lines.append("password_hash = " + hash_password(pw))
    os.makedirs(os.path.dirname(path) or ".", mode=0o700, exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    os.replace(tmp, path)
    print("Senha gravada em", path)


def log(msg):
    sys.stderr.write(msg + "\n")
    sys.stderr.flush()


# ------------------------------------------------------- wg-server-manager ---
def run_mgr(iface, *args, merge=True, timeout=90):
    """Executa o script sem shell. merge=True junta stdout e stderr na ordem."""
    env = dict(ENV)
    if CFG["wg_dir"]:
        env["WG_DIR"] = CFG["wg_dir"]
    cmd = [CFG["manager"], "-i", iface, *args]
    try:
        p = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT if merge else subprocess.PIPE,
                           text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return 124, "[erro] Tempo esgotado executando o wg-server-manager.", ""
    except OSError as e:
        return 127, "[erro] Não foi possível executar {}: {}".format(CFG["manager"], e), ""
    return p.returncode, RE_ANSI.sub("", p.stdout or ""), RE_ANSI.sub("", p.stderr or "")


def parse_msgs(out):
    """Fica so com as mensagens [ok]/[i]/[!]/[erro] e as linhas indentadas que as seguem.
    Configs de peer impressas pelo script (com chave privada) nunca entram."""
    msgs = []
    for line in out.splitlines():
        m = RE_MSG.match(line)
        if m:
            msgs.append([MSG_CLASS[m.group(1)], m.group(2)])
        elif msgs and line.startswith("    "):
            msgs[-1][1] += "\n" + line.strip()
    return msgs


def get_state(iface):
    rc, out, err = run_mgr(iface, "json", merge=False)
    if rc != 0:
        return None, parse_msgs(out + "\n" + err) or [["err", "Falha ao ler o estado."]]
    try:
        return json.loads(out), []
    except ValueError:
        return None, [["err", "Resposta inválida do wg-server-manager."]]


def list_ifaces():
    base = os.path.join(CFG["wg_dir"] or "/etc/wireguard", "wgm")
    try:
        names = sorted(n for n in os.listdir(base)
                       if RE_IFACE.match(n) and os.path.isfile(os.path.join(base, n, "server.env")))
    except OSError:
        names = []
    return names


def qr_data_uri(text):
    try:
        p = subprocess.run(["qrencode", "-t", "SVG", "-o", "-"], input=text.encode(),
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10, env=ENV)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if p.returncode != 0:
        return None
    return "data:image/svg+xml;base64," + base64.b64encode(p.stdout).decode()


# ---------------------------------------------------------------- helpers ----
def esc(s):
    return html.escape("" if s is None else str(s), quote=True)


def u(path, **q):
    s = CFG["base_path"].rstrip("/") + path
    q = {k: v for k, v in q.items() if v not in (None, "")}
    return s + ("?" + urlencode(q) if q else "")


def hbytes(n):
    n = int(n or 0)
    for unit, size in (("GiB", 1 << 30), ("MiB", 1 << 20), ("KiB", 1 << 10)):
        if n >= size:
            return "{:.1f} {}".format(n / size, unit)
    return "{} B".format(n)


def ago(ts, now):
    ts = int(ts or 0)
    if ts == 0:
        return "nunca"
    d = max(0, int(now) - ts)
    if d < 60:
        return "{}s".format(d)
    if d < 3600:
        return "{}min".format(d // 60)
    if d < 86400:
        return "{}h".format(d // 3600)
    return "{}d".format(d // 86400)


def peer_state(p, now):
    hs = int(p.get("handshake") or 0)
    if hs and now - hs < 180:
        return "on", "online"
    if hs:
        return "idle", "inativo"
    return "off", "nunca conectou"


CSS = """
:root{--bg:#090B0B;--panel:#10151c;--line:#222b37;--txt:#e9eef4;--muted:#8b97a8;
--pri:#344A75;--pri2:#405474;--acc:#17BBD0;--ok:#2fbf71;--warn:#e0a526;--err:#e5484d}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--txt);font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
a{color:var(--acc)}
header{display:flex;flex-wrap:wrap;gap:8px 20px;align-items:center;padding:12px 20px;border-bottom:1px solid var(--line);background:#0c1016}
.brand{font-weight:700;letter-spacing:.08em;margin-right:8px}.brand span{color:var(--acc)}
nav{display:flex;gap:16px;flex:1}nav a{color:var(--muted);text-decoration:none}nav a.on,nav a:hover{color:var(--txt)}
header form{margin:0}
main{max-width:1180px;margin:0 auto;padding:22px 16px 60px}
h1{font-size:20px;margin:0 0 16px}h2{font-size:12px;margin:26px 0 10px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px;margin-bottom:8px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.k{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.07em}
.v{font-size:18px;font-weight:600;margin-top:4px;word-break:break-word}
.tw{overflow-x:auto;border:1px solid var(--line);border-radius:10px}
table{width:100%;border-collapse:collapse;background:var(--panel)}
th,td{padding:9px 12px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top;white-space:nowrap}
td.wrap{white-space:normal}th{color:var(--muted);font-weight:500;font-size:11px;text-transform:uppercase;letter-spacing:.06em}
tr:last-child td{border-bottom:0}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:7px;background:#4b5563}
.dot.on{background:var(--ok)}.dot.idle{background:var(--warn)}.dot.down{background:var(--err)}
.btn{display:inline-block;background:var(--pri);color:#fff;border:1px solid var(--pri2);border-radius:8px;padding:8px 14px;text-decoration:none;cursor:pointer;font:inherit}
.btn:hover{background:var(--pri2)}.btn.acc{background:var(--acc);border-color:var(--acc);color:#04161a;font-weight:600}
.btn.ghost{background:transparent;border-color:var(--line);color:var(--txt)}.btn.danger{background:transparent;border-color:var(--err);color:var(--err)}
.btn.sm{padding:4px 10px;font-size:13px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:14px 16px}
label{display:block;color:var(--muted);font-size:12px;margin-bottom:4px}
input,select{width:100%;background:#0a0e13;color:var(--txt);border:1px solid var(--line);border-radius:8px;padding:8px 10px;font:inherit}
input:focus,select:focus{outline:2px solid var(--acc);outline-offset:-1px}
.chk{display:flex;gap:8px;align-items:center;color:var(--txt);font-size:14px}.chk input{width:auto}
.help{color:var(--muted);font-size:12px;margin-top:4px}
.box{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px}
.actions{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-top:14px}
.flash{border-radius:8px;padding:10px 14px;margin-bottom:10px;border:1px solid var(--line);border-left-width:4px;white-space:pre-wrap;background:var(--panel)}
.flash.ok{border-left-color:var(--ok)}.flash.warn{border-left-color:var(--warn)}.flash.err{border-left-color:var(--err)}.flash.i{border-left-color:var(--acc)}
pre{background:#0a0e13;border:1px solid var(--line);border-radius:8px;padding:12px;overflow:auto;font-size:13px;margin:10px 0 0}
details{margin-top:10px}summary{cursor:pointer;color:var(--acc)}
.qr{background:#fff;padding:12px;border-radius:8px;width:280px;max-width:100%;margin-top:10px}
.tag{border:1px solid var(--line);border-radius:999px;padding:1px 9px;font-size:12px;color:var(--muted)}
.login{max-width:360px;margin:12vh auto}.muted{color:var(--muted)}
.split{display:grid;grid-template-columns:1fr 1fr;gap:16px}@media(max-width:820px){.split{grid-template-columns:1fr}}
"""


# --------------------------------------------------------------- handler -----
class Handler(BaseHTTPRequestHandler):
    server_version = "wgm-panel"
    sys_version = ""

    # ---- infraestrutura
    def log_message(self, fmt, *args):
        log("{} {}".format(self.client_ip(), fmt % args))

    def client_ip(self):
        peer = self.client_address[0] if self.client_address else "-"
        if peer in TRUSTED:
            real = (self.headers.get("X-Real-IP") or "").strip()
            if RE_IP.match(real):
                return real
        return peer

    def audit(self, action, **kw):
        extra = " ".join("{}={}".format(k, v) for k, v in kw.items())
        log("AUDIT user={} ip={} action={} {}".format(CFG["user"], self.client_ip(), action, extra).rstrip())

    def headers_common(self):
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; style-src 'nonce-{}'; img-src data:; form-action 'self'; "
                         "frame-ancestors 'none'; base-uri 'none'".format(self.nonce))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")

    def send_html(self, body, status=200, cookies=()):
        data = body.encode("utf-8")
        self.send_response(status)
        self.headers_common()
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for c in cookies:
            self.send_header("Set-Cookie", c)
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, location, cookies=()):
        self.send_response(303)
        self.headers_common()
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        for c in cookies:
            self.send_header("Set-Cookie", c)
        self.end_headers()

    def send_download(self, text, filename):
        data = text.encode("utf-8")
        self.send_response(200)
        self.headers_common()
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Disposition", 'attachment; filename="{}"'.format(filename))
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def cookie(self, value, max_age):
        flags = "Path={}; HttpOnly; SameSite=Strict; Max-Age={}".format(CFG["base_path"], max_age)
        if CFG["cookie_secure"] == "true":
            flags += "; Secure"
        return "wgm_sid={}; {}".format(value, flags)

    def do_GET(self):
        self.dispatch("GET")

    def do_POST(self):
        self.dispatch("POST")

    def dispatch(self, method):
        with LOCK:
            ACTIVITY["active"] += 1
        self.nonce = secrets.token_urlsafe(16)
        self.sess, self.query, self.form = None, {}, {}
        try:
            parts = urlsplit(self.path)
            path = parts.path
            base = CFG["base_path"].rstrip("/")
            if base:
                if not (path == base or path.startswith(base + "/")):
                    return self.send_html(self.page("Não encontrado", "<p>Página inexistente.</p>"), 404)
                path = path[len(base):] or "/"
            self.query = {k: v[0] for k, v in parse_qs(parts.query).items()}
            self.form = self.read_form() if method == "POST" else {}
            self.sess = self.get_session()
            if path == "/login":
                return self.login_get() if method == "GET" else self.login_post()
            if self.sess is None:
                return self.redirect(u("/login"))
            if method == "POST" and not hmac.compare_digest(self.form.get("csrf", ""), self.sess["csrf"]):
                self.audit("csrf_rejeitado", path=path)
                return self.send_html(self.page("Requisição recusada", "<p>Token CSRF inválido. Recarregue a página.</p>"), 403)
            route = ROUTES.get((method, path))
            if route is None:
                return self.send_html(self.page("Não encontrado", "<p>Página inexistente.</p>"), 404)
            return route(self)
        except ValueError as e:
            self.send_html(self.page("Requisição inválida", "<p>{}</p>".format(esc(e))), 400)
        except Exception as e:  # nunca devolve stack trace ao navegador
            log("ERRO {} {}: {!r}".format(method, self.path, e))
            self.send_html(self.page("Erro", "<p>Erro interno. Veja o journal do serviço.</p>"), 500)
        finally:
            with LOCK:
                ACTIVITY["active"] -= 1
                ACTIVITY["last"] = time.monotonic()

    def read_form(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > 65536:
            raise ValueError("Formulário grande demais.")
        raw = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        return {k: v[0].strip() for k, v in parse_qs(raw, keep_blank_values=True).items()}

    # ---- sessao
    def get_session(self):
        sid = None
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "wgm_sid":
                sid = v
        if not sid:
            return None
        now = time.time()
        with LOCK:
            s = SESSIONS.get(sid)
            if not s or s["exp"] < now:
                SESSIONS.pop(sid, None)
                return None
            s["exp"] = now + int(CFG["session_ttl"])
            s["sid"] = sid
            return s

    def flash(self, msgs):
        self.sess.setdefault("flash", []).extend(msgs)

    def take_flash(self):
        if not self.sess:
            return []
        msgs, self.sess["flash"] = self.sess.get("flash", []), []
        return msgs

    # ---- layout
    def page(self, title, body, iface=None, extra_msgs=()):
        nav = ""
        if getattr(self, "sess", None):
            cur = self.path.split("?")[0]
            def a(p, label):
                full = u(p)
                cls = ' class="on"' if cur == full else ""
                return '<a{} href="{}">{}</a>'.format(cls, esc(u(p, i=iface)), label)
            nav = ('<nav>{}{}{}</nav>'.format(a("/", "Painel"), a("/peer/new", "Novo peer"), a("/server", "Servidor"))
                   + '<form method="post" action="{}"><input type="hidden" name="csrf" value="{}">'
                     '<button class="btn ghost sm">Sair</button></form>'.format(esc(u("/logout")), esc(self.sess["csrf"])))
        msgs = list(self.take_flash()) + list(extra_msgs)
        flashes = "".join('<div class="flash {}">{}</div>'.format(c, esc(t)) for c, t in msgs)
        return ('<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">'
                '<meta name="viewport" content="width=device-width,initial-scale=1">'
                '<title>{t} | wgm-panel</title><style nonce="{n}">{css}</style></head><body>'
                '<header><div class="brand">WG<span>M</span> PANEL</div>{nav}</header>'
                '<main>{f}{b}</main></body></html>').format(
                    t=esc(title), n=self.nonce, css=CSS, nav=nav, f=flashes, b=body)

    def csrf_input(self):
        return '<input type="hidden" name="csrf" value="{}">'.format(esc(self.sess["csrf"]))

    def iface_param(self, src=None):
        src = self.query if src is None else src
        iface = src.get("i") or (list_ifaces() or ["wg0"])[0]
        if not RE_IFACE.match(iface):
            raise ValueError("Interface inválida.")
        return iface

    # ---- login
    def login_get(self, msgs=()):
        if self.sess:
            return self.redirect(u("/"))
        body = ('<div class="login box"><h1>Entrar</h1><form method="post" action="{}">'
                '<label>Usuário</label><input name="user" autocomplete="username" required>'
                '<label>Senha</label><input name="password" type="password" autocomplete="current-password" required>'
                '<div class="actions"><button class="btn acc">Entrar</button></div></form></div>').format(esc(u("/login")))
        self.send_html(self.page("Entrar", body, extra_msgs=msgs))

    def login_post(self):
        ip = self.client_ip()
        now = time.time()
        with LOCK:
            fails, until = FAILS.get(ip, (0, 0))
        if until > now:
            self.audit("login_bloqueado")
            return self.login_get([["err", "Muitas tentativas. Aguarde alguns minutos."]])
        user_ok = hmac.compare_digest(self.form.get("user", "").encode(), CFG["user"].encode())
        pass_ok = check_password(self.form.get("password", ""), CFG["password_hash"])
        if not (user_ok and pass_ok):
            fails += 1
            with LOCK:
                FAILS[ip] = (fails, now + LOCK_SECS if fails >= MAX_FAILS else 0)
            self.audit("login_falhou", tentativas=fails)
            return self.login_get([["err", "Usuário ou senha inválidos."]])
        with LOCK:
            FAILS.pop(ip, None)
            for sid in [k for k, v in SESSIONS.items() if v["exp"] < now]:
                SESSIONS.pop(sid, None)
            sid = secrets.token_urlsafe(32)
            SESSIONS[sid] = {"exp": now + int(CFG["session_ttl"]), "csrf": secrets.token_urlsafe(32), "flash": []}
        self.audit("login_ok")
        self.redirect(u("/"), cookies=[self.cookie(sid, int(CFG["session_ttl"]))])

    def logout(self):
        with LOCK:
            SESSIONS.pop(self.sess["sid"], None)
        self.audit("logout")
        self.redirect(u("/login"), cookies=[self.cookie("", 0)])

    # ---- painel
    def dashboard(self):
        iface = self.iface_param()
        ifaces = list_ifaces()
        st, msgs = get_state(iface)
        sel = ""
        if len(ifaces) > 1:
            opts = "".join('<option{}>{}</option>'.format(" selected" if n == iface else "", esc(n)) for n in ifaces)
            sel = ('<form method="get" action="{}" class="actions"><select name="i">{}</select>'
                   '<button class="btn ghost sm">Trocar</button></form>').format(esc(u("/")), opts)
        if st is None:
            return self.send_html(self.page("Painel", "<h1>Painel</h1>" + sel, iface, msgs))
        if not st["exists"]:
            body = ('<h1>Nenhum servidor em {i}</h1><p class="muted">Crie o servidor WireGuard para começar.</p>'
                    '<a class="btn acc" href="{l}">Criar servidor</a>').format(i=esc(iface), l=esc(u("/server", i=iface)))
            return self.send_html(self.page("Painel", body + sel, iface))
        s, peers, now = st["server"], st["peers"], st["now"]
        online = sum(1 for p in peers if peer_state(p, now)[0] == "on")
        up_dot = "on" if s["up"] else "down"
        cards = [
            ("Interface", '<span class="dot {}"></span>{} {}'.format(
                up_dot, esc(iface), "ativa" if s["up"] else "parada")),
            ("Serviço", esc(s["service"])),
            ("Peers online", "{} de {}".format(online, len(peers))),
            ("Endpoint", '<span class="mono">{}</span>'.format(esc(s["endpoint"]))),
            ("Rede do túnel", '<span class="mono">{}</span>'.format(esc(s["network"]))),
            ("Redes do servidor", '<span class="mono">{}</span>'.format(esc(s["lans"] or "nenhuma"))),
        ]
        cards_html = "".join('<div class="card"><div class="k">{}</div><div class="v">{}</div></div>'.format(k, v)
                             for k, v in cards)
        rows = []
        for p in peers:
            cls, label = peer_state(p, now)
            rows.append(
                '<tr><td><span class="dot {cls}"></span>{label}</td>'
                '<td><a href="{link}">{name}</a></td><td><span class="tag">{type}</span></td>'
                '<td class="mono">{ip}</td><td class="mono wrap">{lans}</td><td>{hs}</td>'
                '<td>{rx} / {tx}</td><td class="mono">{ep}</td></tr>'.format(
                    cls=cls, label=label, link=esc(u("/peer", i=iface, n=p["name"])), name=esc(p["name"]),
                    type=esc(p["type"]), ip=esc(p["ip"]), lans=esc(p["lans"] or "-"),
                    hs=ago(p["handshake"], now), rx=hbytes(p["rx"]), tx=hbytes(p["tx"]),
                    ep=esc("-" if p["endpoint"] == "(none)" else p["endpoint"])))
        table = ('<div class="tw"><table><thead><tr><th>Estado</th><th>Peer</th><th>Tipo</th><th>IP no túnel</th>'
                 '<th>Redes atrás do peer</th><th>Handshake</th><th>Recebido / enviado</th><th>Origem real</th>'
                 '</tr></thead><tbody>{}</tbody></table></div>').format(
                     "".join(rows) or '<tr><td colspan="8" class="muted">Nenhum peer ainda.</td></tr>')
        body = ('<h1>Painel</h1>{sel}<div class="cards">{c}</div>'
                '<h2>Peers</h2>{t}<div class="actions"><a class="btn acc" href="{new}">Novo peer</a>'
                '<a class="btn ghost" href="{me}">Atualizar</a></div>').format(
                    sel=sel, c=cards_html, t=table, new=esc(u("/peer/new", i=iface)), me=esc(u("/", i=iface)))
        self.send_html(self.page("Painel", body, iface))

    # ---- peer: criar
    def peer_new_get(self, values=None, msgs=()):
        iface = self.iface_param(values) if values else self.iface_param()
        st, smsgs = get_state(iface)
        if st is None or not st["exists"]:
            self.flash(smsgs or [["warn", "Crie o servidor antes de adicionar peers."]])
            return self.redirect(u("/server", i=iface))
        v = {"i": iface, "name": "", "type": "client", "lans": "", "ip": "", "ca": "auto", "pubkey": "",
             "psk": "1", "ka": str(st["server"]["keepalive"])}
        if values:
            v.update(values)
        auto = st["server"]["network"] + (", " + st["server"]["lans"] if st["server"]["lans"] else "")
        def opt(val, label):
            return '<option value="{}"{}>{}</option>'.format(val, " selected" if v["type"] == val else "", label)
        body = (
            '<h1>Novo peer em {i}</h1><form method="post" action="{act}" class="box">{csrf}'
            '<input type="hidden" name="i" value="{i}"><div class="grid">'
            '<div><label>Nome</label><input name="name" value="{name}" required maxlength="32" pattern="[A-Za-z0-9][A-Za-z0-9._-]*">'
            '<div class="help">Letras, números, ponto, _ e -. Ex.: FILIAL-SC, NOTE-DANIEL</div></div>'
            '<div><label>Tipo</label><select name="type">{o1}{o2}</select>'
            '<div class="help">client: notebook, celular, servidor. site: roteador com rede atrás.</div></div>'
            '<div><label>Redes atrás do peer (AllowedIPs no servidor)</label><input name="lans" value="{lans}" placeholder="10.30.0.0/24">'
            '<div class="help">LAN do site. Vazio para client comum. Separe por vírgula.</div></div>'
            '<div><label>O que o peer manda pelo túnel (AllowedIPs no peer)</label><input name="ca" value="{ca}">'
            '<div class="help">auto = {auto}. full = todo o tráfego. Ou uma lista de redes.</div></div>'
            '<div><label>IP no túnel</label><input name="ip" value="{ip}" placeholder="automático">'
            '<div class="help">Vazio = próximo IP livre em {net}.</div></div>'
            '<div><label>Keepalive (s)</label><input name="ka" value="{ka}" inputmode="numeric"></div>'
            '<div><label>Chave pública gerada no próprio peer (opcional)</label><input name="pubkey" value="{pub}" class="mono">'
            '<div class="help">Preenchida, a chave privada nunca passa pelo servidor.</div></div>'
            '<div><label>&nbsp;</label><label class="chk"><input type="checkbox" name="psk" value="1"{psk}> Usar PresharedKey (recomendado)</label></div>'
            '</div><div class="actions"><button class="btn acc">Criar peer</button>'
            '<a class="btn ghost" href="{back}">Cancelar</a></div></form>').format(
                i=esc(iface), act=esc(u("/peer/new")), csrf=self.csrf_input(), name=esc(v["name"]),
                o1=opt("client", "client"), o2=opt("site", "site"), lans=esc(v["lans"]), ca=esc(v["ca"]),
                auto=esc(auto), ip=esc(v["ip"]), net=esc(st["server"]["network"]), ka=esc(v["ka"]),
                pub=esc(v["pubkey"]), psk=" checked" if v.get("psk") == "1" else "", back=esc(u("/", i=iface)))
        self.send_html(self.page("Novo peer", body, iface, msgs))

    def peer_new_post(self):
        f = self.form
        iface = self.iface_param(f)
        name = f.get("name", "")
        if not RE_NAME.match(name):
            return self.peer_new_get(f, [["err", "Nome inválido."]])
        if f.get("type") not in ("client", "site"):
            return self.peer_new_get(f, [["err", "Tipo inválido."]])
        args = ["peer", "add", name, "-t", f["type"], "-A", f.get("ca") or "auto"]
        if f.get("lans"):
            args += ["-L", f["lans"]]
        if f.get("ip"):
            args += ["-I", f["ip"]]
        if f.get("ka"):
            args += ["-k", f["ka"]]
        if f.get("pubkey"):
            args += ["--pubkey", f["pubkey"]]
        if f.get("psk") != "1":
            args.append("--no-psk")
        rc, out, _ = run_mgr(iface, *args)
        msgs = parse_msgs(out)
        self.audit("peer_add", iface=iface, peer=name, tipo=f["type"], rc=rc)
        if rc != 0:
            return self.peer_new_get(f, msgs or [["err", "Falha ao criar o peer."]])
        self.flash(msgs)
        self.redirect(u("/peer", i=iface, n=name))

    # ---- peer: detalhe
    def find_peer(self, src=None):
        src = self.query if src is None else src
        iface = self.iface_param(src)
        name = src.get("n", "")
        if not RE_NAME.match(name):
            raise ValueError("Peer inválido.")
        st, msgs = get_state(iface)
        if st is None:
            return iface, name, None, None, msgs
        peer = next((p for p in st.get("peers", []) if p["name"] == name), None)
        return iface, name, st, peer, msgs

    def peer_view(self):
        iface, name, st, p, msgs = self.find_peer()
        if p is None:
            self.flash(msgs or [["err", "Peer '{}' não existe.".format(name)]])
            return self.redirect(u("/", i=iface))
        now = st["now"]
        cls, label = peer_state(p, now)
        _, conf, _ = run_mgr(iface, "peer", "show", name, merge=False)
        _, rsc, _ = run_mgr(iface, "peer", "show", name, "--mikrotik", merge=False)
        info = [
            ("Estado", '<span class="dot {}"></span>{}'.format(cls, label)),
            ("Tipo", esc(p["type"])),
            ("IP no túnel", '<span class="mono">{}</span>'.format(esc(p["ip"]))),
            ("Handshake", ago(p["handshake"], now)),
            ("Recebido / enviado", "{} / {}".format(hbytes(p["rx"]), hbytes(p["tx"]))),
            ("Origem real", '<span class="mono">{}</span>'.format(esc("-" if p["endpoint"] == "(none)" else p["endpoint"]))),
            ("AllowedIPs no servidor", '<span class="mono">{}</span>'.format(esc(p["server_allowed"]))),
            ("AllowedIPs no peer", '<span class="mono">{}</span>'.format(esc(p["client_allowed"]))),
            ("Chave pública", '<span class="mono">{}</span>'.format(esc(p["public_key"]))),
            ("PresharedKey", "sim" if p["has_psk"] else "não"),
            ("Chave privada no servidor", "sim" if p["has_private_key"] else "não"),
            ("Criado em", esc(p["created"])),
        ]
        info_html = "".join('<div class="card"><div class="k">{}</div><div class="v">{}</div></div>'.format(k, v)
                            for k, v in info)
        warn = ""
        qr = ""
        if p["has_private_key"]:
            warn = ('<div class="flash warn">A config abaixo contém a chave privada do peer. Entregue por canal seguro '
                    'e depois apague a cópia do servidor em "Apagar chave privada".</div>')
            uri = qr_data_uri(conf)
            if uri:
                qr = '<details><summary>Mostrar QR code (app WireGuard no celular)</summary><img class="qr" alt="QR code da config" src="{}"></details>'.format(uri)
        else:
            warn = ('<div class="flash i">A chave privada não está no servidor. A config sai com o marcador '
                    '&lt;CHAVE_PRIVADA_DO_PEER&gt;; use a chave que já está no peer.</div>')
        cfg = (
            '<h2>Config do peer</h2>{warn}<div class="actions">'
            '<a class="btn" href="{dl}">Baixar .conf</a><a class="btn ghost" href="{dlr}">Baixar script MikroTik (.rsc)</a></div>'
            '<details><summary>Mostrar config (.conf)</summary><pre class="mono">{conf}</pre></details>'
            '<details><summary>Mostrar script MikroTik RouterOS v7</summary><pre class="mono">{rsc}</pre></details>{qr}').format(
                warn=warn, dl=esc(u("/peer/download", i=iface, n=name, fmt="conf")),
                dlr=esc(u("/peer/download", i=iface, n=name, fmt="rsc")), conf=esc(conf), rsc=esc(rsc), qr=qr)
        edit = (
            '<h2>Alterar allowed address</h2><form method="post" action="{act}" class="box">{csrf}'
            '<input type="hidden" name="i" value="{i}"><input type="hidden" name="n" value="{n}"><div class="grid">'
            '<div><label>IP no túnel</label><input name="ip" value="{ip}"></div>'
            '<div><label>Redes atrás do peer (AllowedIPs no servidor)</label><input name="lans" value="{lans}" placeholder="vazio = nenhuma"></div>'
            '<div><label>O que o peer manda pelo túnel (AllowedIPs no peer)</label><input name="ca" value="{ca}">'
            '<div class="help">auto, full ou lista de redes.</div></div></div>'
            '<div class="help">Aplicado sem derrubar o túnel. Mudou IP ou o lado do peer? Reenvie a config ao peer.</div>'
            '<div class="actions"><button class="btn acc">Salvar</button></div></form>').format(
                act=esc(u("/peer/allowed")), csrf=self.csrf_input(), i=esc(iface), n=esc(name), ip=esc(p["ip"]),
                lans=esc(p["lans"]), ca=esc(p["client_allowed_mode"]))
        danger = '<h2>Ações</h2><div class="split">'
        if p["has_private_key"]:
            danger += ('<form method="post" action="{}" class="box">{}<input type="hidden" name="i" value="{}">'
                       '<input type="hidden" name="n" value="{}"><p>Apaga a chave privada do servidor (o peer continua funcionando com a config já entregue).</p>'
                       '<button class="btn">Apagar chave privada</button></form>').format(
                           esc(u("/peer/wipe")), self.csrf_input(), esc(iface), esc(name))
        danger += ('<form method="post" action="{}" class="box">{}<input type="hidden" name="i" value="{}">'
                   '<input type="hidden" name="n" value="{}"><p>Remove o peer, as chaves e as rotas. O acesso dele cai na hora.</p>'
                   '<label class="chk"><input type="checkbox" name="confirm" value="1" required> Confirmo a remoção de {}</label>'
                   '<div class="actions"><button class="btn danger">Remover peer</button></div></form></div>').format(
                       esc(u("/peer/delete")), self.csrf_input(), esc(iface), esc(name), esc(name))
        body = '<h1>{} <span class="tag">{}</span></h1><div class="cards">{}</div>{}{}{}'.format(
            esc(name), esc(iface), info_html, cfg, edit, danger)
        self.send_html(self.page(name, body, iface))

    def peer_download(self):
        iface, name, st, p, msgs = self.find_peer()
        if p is None:
            self.flash(msgs or [["err", "Peer não existe."]])
            return self.redirect(u("/", i=iface))
        fmt = self.query.get("fmt", "conf")
        args = ["peer", "show", name] + (["--mikrotik"] if fmt == "rsc" else [])
        rc, out, _ = run_mgr(iface, *args, merge=False)
        if rc != 0:
            self.flash([["err", "Falha ao gerar a config."]])
            return self.redirect(u("/peer", i=iface, n=name))
        self.audit("peer_download", iface=iface, peer=name, formato=fmt, privada=p["has_private_key"])
        self.send_download(out, "{}.{}".format(name, "rsc" if fmt == "rsc" else "conf"))

    def peer_allowed_post(self):
        f = self.form
        iface, name, st, p, msgs = self.find_peer(f)
        if p is None:
            self.flash(msgs or [["err", "Peer não existe."]])
            return self.redirect(u("/", i=iface))
        args = ["peer", "allowed", name, "-I", f.get("ip") or p["ip"], "-L", f.get("lans") or "none",
                "-A", f.get("ca") or "auto"]
        rc, out, _ = run_mgr(iface, *args)
        self.audit("peer_allowed", iface=iface, peer=name, rc=rc)
        self.flash(parse_msgs(out) or [["err" if rc else "ok", "Concluído." if rc == 0 else "Falhou."]])
        self.redirect(u("/peer", i=iface, n=name))

    def peer_wipe_post(self):
        iface, name, _, _, _ = self.find_peer(self.form)
        rc, out, _ = run_mgr(iface, "peer", "wipe-key", name)
        self.audit("peer_wipe_key", iface=iface, peer=name, rc=rc)
        self.flash(parse_msgs(out))
        self.redirect(u("/peer", i=iface, n=name))

    def peer_delete_post(self):
        iface, name, _, _, _ = self.find_peer(self.form)
        if self.form.get("confirm") != "1":
            self.flash([["warn", "Marque a confirmação para remover."]])
            return self.redirect(u("/peer", i=iface, n=name))
        rc, out, _ = run_mgr(iface, "peer", "del", name, "-y")
        self.audit("peer_del", iface=iface, peer=name, rc=rc)
        self.flash(parse_msgs(out))
        self.redirect(u("/", i=iface) if rc == 0 else u("/peer", i=iface, n=name))

    # ---- servidor
    def server_get(self, values=None, msgs=()):
        iface = self.iface_param(values) if values else self.iface_param()
        if self.query.get("new") == "1" and not values:
            iface = ""
        st, smsgs = get_state(iface) if iface else ({"exists": False}, [])
        if st is None:
            return self.send_html(self.page("Servidor", "<h1>Servidor</h1>", iface, smsgs))
        if not st["exists"]:
            v = {"i": iface or "wg0", "addr": "10.99.0.1/24", "port": "51820", "ep": "", "dns": "", "lans": "",
                 "nat": "none", "isolate": "1", "mtu": "1420", "ka": "25"}
            if values:
                v.update(values)
            body = (
                '<h1>Criar servidor WireGuard</h1><form method="post" action="{act}" class="box">{csrf}<div class="grid">'
                '<div><label>Interface</label><input name="i" value="{i}" required pattern="[a-z][a-z0-9_-]*" maxlength="15"></div>'
                '<div><label>IP/máscara do servidor no túnel</label><input name="addr" value="{addr}" required>'
                '<div class="help">Os peers recebem IPs desta rede.</div></div>'
                '<div><label>Porta UDP</label><input name="port" value="{port}" inputmode="numeric"></div>'
                '<div><label>Endpoint público (IP ou DDNS)</label><input name="ep" value="{ep}" placeholder="vpn.exemplo.com.br">'
                '<div class="help">Endereço que os peers usam para chegar aqui.</div></div>'
                '<div><label>Redes atrás do servidor</label><input name="lans" value="{lans}" placeholder="vazio = nenhuma">'
                '<div class="help">Entram no "auto" dos peers.</div></div>'
                '<div><label>DNS para peers client</label><input name="dns" value="{dns}" placeholder="vazio = nenhum"></div>'
                '<div><label>Interface para NAT de internet</label><input name="nat" value="{nat}">'
                '<div class="help">none = a VPN não vira saída de internet.</div></div>'
                '<div><label>MTU</label><input name="mtu" value="{mtu}"></div>'
                '<div><label>Keepalive padrão (s)</label><input name="ka" value="{ka}"></div>'
                '<div><label>&nbsp;</label><label class="chk"><input type="checkbox" name="isolate" value="1"{iso}> Isolar peers entre si</label></div>'
                '</div><div class="actions"><button class="btn acc">Criar servidor</button></div></form>').format(
                    act=esc(u("/server/init")), csrf=self.csrf_input(), i=esc(v["i"]), addr=esc(v["addr"]),
                    port=esc(v["port"]), ep=esc(v["ep"]), lans=esc(v["lans"]), dns=esc(v["dns"]), nat=esc(v["nat"]),
                    mtu=esc(v["mtu"]), ka=esc(v["ka"]), iso=" checked" if v.get("isolate") == "1" else "")
            return self.send_html(self.page("Servidor", body, iface or None, msgs))
        s = st["server"]
        rc, diag, _ = run_mgr(iface, "status")
        info = "".join('<div class="card"><div class="k">{}</div><div class="v mono">{}</div></div>'.format(k, esc(v)) for k, v in (
            ("Endereço", s["address"]), ("Porta", "{}/udp".format(s["port"])), ("MTU", s["mtu"]),
            ("Chave pública", s["public_key"]), ("Criado em", s["created"])))
        def sel(val):
            return "".join('<option{}>{}</option>'.format(" selected" if val == o else "", o) for o in ("yes", "no"))
        body = (
            '<h1>Servidor {i}</h1><div class="cards">{info}</div>'
            '<h2>Configuração</h2><form method="post" action="{act}" class="box">{csrf}<input type="hidden" name="i" value="{i}">'
            '<div class="grid">'
            '<div><label>Endpoint público</label><input name="ep" value="{ep}"></div>'
            '<div><label>Redes atrás do servidor</label><input name="lans" value="{lans}" placeholder="vazio = nenhuma"></div>'
            '<div><label>DNS para peers client</label><input name="dns" value="{dns}" placeholder="vazio = nenhum"></div>'
            '<div><label>Interface para NAT de internet</label><input name="nat" value="{nat}"></div>'
            '<div><label>Isolar peers entre si</label><select name="isolate">{iso}</select></div>'
            '<div><label>Keepalive padrão para novos peers (s)</label><input name="ka" value="{ka}"></div>'
            '</div><div class="help">Mudou endpoint, DNS ou redes? Reenvie a config aos peers.</div>'
            '<div class="actions"><button class="btn acc">Salvar</button></div></form>'
            '<h2>Manutenção</h2><form method="post" action="{apply}" class="box">{csrf}<input type="hidden" name="i" value="{i}">'
            '<p>Regera a config a partir do estado e reaplica sem derrubar o túnel.</p><button class="btn">Regerar e aplicar</button></form>'
            '<h2>Diagnóstico</h2><pre class="mono">{diag}</pre>'
            '<div class="actions"><a class="btn ghost" href="{new}">Criar outra interface</a></div>').format(
                i=esc(iface), info=info, act=esc(u("/server/set")), csrf=self.csrf_input(), ep=esc(s["endpoint"]),
                lans=esc(s["lans"]), dns=esc(s["dns"]), nat=esc(s["nat_if"]), iso=sel(s["isolate"]),
                ka=esc(s["keepalive"]), apply=esc(u("/server/apply")), diag=esc(diag.strip()),
                new=esc(u("/server", new="1")))
        self.send_html(self.page("Servidor", body, iface, msgs))

    def server_init_post(self):
        f = self.form
        iface = f.get("i", "")
        if not RE_IFACE.match(iface):
            return self.server_get(dict(f, i="wg0"), [["err", "Nome de interface inválido."]])
        args = ["init", "-a", f.get("addr") or "10.99.0.1/24", "-p", f.get("port") or "51820",
                "-n", f.get("nat") or "none", "-m", f.get("mtu") or "1420", "-k", f.get("ka") or "25"]
        for key, opt in (("ep", "-e"), ("dns", "-d"), ("lans", "-l")):
            if f.get(key):
                args += [opt, f[key]]
        if f.get("isolate") != "1":
            args.append("--no-isolate")
        rc, out, _ = run_mgr(iface, *args, timeout=120)
        self.audit("server_init", iface=iface, rc=rc)
        msgs = parse_msgs(out)
        if rc != 0:
            return self.server_get(f, msgs or [["err", "Falha ao criar o servidor."]])
        self.flash(msgs)
        self.redirect(u("/", i=iface))

    def server_set_post(self):
        f = self.form
        iface = self.iface_param(f)
        args = ["server", "set", "-e", f.get("ep", ""), "-d", f.get("dns") or "none", "-l", f.get("lans") or "none",
                "-n", f.get("nat") or "none", "--isolate", f.get("isolate", "yes"), "-k", f.get("ka") or "25"]
        rc, out, _ = run_mgr(iface, *args)
        self.audit("server_set", iface=iface, rc=rc)
        self.flash(parse_msgs(out) or [["err", "Falhou."]])
        self.redirect(u("/server", i=iface))

    def server_apply_post(self):
        iface = self.iface_param(self.form)
        rc, out, _ = run_mgr(iface, "apply")
        self.audit("server_apply", iface=iface, rc=rc)
        self.flash(parse_msgs(out) or [["ok" if rc == 0 else "err", "Aplicado." if rc == 0 else "Falhou."]])
        self.redirect(u("/server", i=iface))


ROUTES = {
    ("GET", "/"): Handler.dashboard,
    ("GET", "/peer"): Handler.peer_view,
    ("GET", "/peer/new"): lambda h: h.peer_new_get(),
    ("POST", "/peer/new"): Handler.peer_new_post,
    ("GET", "/peer/download"): Handler.peer_download,
    ("POST", "/peer/allowed"): Handler.peer_allowed_post,
    ("POST", "/peer/wipe"): Handler.peer_wipe_post,
    ("POST", "/peer/delete"): Handler.peer_delete_post,
    ("GET", "/server"): lambda h: h.server_get(),
    ("POST", "/server/init"): Handler.server_init_post,
    ("POST", "/server/set"): Handler.server_set_post,
    ("POST", "/server/apply"): Handler.server_apply_post,
    ("POST", "/logout"): Handler.logout,
}


# ---------------------------------------------------------------- servidor ---
def make_server():
    """Usa o socket entregue pelo systemd (LISTEN_FDS) ou abre o 'listen' do panel.conf."""
    activated = os.environ.get("LISTEN_PID") == str(os.getpid()) and int(os.environ.get("LISTEN_FDS", "0")) >= 1
    if activated:
        sock = socket.socket(fileno=3)
        srv = ThreadingHTTPServer(sock.getsockname()[:2], Handler, bind_and_activate=False)
        srv.socket.close()
        srv.socket = sock
        srv.server_address = sock.getsockname()[:2]
    else:
        host, _, port = CFG["listen"].rpartition(":")
        srv = ThreadingHTTPServer((host.strip("[]"), int(port)), Handler)
    srv.daemon_threads = True
    return srv, activated


def idle_watch(srv, timeout):
    while True:
        time.sleep(min(15, max(1, timeout // 4)))
        with LOCK:
            idle = ACTIVITY["active"] == 0 and time.monotonic() - ACTIVITY["last"] > timeout
        if idle:
            log("ocioso ha mais de {}s: encerrando (o systemd reabre no proximo acesso)".format(timeout))
            srv.shutdown()
            return


def main():
    if len(sys.argv) > 1 and sys.argv[1] in ("--set-password", "-p"):
        return set_password(CONF_PATH)
    if len(sys.argv) > 1 and sys.argv[1] in ("--version", "-V"):
        return print("wgm-panel", VERSION)
    CFG.update(load_conf(CONF_PATH))
    if not CFG["base_path"].startswith("/"):
        sys.exit("base_path deve comecar com /")
    if not CFG["base_path"].endswith("/"):
        CFG["base_path"] += "/"
    TRUSTED.update(x.strip() for x in CFG["trusted_proxies"].split(",") if x.strip())
    if not CFG["password_hash"]:
        sys.exit("Sem senha configurada. Rode: wgm-panel --set-password")
    if os.geteuid() != 0:
        log("aviso: o painel nao esta como root; o wg-server-manager vai recusar alteracoes.")
    srv, activated = make_server()
    timeout = int(CFG["idle_timeout"])
    if activated and timeout > 0:
        threading.Thread(target=idle_watch, args=(srv, timeout), daemon=True).start()
    log("wgm-panel {} em {}:{} ({})".format(VERSION, *srv.server_address[:2],
                                            "socket do systemd" if activated else "modo direto, sem encerramento por ociosidade"))
    try:
        srv.serve_forever(poll_interval=1)
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
