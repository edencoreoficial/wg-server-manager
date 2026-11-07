#!/usr/bin/env bash
# =============================================================================
#  wg-server-manager.sh
#  Gerador de servidor e peers WireGuard para Debian e demais distros Linux
#  com systemd (Ubuntu, RHEL/Rocky/Alma/Fedora, Arch, openSUSE).
#
#  EdenCore / Sagarys  |  Licenca MIT  |  v1.3.1
#
#  Seguranca por Design
#  - umask 077: chaves, estado e <iface>.conf nascem 600; pastas 700.
#  - Estado lido por parser com lista de chaves permitidas, nunca com 'source'.
#  - <iface>.conf e gerado a partir do estado, validado com 'wg-quick strip' e
#    trocado de forma atomica. A versao anterior vai para backups/ (ultimas 20).
#  - Alteracao de peer entra com 'wg syncconf': quem ja esta conectado nao cai.
#  - PresharedKey por peer: camada simetrica extra (mitigacao pos-quantica).
#  - AllowedIPs sobrepostos sao recusados. No WireGuard o ultimo peer assume a
#    rede em silencio, o que desvia trafego de um cliente para outro.
#  - Isolamento entre peers ligado e NAT de saida desligado por padrao.
#  - '--pubkey': o peer gera a propria chave; a privada nunca passa pelo servidor.
#  - 'peer wipe-key': apaga (shred) a chave privada do peer depois da entrega.
#  - Nao altera o firewall do host (nftables, firewalld, ufw, Docker). Cria so a
#    propria tabela 'inet wgm_<iface>' e nunca usa 'flush ruleset'. Conflito com
#    politica existente e avisado, nunca omitido.
# =============================================================================
set -Eeuo pipefail
umask 077
shopt -s nullglob

readonly VERSION="1.3.1"
readonly PROG=${0##*/}
WG_DIR=${WG_DIR:-/etc/wireguard}
IFACE=${WGM_IFACE:-wg0}
ASSUME_YES=0

S_KEYS=(S_IFACE S_ADDR S_PORT S_ENDPOINT S_DNS S_MTU S_LANS S_NAT_IF S_ISOLATE S_KEEPALIVE S_CREATED)
P_KEYS=(P_NAME P_TYPE P_IP P_LANS P_CLIENT_ALLOWED P_KEEPALIVE P_CREATED)

# ------------------------------------------------------------------ saida ----
if [[ -t 1 ]]; then
  C_R=$'\e[31m' C_G=$'\e[32m' C_Y=$'\e[33m' C_B=$'\e[36m' C_D=$'\e[1m' C_0=$'\e[0m'
else
  C_R='' C_G='' C_Y='' C_B='' C_D='' C_0=''
fi
info() { printf '%s[i]%s %s\n'    "$C_B" "$C_0" "$*"; }
ok()   { printf '%s[ok]%s %s\n'   "$C_G" "$C_0" "$*"; }
warn() { printf '%s[!]%s %s\n'    "$C_Y" "$C_0" "$*" >&2; }
die()  { printf '%s[erro]%s %s\n' "$C_R" "$C_0" "$*" >&2; exit 1; }

# Retorna o valor de uma opcao ou aborta se faltar. Uso: v=$(argv "$@")
argv() { [[ $# -ge 2 ]] || die "Falta valor para $1"; printf '%s' "$2"; }

set_paths() {
  [[ $IFACE =~ ^[a-z][a-z0-9_-]{0,14}$ ]] \
    || die "Interface invalida: '$IFACE' (a-z, 0-9, _ e -, ate 15 caracteres)."
  STATE="$WG_DIR/wgm/$IFACE"
  CONF="$WG_DIR/$IFACE.conf"
  SENV="$STATE/server.env"
  PEERS="$STATE/peers"
  BACKUPS="$STATE/backups"
  FWFILE="$STATE/fw.nft"
  NFT_TABLE="wgm_${IFACE//-/_}"
}

require_root() { [[ $EUID -eq 0 ]] || die "Execute como root (sudo $PROG ...)."; }
require_cmds() {
  local c miss=()
  for c in "$@"; do command -v "$c" >/dev/null 2>&1 || miss+=("$c"); done
  ((${#miss[@]} == 0)) || die "Faltando: ${miss[*]}. Rode: $PROG install"
}
has_systemd() { [[ -d /run/systemd/system ]] && command -v systemctl >/dev/null 2>&1; }
iface_up()    { ip link show dev "$IFACE" >/dev/null 2>&1; }

# --------------------------------------------------------- validacao e IP ----
valid_name() { [[ $1 =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$ ]]; }
valid_key()  { [[ $1 =~ ^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=$ ]]; }
valid_port() { [[ $1 =~ ^[0-9]{1,5}$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 )); }

is_ip() {
  [[ $1 =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  local o
  for o in "${BASH_REMATCH[@]:1}"; do (( 10#$o <= 255 )) || return 1; done
  return 0
}
is_cidr() {
  local ip pfx
  [[ $1 =~ ^([0-9.]+)/([0-9]{1,2})$ ]] || return 1
  ip=${BASH_REMATCH[1]} pfx=${BASH_REMATCH[2]}
  is_ip "$ip" && (( 10#$pfx <= 32 ))
}
ip2int() {
  local a b c d
  IFS=. read -r a b c d <<<"$1"
  echo $(( (10#$a << 24) | (10#$b << 16) | (10#$c << 8) | 10#$d ))
}
int2ip()  { echo "$(( ($1 >> 24) & 255 )).$(( ($1 >> 16) & 255 )).$(( ($1 >> 8) & 255 )).$(( $1 & 255 ))"; }
mask_of() { if (( $1 == 0 )); then echo 0; else echo $(( (0xFFFFFFFF << (32 - $1)) & 0xFFFFFFFF )); fi; }

cidr_range() {  # a.b.c.d/p -> "inicio fim" em inteiros
  local p=$(( 10#${1#*/} )) m n
  m=$(mask_of "$p")
  n=$(( $(ip2int "${1%/*}") & m ))
  echo "$n $(( n | (~m & 0xFFFFFFFF) ))"
}
cidr_norm() { local s e; read -r s e < <(cidr_range "$1"); echo "$(int2ip "$s")/$(( 10#${1#*/} ))"; }
overlaps() {
  local a1 a2 b1 b2
  read -r a1 a2 < <(cidr_range "$1")
  read -r b1 b2 < <(cidr_range "$2")
  (( a1 <= b2 && b1 <= a2 ))
}
in_list() { local x=$1 i; shift; for i in "$@"; do [[ $i == "$x" ]] && return 0; done; return 1; }

# Lista de redes "a b,c" -> "a, b, c". IP sem mascara vira /32. 'none' = vazio.
# Com $2=1 aceita 'full' e 0.0.0.0/0 (so no lado do peer).
norm_list() {
  local raw=$1 allow_default=${2:-0} item n arr=() out=()
  [[ $raw == none ]] && raw=''
  read -ra arr <<<"${raw//,/ }"
  for item in "${arr[@]}"; do
    [[ $item == full ]] && item=0.0.0.0/0
    [[ $item == */* ]] || item="$item/32"
    is_cidr "$item" || die "Rede invalida: '$item'"
    n=$(cidr_norm "$item")
    [[ $n == "$item" ]] || warn "'$item' ajustado para '$n' (bits de host zerados)."
    if [[ $n == 0.0.0.0/0 && $allow_default != 1 ]]; then
      die "0.0.0.0/0 nao e permitido aqui: o servidor mandaria todo o trafego para um peer."
    fi
    in_list "$n" "${out[@]}" || out+=("$n")
  done
  local IFS=,
  local j="${out[*]}"
  echo "${j//,/, }"
}
norm_client_allowed() {
  case $1 in
    ''|auto) echo auto ;;
    full)    echo 0.0.0.0/0 ;;
    *)       norm_list "$1" 1 ;;
  esac
}
norm_dns() {
  local arr=() d out=()
  [[ $1 == none ]] && { echo ''; return 0; }
  read -ra arr <<<"${1//,/ }"
  for d in "${arr[@]}"; do is_ip "$d" || die "DNS invalido: $d"; out+=("$d"); done
  local IFS=,
  local j="${out[*]}"
  echo "${j//,/, }"
}
norm_endpoint() {
  local ep=$1 port=$2 host p
  if [[ $ep == *:* ]]; then host=${ep%:*} p=${ep##*:}; else host=$ep p=$port; fi
  [[ $host =~ ^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$ ]] || die "Endpoint invalido: '$ep' (IPv4 ou nome DNS)."
  valid_port "$p" || die "Porta invalida no endpoint: $p"
  echo "$host:$p"
}
detect_ip() {
  local r; r=$(ip -4 route get 1.1.1.1 2>/dev/null) || true
  if [[ $r =~ src\ ([0-9.]+) ]]; then echo "${BASH_REMATCH[1]}"; fi
  return 0
}
default_if() {
  local r; r=$(ip -4 route show default 2>/dev/null) || true
  if [[ $r =~ dev\ ([^ ]+) ]]; then echo "${BASH_REMATCH[1]}"; fi
  return 0
}

# ----------------------------------------------------------------- estado ----
load_kv() {  # arquivo prefixo; so aceita chaves <prefixo>_MAIUSCULAS
  local f=$1 pfx=$2 k v
  [[ -r $f ]] || die "Estado ausente: $f"
  while IFS='=' read -r k v || [[ -n ${k:-} ]]; do
    [[ $k =~ ^${pfx}_[A-Z0-9_]+$ ]] || continue
    printf -v "$k" '%s' "$v"
  done <"$f"
}
save_kv() {
  local f=$1 tmp k; shift
  tmp=$(mktemp "$f.XXXXXX")
  for k in "$@"; do printf '%s=%s\n' "$k" "${!k-}"; done >"$tmp"
  mv -f "$tmp" "$f"
}
load_server() {
  require_cmds wg wg-quick ip nft
  [[ -f $SENV ]] || die "Servidor '$IFACE' nao existe. Crie com: $PROG -i $IFACE init"
  load_kv "$SENV" S
  S_NET=$(cidr_norm "$S_ADDR")
  S_IP=${S_ADDR%/*}
}
load_peer() {
  valid_name "${1:-}" || die "Nome de peer invalido: '${1:-}'"
  local d="$PEERS/$1"
  [[ -f $d/peer.env ]] || die "Peer '$1' nao existe."
  P_NAME='' P_TYPE='' P_IP='' P_LANS='' P_CLIENT_ALLOWED='' P_KEEPALIVE='' P_CREATED=''
  load_kv "$d/peer.env" P
  P_DIR=$d
}
kv_get() {  # arquivo chave -> valor, sem alterar variaveis globais
  local k v
  [[ -r $1 ]] || return 0
  while IFS='=' read -r k v || [[ -n ${k:-} ]]; do
    if [[ $k == "$2" ]]; then echo "$v"; return 0; fi
  done <"$1"
  return 0
}
peer_get() { kv_get "$PEERS/$1/peer.env" "$2"; }  # nome chave -> valor
peer_names() {
  local d
  for d in "$PEERS"/*/; do
    d=${d%/}
    if [[ -f $d/peer.env ]]; then echo "${d##*/}"; fi
  done
}
secure_rm() {
  local f
  for f in "$@"; do
    [[ -f $f ]] || continue
    if command -v shred >/dev/null 2>&1; then shred -u -- "$f"; else rm -f -- "$f"; fi
  done
}
confirm() {
  ((ASSUME_YES)) && return 0
  local a; read -rp "$1 [s/N]: " a
  [[ $a =~ ^[sSyY]$ ]]
}
with_lock() {
  if [[ ! -d $STATE ]]; then
    [[ $1 == cmd_init || $1 == menu_init ]] || die "Servidor '$IFACE' nao existe. Crie com: $PROG -i $IFACE init"
    mkdir -p "$STATE"
    # init recusado nao deixa pasta de estado vazia para tras
    trap '[[ -f $SENV ]] || rm -rf -- "$STATE"' EXIT
  fi
  if command -v flock >/dev/null 2>&1; then
    exec 9>"$STATE/.lock"
    flock -n 9 || die "Outra execucao esta alterando '$IFACE'. Tente de novo em instantes."
  fi
  "$@"
}

# ------------------------------------------------- AllowedIPs e conflitos ----
client_allowed() {  # lado do peer: o que ele manda pelo tunel
  if [[ -z $P_CLIENT_ALLOWED || $P_CLIENT_ALLOWED == auto ]]; then
    if [[ -n $S_LANS ]]; then echo "$S_NET, $S_LANS"; else echo "$S_NET"; fi
  else
    echo "$P_CLIENT_ALLOWED"
  fi
}
server_allowed() {  # lado do servidor: o que pertence a este peer
  if [[ -n $P_LANS ]]; then echo "$P_IP/32, $P_LANS"; else echo "$P_IP/32"; fi
}

# Redes das OUTRAS interfaces gerenciadas no host: "iface tipo cidr rotulo".
# Tipo T = rede do tunel, S = rede atras do servidor, P = LAN de peer.
other_iface_nets() {
  local d ifn senv addr p pname n arr=()
  for d in "$WG_DIR"/wgm/*/; do
    d=${d%/}; ifn=${d##*/}; senv="$d/server.env"
    if [[ $ifn == "$IFACE" || ! -f $senv ]]; then continue; fi
    addr=$(kv_get "$senv" S_ADDR)
    if [[ -n $addr ]]; then echo "$ifn T $(cidr_norm "$addr") rede do tunel"; fi
    read -ra arr <<<"$(kv_get "$senv" S_LANS | tr ',' ' ')"
    for n in "${arr[@]}"; do echo "$ifn S $n rede atras do servidor"; done
    for p in "$d"/peers/*/peer.env; do
      pname=${p%/peer.env}; pname=${pname##*/}
      read -ra arr <<<"$(kv_get "$p" P_LANS | tr ',' ' ')"
      for n in "${arr[@]}"; do echo "$ifn P $n LAN do peer $pname"; done
    done
  done
  return 0
}

# Recusa sobreposicao com outras interfaces (rotas do host colidiriam em silencio).
# Uso: check_cross_iface <ignorar redes do servidor: 0|1> <cidr>...
# Rede atras do servidor repetida entre tuneis e legitima (e rede local do hub).
check_cross_iface() {
  local skip_s=$1 n ifn t c label
  shift
  [[ $# -gt 0 ]] || return 0
  while read -r ifn t c label; do
    [[ -n $ifn ]] || continue
    if [[ $t == S && $skip_s == 1 ]]; then continue; fi
    for n in "$@"; do
      if overlaps "$n" "$c"; then die "$n conflita com $c ($label, interface $ifn)."; fi
    done
  done < <(other_iface_nets)
  return 0
}

# Recusa sobreposicao. Uso: check_conflicts <peer_a_ignorar> <ip> <lans>
check_conflicts() {
  local self=$1 ip=$2 lans=$3 s e i n x name arr=() mine=() theirs=() srv=() plans=()
  read -r s e < <(cidr_range "$S_NET")
  i=$(ip2int "$ip")
  (( i > s && i < e )) || die "IP $ip fora da faixa util do tunel $S_NET."
  [[ $ip != "$S_IP" ]] || die "IP $ip e o do proprio servidor."
  mine=("$ip/32")
  read -ra arr <<<"${lans//,/ }"
  read -ra srv <<<"${S_LANS//,/ }"
  for n in "${arr[@]}"; do
    if overlaps "$n" "$S_NET"; then die "LAN $n sobrepoe a rede do tunel $S_NET."; fi
    for x in "${srv[@]}"; do
      if overlaps "$n" "$x"; then die "LAN $n conflita com a rede do servidor $x."; fi
    done
    mine+=("$n")
    plans+=("$n")
  done
  if (( ${#plans[@]} )); then check_cross_iface 0 "${plans[@]}"; fi
  while read -r name; do
    [[ -z $name || $name == "$self" ]] && continue
    theirs=("$(peer_get "$name" P_IP)/32")
    read -ra arr <<<"$(peer_get "$name" P_LANS | tr ',' ' ')"
    theirs+=("${arr[@]}")
    for n in "${mine[@]}"; do
      for x in "${theirs[@]}"; do
        if overlaps "$n" "$x"; then die "$n conflita com $x do peer '$name'."; fi
      done
    done
  done < <(peer_names)
  return 0
}
check_server_lans() {
  local arr=() theirs=() n x name
  read -ra arr <<<"${1//,/ }"
  if (( ${#arr[@]} )); then check_cross_iface 1 "${arr[@]}"; fi
  for n in "${arr[@]}"; do
    if overlaps "$n" "$S_NET"; then die "Rede $n sobrepoe a rede do tunel $S_NET."; fi
    while read -r name; do
      read -ra theirs <<<"$(peer_get "$name" P_LANS | tr ',' ' ')"
      for x in "${theirs[@]}"; do
        if overlaps "$n" "$x"; then die "Rede $n conflita com $x do peer '$name'."; fi
      done
    done < <(peer_names)
  done
  return 0
}
next_free_ip() {
  local s e i ip name used=" $S_IP "
  while read -r name; do used+="$(peer_get "$name" P_IP) "; done < <(peer_names)
  read -r s e < <(cidr_range "$S_NET")
  for (( i = s + 1; i < e; i++ )); do
    ip=$(int2ip "$i")
    if [[ $used != *" $ip "* ]]; then echo "$ip"; return 0; fi
  done
  die "Sem IP livre em $S_NET."
}

# ---------------------------------------------------------------- render -----
render_fw() {
  local tmp; tmp=$(mktemp "$FWFILE.XXXXXX")
  {
    printf '# Gerado por %s. Tabela propria: nao altera outras tabelas do host.\n' "$PROG"
    printf 'table inet %s\ndelete table inet %s\n' "$NFT_TABLE" "$NFT_TABLE"
    printf 'table inet %s {\n' "$NFT_TABLE"
    printf '  chain forward {\n    type filter hook forward priority -5; policy accept;\n'
    printf '    iifname "%s" ct state invalid counter drop\n' "$IFACE"
    if [[ $S_ISOLATE == yes ]]; then
      printf '    iifname "%s" oifname "%s" counter drop comment "isolamento entre peers"\n' "$IFACE" "$IFACE"
    fi
    printf '  }\n'
    if [[ $S_NAT_IF != none ]]; then
      printf '  chain postrouting {\n    type nat hook postrouting priority 100; policy accept;\n'
      printf '    iifname "%s" oifname "%s" counter masquerade\n  }\n' "$IFACE" "$S_NAT_IF"
    fi
    printf '}\n'
  } >"$tmp"
  mv -f "$tmp" "$FWFILE"
}

render_conf() {
  local tmpd out name old=()
  tmpd=$(mktemp -d "$STATE/.tmp.XXXXXX")
  out="$tmpd/$IFACE.conf"
  {
    printf '# Gerado por %s v%s em %s.\n' "$PROG" "$VERSION" "$(date '+%F %T')"
    printf '# NAO edite a mao: altere com o script (estado em %s).\n\n' "$STATE"
    printf '[Interface]\nAddress = %s\nListenPort = %s\nMTU = %s\n' "$S_ADDR" "$S_PORT" "$S_MTU"
    printf 'PrivateKey = %s\n' "$(<"$STATE/server.key")"
    printf 'PostUp = nft -f %s\n' "$FWFILE"
    printf 'PostDown = nft delete table inet %s || true\n' "$NFT_TABLE"
    while read -r name; do
      load_peer "$name"
      printf '\n# peer: %s | tipo: %s | criado: %s\n[Peer]\n' "$P_NAME" "$P_TYPE" "$P_CREATED"
      printf 'PublicKey = %s\n' "$(<"$P_DIR/public.key")"
      if [[ -s $P_DIR/psk ]]; then printf 'PresharedKey = %s\n' "$(<"$P_DIR/psk")"; fi
      printf 'AllowedIPs = %s\n' "$(server_allowed)"
    done < <(peer_names)
  } >"$out"
  if ! wg-quick strip "$out" >/dev/null 2>"$tmpd/err"; then
    cat "$tmpd/err" >&2
    rm -rf "$tmpd"
    die "Configuracao gerada nao passou na validacao; $CONF nao foi alterado."
  fi
  if [[ -f $CONF ]]; then
    mkdir -p "$BACKUPS"
    cp -p "$CONF" "$(mktemp "$BACKUPS/$IFACE.conf.$(date +%Y%m%d-%H%M%S).XXXX")"
    old=("$BACKUPS/$IFACE.conf."*)
    if (( ${#old[@]} > 20 )); then rm -f -- "${old[@]:0:${#old[@]}-20}"; fi
  fi
  chmod 600 "$out"
  mv -f "$out" "$CONF"
  rm -rf "$tmpd"
}

render_client() {
  local priv
  if [[ -s $P_DIR/private.key ]]; then priv=$(<"$P_DIR/private.key"); else priv='<CHAVE_PRIVADA_DO_PEER>'; fi
  printf '# Peer %s (%s) | hub %s em %s | gerado por %s\n' "$P_NAME" "$P_TYPE" "$IFACE" "$S_ENDPOINT" "$PROG"
  if [[ $P_TYPE == site ]]; then
    printf '# Site: habilite net.ipv4.ip_forward=1 neste lado. LANs anunciadas ao hub: %s\n' "${P_LANS:-nenhuma}"
  fi
  printf '[Interface]\nPrivateKey = %s\nAddress = %s/32\nMTU = %s\n' "$priv" "$P_IP" "$S_MTU"
  if [[ $P_TYPE == client && -n $S_DNS ]]; then printf 'DNS = %s\n' "$S_DNS"; fi
  printf '\n[Peer]\nPublicKey = %s\n' "$(<"$STATE/server.pub")"
  if [[ -s $P_DIR/psk ]]; then printf 'PresharedKey = %s\n' "$(<"$P_DIR/psk")"; fi
  printf 'Endpoint = %s\nAllowedIPs = %s\n' "$S_ENDPOINT" "$(client_allowed)"
  if (( 10#$P_KEEPALIVE > 0 )); then printf 'PersistentKeepalive = %s\n' "$P_KEEPALIVE"; fi
}

render_rsc() {  # RouterOS v7, lado do peer
  local ifn=wg-hub host=${S_ENDPOINT%:*} port=${S_ENDPOINT##*:} pfx=${S_NET#*/}
  local allowed n arr=()
  allowed=$(client_allowed); allowed=${allowed//, /,}
  printf '# RouterOS v7 | peer %s do hub %s (%s) | gerado por %s\n' "$P_NAME" "$IFACE" "$S_ENDPOINT" "$PROG"
  if [[ -s $P_DIR/private.key ]]; then
    printf '/interface wireguard add name=%s mtu=%s private-key="%s" comment="hub %s"\n' \
      "$ifn" "$S_MTU" "$(<"$P_DIR/private.key")" "$IFACE"
  else
    printf '# Chave privada nao esta no servidor: use a interface cuja public-key foi cadastrada no hub.\n'
  fi
  printf '/interface wireguard peers add interface=%s public-key="%s"' "$ifn" "$(<"$STATE/server.pub")"
  if [[ -s $P_DIR/psk ]]; then printf ' preshared-key="%s"' "$(<"$P_DIR/psk")"; fi
  printf ' endpoint-address=%s endpoint-port=%s allowed-address=%s persistent-keepalive=%ss comment="hub %s"\n' \
    "$host" "$port" "$allowed" "$P_KEEPALIVE" "$IFACE"
  printf '/ip address add address=%s/%s interface=%s comment="tunel hub %s"\n' "$P_IP" "$pfx" "$ifn" "$IFACE"
  read -ra arr <<<"${allowed//,/ }"
  for n in "${arr[@]}"; do
    [[ $n == "$S_NET" ]] && continue
    if [[ $n == 0.0.0.0/0 ]]; then
      printf '# 0.0.0.0/0 nao vira rota: derrubaria o acesso do roteador. Para tunel total use tabela/routing-mark.\n'
      continue
    fi
    printf '/ip route add dst-address=%s gateway=%s comment="hub %s"\n' "$n" "$ifn" "$IFACE"
  done
  if [[ $P_TYPE == site && -n $P_LANS ]]; then
    printf '# LANs deste site anunciadas ao hub: %s. Libere o forward entre %s e a LAN no firewall.\n' "$P_LANS" "$ifn"
  fi
}

# ---------------------------------------------------------- aplicacao live ----
sync_routes() {  # rotas das LANs dos peers (wg syncconf nao mexe em rotas)
  local want=() arr=() name n dst rest
  while read -r name; do
    read -ra arr <<<"$(peer_get "$name" P_LANS | tr ',' ' ')"
    want+=("${arr[@]}")
  done < <(peer_names)
  for n in "${want[@]}"; do ip -4 route replace "$n" dev "$IFACE"; done
  while read -r dst rest; do
    [[ -z $dst || $dst == default || $rest == *"proto kernel"* ]] && continue
    [[ $dst == */* ]] || dst="$dst/32"
    in_list "$dst" "${want[@]}" || ip -4 route del "$dst" dev "$IFACE" || true
  done < <(ip -4 route show dev "$IFACE")
  return 0
}
apply_live() {
  if ! iface_up; then
    info "$IFACE nao esta ativa: a configuracao vale no proximo start (systemctl start wg-quick@$IFACE)."
    return 0
  fi
  wg syncconf "$IFACE" <(wg-quick strip "$CONF")
  nft -f "$FWFILE"
  sync_routes
  ok "Aplicado em $IFACE sem derrubar o tunel."
}
enable_forward() {
  mkdir -p /etc/sysctl.d
  printf '# %s: roteamento do tunel WireGuard\nnet.ipv4.ip_forward = 1\n' "$PROG" >/etc/sysctl.d/99-wgm.conf
  chmod 644 /etc/sysctl.d/99-wgm.conf
  sysctl -q -p /etc/sysctl.d/99-wgm.conf 2>/dev/null \
    || warn "ip_forward nao aplicado agora (container?). Confira: sysctl net.ipv4.ip_forward"
}
# O forward so importa se ha rede atras do servidor, LAN de peer, NAT ou peers conversando entre si.
needs_forward() {
  local name
  if [[ -n $S_LANS || $S_NAT_IF != none || $S_ISOLATE == no ]]; then return 0; fi
  while read -r name; do
    if [[ -n $(peer_get "$name" P_LANS) ]]; then return 0; fi
  done < <(peer_names)
  return 1
}

# Imprime "familia tabela chain" das chains base com policy drop no hook pedido, so em
# tabelas nftables nativas. As do iptables-nft (ufw, Docker) sao tratadas pelo iptables.
# $3 = lista "familia tabela" gerenciadas pelo iptables-nft. O nft avisa isso no stderr,
# separado do ruleset, por isso a lista vem a parte.
nft_native_drop_chains() {
  local hook=$1 rs=$2 managed=" ${3:-} " line fam='' tbl='' ch='' skip=0
  while IFS= read -r line; do
    if [[ $line =~ ^table\ ([a-z0-9]+)\ ([^ ]+)\ \{ ]]; then
      fam=${BASH_REMATCH[1]} tbl=${BASH_REMATCH[2]} ch='' skip=0
      if [[ $managed == *" $fam:$tbl "* ]]; then skip=1; fi
    elif [[ $line =~ ^[[:space:]]+chain\ ([^ ]+)\ \{ ]]; then
      ch=${BASH_REMATCH[1]}
    elif (( skip == 0 )) && [[ $line == *"hook $hook "* && $line == *"policy drop"* ]]; then
      # Assinatura do iptables-nft mesmo sem o aviso (o nft so avisa quando ha extensoes xt):
      # familia ip/ip6, tabela classica e chain nativa em maiusculas.
      if [[ $fam =~ ^ip6?$ && $tbl =~ ^(filter|nat|mangle|raw|security)$ \
            && $ch =~ ^(INPUT|FORWARD|OUTPUT|PREROUTING|POSTROUTING)$ ]]; then
        continue
      fi
      echo "$fam $tbl $ch"
    fi
  done <<<"$rs"
  return 0
}

# Avisa so o que falta: confere se a porta e o forward do tunel ja estao liberados
# no ufw, firewalld, iptables (inclusive Docker) ou nftables nativo antes de alertar.
check_host_fw() {
  local rs ipt ufwst fwd fam tbl ch du managed='' w du_managed=0 port_ok=0 fwd_ok=0 need_fwd=0 ufw_on=0 alerts=0 nft_hint=0
  rs=$(nft list ruleset 2>/dev/null) || true
  while IFS= read -r w; do
    if [[ $w =~ table\ ([a-z0-9]+)\ ([^ ]+)\ is\ managed\ by\ iptables-nft ]]; then
      managed+=" ${BASH_REMATCH[1]}:${BASH_REMATCH[2]}"
    fi
  done < <(nft list ruleset 2>&1 >/dev/null || true)
  ipt=$(iptables -S 2>/dev/null) || true
  if grep -Eq "udp dport ($S_PORT|\{[^}]*\<$S_PORT\>[^}]*\})[^#]* accept" <<<"$rs" \
     || grep -Eq -- "--dport $S_PORT( .*)? -j ACCEPT" <<<"$ipt"; then
    port_ok=1
  fi
  if grep -Eq "iifname \"$IFACE\"[^#]* accept" <<<"$rs" \
     || grep -Eq -- "-i $IFACE( .*)? -j ACCEPT" <<<"$ipt"; then
    fwd_ok=1
  fi
  if needs_forward; then need_fwd=1; fi

  if has_systemd && systemctl is-active --quiet firewalld && { (( ! port_ok )) || (( need_fwd && ! fwd_ok )); }; then
    warn "firewalld ativo sem liberacao para o tunel. Ajuste:"
    printf '    firewall-cmd --permanent --add-port=%s/udp\n' "$S_PORT"
    printf '    firewall-cmd --permanent --zone=trusted --add-interface=%s\n    firewall-cmd --reload\n' "$IFACE"
    alerts=1
  fi

  if command -v ufw >/dev/null 2>&1; then
    ufwst=$(ufw status 2>/dev/null) || true
    if [[ $ufwst == *"Status: active"* ]]; then
      ufw_on=1
      if (( ! port_ok )); then
        warn "ufw ativo sem a porta do tunel. Ajuste:"
        printf '    ufw allow %s/udp\n' "$S_PORT"
        alerts=1
      fi
      if (( need_fwd && ! fwd_ok )); then
        warn "ufw ativo sem forward para o tunel. Ajuste:"
        printf '    ufw route allow in on %s\n' "$IFACE"
        alerts=1
      fi
    fi
  fi

  fwd=$(iptables -S FORWARD 2>/dev/null) || true
  # DOCKER-USER com regras (alem de um RETURN) e politica de forward de quem administra o
  # host. Nao sugere ACCEPT geral, que passaria por cima dela.
  du=$(iptables -S DOCKER-USER 2>/dev/null | grep -Ev '^-N DOCKER-USER$|^-A DOCKER-USER -j RETURN$') || true
  if (( ! ufw_on && need_fwd && ! fwd_ok )) && [[ $fwd == *"-P FORWARD DROP"* && -n $du ]]; then
    du_managed=1
    info "Forward do $IFACE controlado pela chain DOCKER-USER existente (regras proprias do host); nada sugerido."
    info "Garanta nela o que deve passar entre o tunel e os containers (ex.: allowlist por grupo)."
  elif (( ! ufw_on && need_fwd && ! fwd_ok )) && [[ $fwd == *"-P FORWARD DROP"* ]]; then
    ch=FORWARD
    if iptables -S DOCKER-USER >/dev/null 2>&1; then ch=DOCKER-USER; fi
    warn "Politica FORWARD DROP no iptables (tipico com Docker). O trafego roteado pelo tunel sera descartado ate liberar:"
    printf '    iptables -I %s -i %s -j ACCEPT\n' "$ch" "$IFACE"
    printf '    iptables -I %s -o %s -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n' "$ch" "$IFACE"
    printf '    Se um script ou timer gerencia essa chain, inclua as regras nele para sobreviverem ao restart do Docker.\n'
    alerts=1
  fi

  while read -r fam tbl ch; do
    [[ -n $fam ]] || continue
    nft_hint=1
    if (( ! port_ok )); then
      warn "nftables: a chain '$ch' da tabela '$fam $tbl' descarta por padrao e nao libera $S_PORT/udp:"
      printf '    nft add rule %s %s %s udp dport %s accept\n' "$fam" "$tbl" "$ch" "$S_PORT"
      alerts=1
    fi
  done < <(nft_native_drop_chains input "$rs" "$managed")
  if (( need_fwd && ! fwd_ok )); then
    while read -r fam tbl ch; do
      [[ -n $fam ]] || continue
      nft_hint=1
      warn "nftables: a chain '$ch' da tabela '$fam $tbl' descarta o forward do tunel:"
      printf '    nft add rule %s %s %s iifname "%s" accept\n' "$fam" "$tbl" "$ch" "$IFACE"
      printf '    nft add rule %s %s %s oifname "%s" ct state established,related accept\n' "$fam" "$tbl" "$ch" "$IFACE"
      alerts=1
    done < <(nft_native_drop_chains forward "$rs" "$managed")
  fi
  if (( alerts && nft_hint )); then
    printf '    Grave as mesmas regras no arquivo que carrega essa tabela (ex.: /etc/nftables.conf) para valerem apos reboot.\n'
    printf '    Se a chain termina com uma regra drop/reject explicita, inclua as novas regras antes dela.\n'
  fi
  if (( nft_hint )) || [[ $ipt == *"-P INPUT DROP"* ]]; then
    info "Input com drop: peers acessando servicos do proprio servidor pelo tunel (ping em ${S_IP}, SSH, agentes) precisam de regra de entrada no $IFACE, por porta."
  fi

  if (( ! alerts )); then
    if (( du_managed )); then
      ok "Firewall do host: $S_PORT/udp liberada; forward a cargo da DOCKER-USER."
    elif (( need_fwd )); then
      ok "Firewall do host: $S_PORT/udp e forward do $IFACE liberados."
    else
      ok "Firewall do host: $S_PORT/udp liberada (sem forward necessario: nenhuma rede atras do servidor ou dos peers)."
    fi
  fi
  return 0
}

# ------------------------------------------------------------- comandos ------
# Le ID e ID_LIKE sem executar o arquivo: o os-release define VERSION, que aqui e readonly,
# e um arquivo de sistema nunca deve rodar dentro do contexto do script.
os_ids() {
  local f=${1:-/etc/os-release} k v out=''
  [[ -r $f ]] || { echo ''; return 0; }
  while IFS='=' read -r k v || [[ -n ${k:-} ]]; do
    case $k in
      ID|ID_LIKE) v=${v#[\"\']}; v=${v%[\"\']}; out+=" $v" ;;
    esac
  done <"$f"
  echo "$out"
}

cmd_install() {
  require_root
  local ids
  ids=" $(os_ids /etc/os-release) "
  info "Distro detectada:$ids"
  case $ids in
    *" debian "*|*" ubuntu "*)
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -qq
      apt-get install -y -qq wireguard-tools nftables iproute2 util-linux
      apt-get install -y -qq qrencode || warn "qrencode indisponivel: sem QR code." ;;
    *" fedora "*|*" rhel "*|*" centos "*|*" rocky "*|*" almalinux "*|*" ol "*)
      dnf install -y wireguard-tools nftables iproute util-linux
      dnf install -y qrencode || warn "qrencode indisponivel (no RHEL e clones vem do EPEL)." ;;
    *" arch "*)
      pacman -Sy --noconfirm --needed wireguard-tools nftables iproute2 util-linux qrencode ;;
    *" suse "*|*" opensuse "*)
      zypper -n in wireguard-tools nftables iproute2 util-linux qrencode ;;
    *) die "Distro nao reconhecida. Instale: wireguard-tools nftables iproute2 util-linux (qrencode opcional)." ;;
  esac
  if ! modprobe wireguard 2>/dev/null && [[ ! -d /sys/module/wireguard ]]; then
    warn "Modulo wireguard nao carregou. Kernel 5.6+ ja traz; em kernel antigo instale o modulo da distro."
  fi
  ok "Dependencias instaladas."
}

cmd_init() {
  require_cmds wg wg-quick ip nft
  local addr=10.99.0.1/24 port=51820 endpoint='' dns='' lans='' natif=none isolate=yes mtu=1420 ka=25 pfx
  while (($#)); do
    case $1 in
      -a|--address)   addr=$(argv "$@"); shift 2 ;;
      -p|--port)      port=$(argv "$@"); shift 2 ;;
      -e|--endpoint)  endpoint=$(argv "$@"); shift 2 ;;
      -d|--dns)       dns=$(argv "$@"); shift 2 ;;
      -l|--lans)      lans=$(argv "$@"); shift 2 ;;
      -n|--nat-if)    natif=$(argv "$@"); shift 2 ;;
      --no-isolate)   isolate=no; shift ;;
      -m|--mtu)       mtu=$(argv "$@"); shift 2 ;;
      -k|--keepalive) ka=$(argv "$@"); shift 2 ;;
      *) die "Opcao desconhecida para init: $1" ;;
    esac
  done
  if [[ -f $SENV ]]; then die "Servidor '$IFACE' ja existe. Use '$PROG -i $IFACE server set' para alterar."; fi
  if [[ -f $CONF ]]; then die "$CONF ja existe e nao foi criado por este script. Faca backup e mova antes."; fi
  is_cidr "$addr" || die "Endereco invalido: $addr (ex.: 10.99.0.1/24)."
  pfx=$(( 10#${addr#*/} ))
  (( pfx >= 8 && pfx <= 30 )) || die "Use mascara entre /8 e /30 para a rede do tunel."
  S_NET=$(cidr_norm "$addr"); S_IP=${addr%/*}
  local s e i; read -r s e < <(cidr_range "$S_NET"); i=$(ip2int "$S_IP")
  (( i > s && i < e )) || die "Use um IP de host em $S_NET, nao o endereco de rede ou broadcast."
  valid_port "$port" || die "Porta invalida: $port"
  check_cross_iface 0 "$S_NET"
  local senv_other
  for senv_other in "$WG_DIR"/wgm/*/server.env; do
    [[ $senv_other == "$SENV" ]] && continue
    if [[ $(kv_get "$senv_other" S_PORT) == "$port" ]]; then
      senv_other=${senv_other%/server.env}
      die "Porta $port/udp ja usada pela interface ${senv_other##*/}. Use -p com outra porta."
    fi
  done
  [[ $mtu =~ ^[0-9]+$ ]] && (( mtu >= 1280 && mtu <= 1500 )) || die "MTU deve ficar entre 1280 e 1500."
  [[ $ka =~ ^[0-9]{1,5}$ ]] || die "Keepalive invalido: $ka"
  if [[ -z $endpoint ]]; then
    endpoint=$(detect_ip)
    [[ -n $endpoint ]] || die "Informe o endpoint publico com -e (IP ou DDNS)."
    warn "Endpoint nao informado; usando $endpoint. Atras de NAT, troque pelo IP publico/DDNS: server set -e"
  fi
  endpoint=$(norm_endpoint "$endpoint" "$port")
  dns=$(norm_dns "$dns")
  lans=$(norm_list "$lans")
  S_LANS=''
  check_server_lans "$lans"
  if [[ $natif != none ]] && ! ip link show dev "$natif" >/dev/null 2>&1; then
    die "Interface de NAT '$natif' nao existe."
  fi

  mkdir -p "$PEERS" "$BACKUPS"
  chmod 700 "$WG_DIR/wgm" "$STATE" "$PEERS" "$BACKUPS"
  wg genkey >"$STATE/server.key"
  wg pubkey <"$STATE/server.key" >"$STATE/server.pub"

  # shellcheck disable=SC2034  # gravadas por referencia indireta em save_kv
  S_IFACE=$IFACE S_ADDR=$addr S_PORT=$port S_ENDPOINT=$endpoint S_DNS=$dns S_MTU=$mtu
  # shellcheck disable=SC2034
  S_LANS=$lans S_NAT_IF=$natif S_ISOLATE=$isolate S_KEEPALIVE=$ka S_CREATED=$(date '+%F %T')
  save_kv "$SENV" "${S_KEYS[@]}"
  render_fw
  render_conf
  enable_forward
  if has_systemd; then
    systemctl enable --now "wg-quick@$IFACE" \
      || warn "Falha ao subir wg-quick@$IFACE. Veja: journalctl -u wg-quick@$IFACE"
  else
    warn "Sem systemd: suba com 'wg-quick up $CONF' e configure o boot na sua init."
  fi
  check_host_fw
  ok "Servidor $IFACE criado."
  printf '    Tunel: %s | Porta: %s/udp | Endpoint: %s\n' "$S_ADDR" "$S_PORT" "$S_ENDPOINT"
  printf '    NAT: %s | Isolamento: %s | Chave publica: %s\n' "$S_NAT_IF" "$S_ISOLATE" "$(<"$STATE/server.pub")"
  printf '    Proximo passo: %s -i %s peer add NOME\n' "$PROG" "$IFACE"
}

cmd_peer_add() {
  load_server
  local name=${1:-}
  (($#)) && shift
  valid_name "$name" || die "Nome invalido: '$name' (letras, numeros, . _ -; ate 32; comeca com letra ou numero)."
  [[ ! -e $PEERS/$name ]] || die "Peer '$name' ja existe."
  local type=client ip='' lans='' callowed=auto ka=$S_KEEPALIVE pub='' psk=1 d other
  while (($#)); do
    case $1 in
      -t|--type)           type=$(argv "$@"); shift 2 ;;
      -I|--ip)             ip=$(argv "$@"); shift 2 ;;
      -L|--lans)           lans=$(argv "$@"); shift 2 ;;
      -A|--client-allowed) callowed=$(argv "$@"); shift 2 ;;
      -k|--keepalive)      ka=$(argv "$@"); shift 2 ;;
      --pubkey)            pub=$(argv "$@"); shift 2 ;;
      --no-psk)            psk=0; shift ;;
      *) die "Opcao desconhecida para peer add: $1" ;;
    esac
  done
  [[ $type == client || $type == site ]] || die "Tipo deve ser 'client' ou 'site'."
  [[ $ka =~ ^[0-9]{1,5}$ ]] || die "Keepalive invalido: $ka"
  if [[ -z $ip ]]; then ip=$(next_free_ip); else is_ip "$ip" || die "IP invalido: $ip"; fi
  lans=$(norm_list "$lans")
  callowed=$(norm_client_allowed "$callowed")
  if [[ $type == site && -z $lans ]]; then warn "Peer 'site' sem LANs: so o IP do tunel sera roteado. Informe com -L."; fi
  if [[ $type == client && -n $lans ]]; then warn "Peer 'client' com LANs: o servidor vai rotear $lans para ele."; fi
  if [[ -n $pub ]]; then
    valid_key "$pub" || die "Chave publica invalida."
    [[ $pub != "$(<"$STATE/server.pub")" ]] || die "Essa e a chave publica do proprio servidor."
    while read -r other; do
      [[ $pub != "$(<"$PEERS/$other/public.key")" ]] || die "Chave publica ja usada pelo peer '$other'."
    done < <(peer_names)
  fi
  check_conflicts "" "$ip" "$lans"

  d="$PEERS/$name"
  mkdir -m 700 "$d"
  if [[ -n $pub ]]; then
    printf '%s\n' "$pub" >"$d/public.key"
  else
    wg genkey >"$d/private.key"
    wg pubkey <"$d/private.key" >"$d/public.key"
  fi
  if ((psk)); then wg genpsk >"$d/psk"; fi
  P_NAME=$name P_TYPE=$type P_IP=$ip P_LANS=$lans P_CLIENT_ALLOWED=$callowed P_KEEPALIVE=$ka
  P_CREATED=$(date '+%F %T')
  save_kv "$d/peer.env" "${P_KEYS[@]}"
  if ! ( render_conf ); then
    secure_rm "$d"/*; rm -rf "$d"
    die "Peer '$name' revertido."
  fi
  apply_live
  ok "Peer '$name' criado: $ip ($type)."
  echo
  cmd_peer_show "$name"
}

cmd_peer_del() {
  load_server
  local name=${1:-}
  (($#)) && shift
  [[ ${1:-} == -y ]] && ASSUME_YES=1
  load_peer "$name"
  confirm "Remover o peer '$name' ($P_IP)?" || { info "Cancelado."; return 0; }
  secure_rm "$P_DIR"/*
  rm -rf "$P_DIR"
  render_conf
  apply_live
  ok "Peer '$name' removido; chaves apagadas."
}

ago() {
  local t=$1 n=$2 d
  if (( t == 0 )); then echo nunca; return 0; fi
  d=$(( n - t ))
  if   (( d < 60 ));    then echo "${d}s"
  elif (( d < 3600 ));  then echo "$((d / 60))min"
  elif (( d < 86400 )); then echo "$((d / 3600))h"
  else echo "$((d / 86400))d"; fi
}
hbytes() {
  local b=$1
  if   (( b < 1024 ));       then echo "${b}B"
  elif (( b < 1048576 ));    then echo "$((b / 1024))KiB"
  elif (( b < 1073741824 )); then echo "$((b / 1048576))MiB"
  else echo "$((b / 1073741824))GiB"; fi
}
cmd_peer_list() {
  load_server
  declare -A HS=() RX=() TX=()
  local k a b now name pub
  now=$(date +%s)
  if iface_up; then
    while read -r k a; do HS[$k]=$a; done < <(wg show "$IFACE" latest-handshakes)
    while read -r k a b; do RX[$k]=$a; TX[$k]=$b; done < <(wg show "$IFACE" transfer)
  fi
  printf '%s%-22s %-6s %-15s %-32s %-9s %9s %9s%s\n' "$C_D" NOME TIPO IP "LANS (rota no servidor)" HANDSHAKE RX TX "$C_0"
  while read -r name; do
    load_peer "$name"
    pub=$(<"$P_DIR/public.key")
    printf '%-22s %-6s %-15s %-32s %-9s %9s %9s\n' "$P_NAME" "$P_TYPE" "$P_IP" "${P_LANS:--}" \
      "$(ago "${HS[$pub]:-0}" "$now")" "$(hbytes "${RX[$pub]:-0}")" "$(hbytes "${TX[$pub]:-0}")"
  done < <(peer_names)
}

cmd_peer_show() {
  load_server
  local name=${1:-} fmt=conf out='' has_priv=0
  (($#)) && shift
  load_peer "$name"
  while (($#)); do
    case $1 in
      --qr)             fmt=qr; shift ;;
      --mikrotik|--rsc) fmt=rsc; shift ;;
      -o|--out)         out=$(argv "$@"); shift 2 ;;
      *) die "Opcao desconhecida para peer show: $1" ;;
    esac
  done
  [[ -s $P_DIR/private.key ]] && has_priv=1
  case $fmt in
    conf)
      if [[ -n $out ]]; then
        ( umask 077; render_client >"$out" ); ok "Salvo em $out (600)."
      else
        render_client
      fi ;;
    qr)
      ((has_priv)) || die "Chave privada nao esta no servidor (--pubkey ou wipe-key): QR indisponivel."
      require_cmds qrencode
      render_client | qrencode -t ansiutf8 ;;
    rsc) render_rsc ;;
  esac
  if ((has_priv)); then
    warn "Contem a chave privada do peer. Entregue por canal seguro e depois rode: $PROG -i $IFACE peer wipe-key $name"
  fi
}

cmd_peer_allowed() {
  load_server
  local name=${1:-}
  (($#)) && shift
  load_peer "$name"
  local ip=$P_IP lans=$P_LANS callowed=$P_CLIENT_ALLOWED changed=0 old_env v
  while (($#)); do
    case $1 in
      -I|--ip)             ip=$(argv "$@"); is_ip "$ip" || die "IP invalido: $ip"; changed=1; shift 2 ;;
      -L|--lans)           v=$(argv "$@"); lans=$(norm_list "$v"); changed=1; shift 2 ;;
      -A|--client-allowed) v=$(argv "$@"); callowed=$(norm_client_allowed "$v"); changed=1; shift 2 ;;
      *) die "Opcao desconhecida para peer allowed: $1" ;;
    esac
  done
  ((changed)) || die "Nada a alterar. Use -L (rede atras do peer), -A (o que o peer roteia) ou -I (IP no tunel)."
  if [[ $P_TYPE == site && -z $lans ]]; then warn "Peer 'site' ficara sem LANs."; fi
  check_conflicts "$name" "$ip" "$lans"
  old_env=$(<"$P_DIR/peer.env")
  P_IP=$ip P_LANS=$lans P_CLIENT_ALLOWED=$callowed
  local srv_side cli_side
  srv_side=$(server_allowed); cli_side=$(client_allowed)
  save_kv "$P_DIR/peer.env" "${P_KEYS[@]}"
  if ! ( render_conf ); then
    printf '%s\n' "$old_env" >"$P_DIR/peer.env"
    die "Alteracao revertida."
  fi
  apply_live
  ok "Peer '$name' atualizado."
  printf '    No servidor (AllowedIPs): %s\n    No peer (AllowedIPs):     %s\n' "$srv_side" "$cli_side"
  info "Se mudou -A ou -I, reexporte a config do peer: $PROG -i $IFACE peer show $name"
}

cmd_peer_wipe() {
  load_server
  load_peer "${1:-}"
  if [[ ! -f $P_DIR/private.key ]]; then info "Peer '$P_NAME' ja nao tem chave privada no servidor."; return 0; fi
  secure_rm "$P_DIR/private.key"
  ok "Chave privada de '$P_NAME' apagada do servidor. O peer continua funcionando com a config entregue."
}

cmd_server_set() {
  load_server
  local changed=0 reexport=0 v
  while (($#)); do
    case $1 in
      -e|--endpoint)  v=$(argv "$@"); S_ENDPOINT=$(norm_endpoint "$v" "$S_PORT"); reexport=1 ;;
      -d|--dns)       v=$(argv "$@"); S_DNS=$(norm_dns "$v"); reexport=1 ;;
      -l|--lans)      v=$(argv "$@"); v=$(norm_list "$v"); check_server_lans "$v"; S_LANS=$v; reexport=1 ;;
      -n|--nat-if)    v=$(argv "$@")
                      if [[ $v != none ]] && ! ip link show dev "$v" >/dev/null 2>&1; then die "Interface '$v' nao existe."; fi
                      S_NAT_IF=$v ;;
      --isolate)      v=$(argv "$@"); [[ $v == yes || $v == no ]] || die "--isolate aceita yes ou no."; S_ISOLATE=$v ;;
      -k|--keepalive) v=$(argv "$@"); [[ $v =~ ^[0-9]{1,5}$ ]] || die "Keepalive invalido."; S_KEEPALIVE=$v ;;
      *) die "Opcao desconhecida para server set: $1" ;;
    esac
    changed=1; shift 2
  done
  ((changed)) || die "Nada a alterar. Opcoes: -e -d -l -n --isolate -k"
  save_kv "$SENV" "${S_KEYS[@]}"
  render_fw
  render_conf
  apply_live
  ok "Servidor $IFACE atualizado."
  if ((reexport)); then
    warn "Endpoint, DNS ou redes do servidor mudaram: reexporte a config dos peers (peer show NOME)."
  fi
}

cmd_status() {
  load_server
  printf '%sInterface %s%s | rede %s | endpoint %s | NAT %s | isolamento %s\n' \
    "$C_D" "$IFACE" "$C_0" "$S_NET" "$S_ENDPOINT" "$S_NAT_IF" "$S_ISOLATE"
  printf 'Redes do servidor: %s\n' "${S_LANS:-nenhuma}"
  printf 'Chave publica: %s\n' "$(<"$STATE/server.pub")"
  if has_systemd; then printf 'Servico wg-quick@%s: %s\n' "$IFACE" "$(systemctl is-active "wg-quick@$IFACE" 2>/dev/null || true)"; fi
  if iface_up; then echo; wg show "$IFACE"; else warn "$IFACE parada."; fi
  check_host_fw
}

cmd_apply() {
  load_server
  render_fw
  render_conf
  apply_live
}

# Estado em JSON para o painel web. Nunca inclui chave privada nem PSK.
json_str() { local s=${1//\\/\\\\}; s=${s//\"/\\\"}; printf '"%s"' "$s"; }
cmd_json() {
  if [[ ! -f $SENV ]]; then
    printf '{"iface":%s,"exists":false}\n' "$(json_str "$IFACE")"
    return 0
  fi
  load_server
  declare -A HS=() RX=() TX=() EP=()
  local up=false svc=unknown k a b first=1 name pub haspriv haspsk
  if iface_up; then
    up=true
    while read -r k a; do HS[$k]=$a; done < <(wg show "$IFACE" latest-handshakes)
    while read -r k a b; do RX[$k]=$a; TX[$k]=$b; done < <(wg show "$IFACE" transfer)
    while read -r k a; do EP[$k]=$a; done < <(wg show "$IFACE" endpoints)
  fi
  if has_systemd; then svc=$(systemctl is-active "wg-quick@$IFACE" 2>/dev/null || true); fi
  printf '{"iface":%s,"exists":true,"now":%s,"server":{' "$(json_str "$IFACE")" "$(date +%s)"
  printf '"address":%s,"network":%s,"port":%s,"endpoint":%s,"dns":%s,"lans":%s,' \
    "$(json_str "$S_ADDR")" "$(json_str "$S_NET")" "$S_PORT" "$(json_str "$S_ENDPOINT")" \
    "$(json_str "$S_DNS")" "$(json_str "$S_LANS")"
  printf '"nat_if":%s,"isolate":%s,"keepalive":%s,"mtu":%s,"created":%s,"public_key":%s,"up":%s,"service":%s},"peers":[' \
    "$(json_str "$S_NAT_IF")" "$(json_str "$S_ISOLATE")" "$S_KEEPALIVE" "$S_MTU" \
    "$(json_str "$S_CREATED")" "$(json_str "$(<"$STATE/server.pub")")" "$up" "$(json_str "$svc")"
  while read -r name; do
    load_peer "$name"
    pub=$(<"$P_DIR/public.key")
    haspriv=false; [[ -s $P_DIR/private.key ]] && haspriv=true
    haspsk=false;  [[ -s $P_DIR/psk ]] && haspsk=true
    ((first)) || printf ','
    first=0
    printf '{"name":%s,"type":%s,"ip":%s,"lans":%s,"server_allowed":%s,"client_allowed":%s,"client_allowed_mode":%s,' \
      "$(json_str "$P_NAME")" "$(json_str "$P_TYPE")" "$(json_str "$P_IP")" "$(json_str "$P_LANS")" \
      "$(json_str "$(server_allowed)")" "$(json_str "$(client_allowed)")" "$(json_str "${P_CLIENT_ALLOWED:-auto}")"
    printf '"keepalive":%s,"created":%s,"public_key":%s,"has_private_key":%s,"has_psk":%s,"handshake":%s,"rx":%s,"tx":%s,"endpoint":%s}' \
      "$(( 10#${P_KEEPALIVE:-0} ))" "$(json_str "$P_CREATED")" "$(json_str "$pub")" "$haspriv" "$haspsk" \
      "${HS[$pub]:-0}" "${RX[$pub]:-0}" "${TX[$pub]:-0}" "$(json_str "${EP[$pub]:-(none)}")"
  done < <(peer_names)
  printf ']}\n'
}

# ------------------------------------------------------------------ menu -----
ask() {  # variavel pergunta [padrao]
  local __v
  read -rp "$2${3:+ [$3]}: " __v || true
  printf -v "$1" '%s' "${__v:-${3:-}}"
}
pick_peer() {
  local names=() i a
  mapfile -t names < <(peer_names)
  ((${#names[@]})) || die "Nenhum peer cadastrado."
  for i in "${!names[@]}"; do printf '  %2d) %s\n' $((i + 1)) "${names[$i]}"; done
  read -rp "Peer (numero ou nome): " a || true
  if [[ $a =~ ^[0-9]+$ ]] && (( 10#$a >= 1 && 10#$a <= ${#names[@]} )); then a=${names[$((10#$a - 1))]}; fi
  printf -v "$1" '%s' "$a"
}
menu_init() {
  local addr port ep dns lans nat iso args=()
  ask addr "IP/mascara do servidor no tunel" "10.99.0.1/24"
  ask port "Porta UDP" "51820"
  ask ep   "Endpoint publico que os peers usam (IP ou DDNS)" "$(detect_ip)"
  ask dns  "DNS entregue aos peers 'client' (vazio = nenhum)" ""
  ask lans "Redes atras do servidor que os peers acessam (vazio = nenhuma)" ""
  ask nat  "Interface para NAT de internet (none = sem NAT; saida padrao: $(default_if))" "none"
  ask iso  "Isolar peers entre si? (s/n)" "s"
  args=(-a "$addr" -p "$port" -e "$ep" -n "$nat")
  [[ -n $dns ]]  && args+=(-d "$dns")
  [[ -n $lans ]] && args+=(-l "$lans")
  [[ $iso =~ ^[nN] ]] && args+=(--no-isolate)
  cmd_init "${args[@]}"
}
menu_peer_add() {
  load_server
  local name type ip lans ca pub args=()
  ask name "Nome do peer (ex.: CLIENTEA-FW01)" ""
  ask type "Tipo: client (notebook/servidor) ou site (roteador com LAN atras)" "client"
  if [[ $type == site ]]; then
    ask lans "LANs atras deste site (ex.: 10.30.0.0/24)" ""
  else
    ask lans "Redes atras deste peer (normalmente vazio)" ""
  fi
  ask ip  "IP no tunel (vazio = proximo livre)" ""
  ask ca  "O que o peer manda pelo tunel: auto ($S_NET${S_LANS:+, $S_LANS}), full (tudo) ou lista" "auto"
  ask pub "Chave publica gerada no proprio peer (vazio = gerar aqui)" ""
  args=(-t "$type" -A "$ca")
  [[ -n $lans ]] && args+=(-L "$lans")
  [[ -n $ip ]]   && args+=(-I "$ip")
  [[ -n $pub ]]  && args+=(--pubkey "$pub")
  cmd_peer_add "$name" "${args[@]}"
}
menu_peer_show() {
  load_server
  local name f out
  pick_peer name
  ask f "Formato: 1) texto  2) QR code  3) MikroTik RouterOS v7  4) salvar .conf" "1"
  case $f in
    2) cmd_peer_show "$name" --qr ;;
    3) cmd_peer_show "$name" --mikrotik ;;
    4) ask out "Arquivo" "./$name.conf"; cmd_peer_show "$name" -o "$out" ;;
    *) cmd_peer_show "$name" ;;
  esac
}
menu_peer_allowed() {
  load_server
  local name lans ca ip
  pick_peer name
  load_peer "$name"
  printf 'Atual no servidor: %s\nAtual no peer:     %s\n' "$(server_allowed)" "$(client_allowed)"
  ask ip   "IP no tunel" "$P_IP"
  ask lans "Redes atras do peer (none = nenhuma)" "${P_LANS:-none}"
  ask ca   "O que o peer manda pelo tunel (auto, full ou lista)" "${P_CLIENT_ALLOWED:-auto}"
  cmd_peer_allowed "$name" -I "$ip" -L "$lans" -A "$ca"
}
menu_peer_del() {
  load_server
  local name; pick_peer name
  cmd_peer_del "$name"
}
menu_server() {
  load_server
  local ep dns lans nat iso ka
  ask ep   "Endpoint" "$S_ENDPOINT"
  ask dns  "DNS para peers client (none = nenhum)" "${S_DNS:-none}"
  ask lans "Redes atras do servidor (none = nenhuma)" "${S_LANS:-none}"
  ask nat  "Interface de NAT (none = sem NAT)" "$S_NAT_IF"
  ask iso  "Isolar peers (yes/no)" "$S_ISOLATE"
  ask ka   "Keepalive padrao para novos peers (s)" "$S_KEEPALIVE"
  cmd_server_set -e "$ep" -d "$dns" -l "$lans" -n "$nat" --isolate "$iso" -k "$ka"
}
run() { ( "$@" ) || warn "Operacao nao concluida."; }
menu() {
  local op new
  while true; do
    printf '\n%sWireGuard Server Manager v%s%s | interface: %s%s\n' "$C_D" "$VERSION" "$C_0" "$IFACE" \
      "$([[ -f $SENV ]] || echo ' (ainda nao criada)')"
    cat <<'EOF'
   1) Instalar dependencias            6) Alterar allowed address de um peer
   2) Criar servidor                   7) Remover peer
   3) Adicionar peer                   8) Alterar servidor (endpoint, DNS, redes, NAT)
   4) Listar peers                     9) Status do tunel
   5) Exportar config do peer         10) Regerar e aplicar config
   i) Trocar interface                 0) Sair
EOF
    read -rp "Opcao: " op || exit 0
    case $op in
      1)  run cmd_install ;;
      2)  run with_lock menu_init ;;
      3)  run with_lock menu_peer_add ;;
      4)  run cmd_peer_list ;;
      5)  run menu_peer_show ;;
      6)  run with_lock menu_peer_allowed ;;
      7)  run with_lock menu_peer_del ;;
      8)  run with_lock menu_server ;;
      9)  run cmd_status ;;
      10) run with_lock cmd_apply ;;
      i|I)
        read -rp "Interface: " new || true
        if [[ $new =~ ^[a-z][a-z0-9_-]{0,14}$ ]]; then IFACE=$new; set_paths; else warn "Nome invalido."; fi ;;
      0|q) exit 0 ;;
      *) warn "Opcao invalida." ;;
    esac
  done
}

usage() {
  cat <<EOF
$PROG v$VERSION - gerador de servidor e peers WireGuard

Uso: $PROG [-i IFACE] [comando]        (sem comando abre o menu)

  install                              instala wireguard-tools, nftables, qrencode
  init  [-a 10.99.0.1/24] [-p 51820] [-e host[:porta]] [-d dns] [-l redes]
        [-n iface_nat|none] [--no-isolate] [-m 1420] [-k 25]
  peer add NOME [-t client|site] [-I ip] [-L redes_atras_do_peer]
                [-A auto|full|redes] [-k keepalive] [--pubkey CHAVE] [--no-psk]
  peer allowed NOME [-I ip] [-L redes|none] [-A auto|full|redes]
  peer show NOME [--qr | --mikrotik | -o arquivo.conf]
  peer list
  peer wipe-key NOME                   apaga a chave privada do peer no servidor
  peer del NOME [-y]
  server set [-e endpoint] [-d dns|none] [-l redes|none] [-n iface|none]
             [--isolate yes|no] [-k keepalive]
  apply | status | json | version      (json: estado para o painel web, sem chaves privadas)

  -L  AllowedIPs no SERVIDOR: redes que ficam atras do peer (LAN do site).
  -A  AllowedIPs no PEER: o que ele manda pelo tunel. auto = rede do tunel +
      redes do servidor; full = 0.0.0.0/0.

Exemplos:
  $PROG init -e vpn.exemplo.com.br -l 172.16.10.0/24
  $PROG peer add FILIAL-SC -t site -L 10.30.0.0/24
  $PROG peer add NOTE-DANIEL -A full
  $PROG peer show FILIAL-SC --mikrotik
EOF
}

main() {
  while (($#)); do
    case $1 in
      -i|--interface) IFACE=$(argv "$@"); shift 2 ;;
      -y|--yes)       ASSUME_YES=1; shift ;;
      *) break ;;
    esac
  done
  set_paths
  local cmd=${1:-menu} sub
  (($#)) && shift
  case $cmd in
    menu)    require_root; menu ;;
    install) cmd_install ;;
    init)    require_root; with_lock cmd_init "$@" ;;
    peer)
      sub=${1:-}
      (($#)) && shift
      require_root
      case $sub in
        add)      with_lock cmd_peer_add "$@" ;;
        del|rm)   with_lock cmd_peer_del "$@" ;;
        list|ls)  cmd_peer_list ;;
        show)     cmd_peer_show "$@" ;;
        allowed)  with_lock cmd_peer_allowed "$@" ;;
        wipe-key) with_lock cmd_peer_wipe "$@" ;;
        *) usage; exit 1 ;;
      esac ;;
    server)
      [[ ${1:-} == set ]] || { usage; exit 1; }
      shift; require_root; with_lock cmd_server_set "$@" ;;
    apply)   require_root; with_lock cmd_apply ;;
    status)  require_root; cmd_status ;;
    json)    require_root; cmd_json ;;
    -h|--help|help)       usage ;;
    -V|--version|version) echo "$PROG $VERSION" ;;
    *) usage; exit 1 ;;
  esac
}

main "$@"
