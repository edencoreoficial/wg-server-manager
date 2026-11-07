# wg-server-manager

Gerador de servidor e peers WireGuard para Debian e demais distros Linux com systemd. Cria o servidor, gera os peers com IP automático, define o allowed address dos dois lados, aplica sem derrubar o túnel e exporta a config do peer em texto, QR code ou script MikroTik RouterOS v7.

Testado em Debian (bash 5, wireguard-tools, nftables). Suporta também Ubuntu, RHEL, Rocky, Alma, Fedora, Arch e openSUSE. Somente IPv4 nesta versão.

## Painel web

Para operar sem terminal, use o painel em `panel/` (sob demanda, ~25 MB só enquanto aberto). Instalação e acesso em `panel/README.md`.

## Instalação

```bash
curl -fsSLO https://raw.githubusercontent.com/edencoreoficial/wg-server-manager/main/wg-server-manager.sh
install -m 750 wg-server-manager.sh /usr/local/sbin/wg-server-manager
wg-server-manager install        # wireguard-tools, nftables, iproute2, qrencode
```

## Uso rápido

Sem argumentos abre o menu:

```bash
sudo wg-server-manager
```

Ou por comando (bom para automação):

```bash
# 1. Servidor: rede do túnel, endpoint público e redes atrás do servidor
wg-server-manager init -a 10.99.0.1/24 -e vpn.exemplo.com.br -l 172.16.10.0/24

# 2. Filial com MikroTik e LAN atrás (site-to-site)
wg-server-manager peer add FILIAL-SC -t site -L 10.30.0.0/24
wg-server-manager peer show FILIAL-SC --mikrotik

# 3. Notebook que só acessa a rede da empresa
wg-server-manager peer add NOTE-DANIEL
wg-server-manager peer show NOTE-DANIEL --qr

# 4. Depois de entregar a config, tire a chave privada do servidor
wg-server-manager peer wipe-key NOTE-DANIEL
```

## Allowed address: os dois lados

O WireGuard usa AllowedIPs como tabela de roteamento e como filtro de origem. O script separa os dois lados:

| Opção | Onde vale | Significa | Exemplo |
|---|---|---|---|
| `-L` | No **servidor** | Redes que ficam atrás do peer. O servidor cria a rota e aceita tráfego vindo delas. | LAN da filial `10.30.0.0/24` |
| `-A` | No **peer** | O que o peer manda pelo túnel. | `auto` = rede do túnel + redes do servidor; `full` = tudo (`0.0.0.0/0`) |

O IP do peer no túnel (`/32`) entra sozinho no lado do servidor. Para alterar depois, sem derrubar ninguém:

```bash
wg-server-manager peer allowed FILIAL-SC -L 10.30.0.0/24,10.31.0.0/24
wg-server-manager peer allowed NOTE-DANIEL -A full
wg-server-manager peer allowed FILIAL-SC -L none      # remove as LANs
```

Se mudar `-A` ou `-I`, reexporte a config do peer com `peer show`.

## Comandos

| Comando | Faz |
|---|---|
| `install` | Instala dependências conforme a distro |
| `init [-a] [-p] [-e] [-d] [-l] [-n] [--no-isolate] [-m] [-k]` | Cria o servidor, sobe `wg-quick@<iface>` e habilita no boot |
| `peer add NOME [-t client\|site] [-I ip] [-L redes] [-A auto\|full\|redes] [--pubkey CHAVE] [--no-psk]` | Cria peer com chaves, PSK e IP livre |
| `peer allowed NOME [-I] [-L] [-A]` | Altera IP e allowed address |
| `peer show NOME [--qr \| --mikrotik \| -o arquivo]` | Exporta a config do peer |
| `peer list` | Peers com LANs, último handshake e tráfego |
| `peer wipe-key NOME` | Apaga a chave privada do peer no servidor |
| `peer del NOME [-y]` | Remove peer, chaves e rotas |
| `server set [-e] [-d] [-l] [-n] [--isolate yes\|no] [-k]` | Altera endpoint, DNS, redes, NAT, isolamento |
| `apply` | Regera e reaplica tudo a partir do estado |
| `status` | Resumo, `wg show` e checagem do firewall do host |
| `json` | Estado em JSON (sem chaves privadas), usado pelo painel web |

Várias interfaces: `wg-server-manager -i wg1 init ...`, `wg-server-manager -i wg1 peer add ...`.

Opções do `init`: `-a` IP/máscara do servidor no túnel (padrão `10.99.0.1/24`), `-p` porta UDP (51820), `-e` endpoint público IP ou DDNS, `-d` DNS para peers `client`, `-l` redes atrás do servidor, `-n` interface para NAT de internet (padrão `none`), `--no-isolate` permite peer falar com peer, `-m` MTU (1420), `-k` keepalive padrão (25 s).

## Onde ficam os arquivos

```
/etc/wireguard/
├── wg0.conf                   gerado; não edite à mão
└── wgm/wg0/
    ├── server.env             parâmetros do servidor
    ├── server.key / .pub
    ├── fw.nft                 tabela nftables própria (PostUp/PostDown)
    ├── backups/               20 últimas versões do wg0.conf
    └── peers/<NOME>/
        ├── peer.env           tipo, IP, LANs, allowed do peer
        ├── public.key, psk
        └── private.key        só se gerada aqui; some com wipe-key
```

Backup: copie `/etc/wireguard/` inteiro. Restaurar em outro servidor é copiar a pasta e rodar `wg-server-manager apply`.

## Firewall

O script cria só a tabela `inet wgm_<iface>` (subida e removida com a interface) com:

- descarte de pacote `invalid` vindo do túnel;
- isolamento entre peers (padrão ligado; desligue com `--isolate no` se filiais precisarem se falar pelo hub);
- masquerade de saída só se você definir `-n <iface>`.

Ele **não** mexe no firewall do host. No `init` e no `status` ele confere se a porta UDP do túnel e o forward do `wg0` já estão liberados e só avisa o que falta, com o comando pronto:

| Firewall do host | Comando sugerido |
|---|---|
| ufw | `ufw allow <porta>/udp` e `ufw route allow in on wg0` |
| firewalld | `firewall-cmd` com a porta e a interface na zona `trusted` |
| iptables com `FORWARD DROP` (Docker, sem ufw) | regras na `DOCKER-USER` (ou `FORWARD`) |
| nftables nativo | `nft add rule <família> <tabela> <chain> ...` com os nomes reais da sua tabela |

O forward só é cobrado quando há rede para rotear: redes atrás do servidor, LAN de peer, NAT ou isolamento desligado. Tabelas que o `iptables-nft` cria para o ufw e o Docker não são confundidas com nftables nativo. Quando está tudo liberado, aparece `[ok] Firewall do host: ...`.

Com nftables nativo, grave as regras também no arquivo que carrega a tabela (por exemplo `/etc/nftables.conf`). Em host com Docker ou ufw, esse arquivo não pode ter `flush ruleset`, e o serviço `nftables` não deve ser parado com `systemctl stop`, porque os dois apagam as regras do Docker e do ufw.

Libere também a porta UDP no firewall do provedor e encaminhe no roteador de borda, se houver.

## Segurança por design

- Arquivos 600 e pastas 700; estado lido sem `source`.
- Config nova validada com `wg-quick strip` antes de substituir a atual.
- AllowedIPs sobrepostos são recusados, e `0.0.0.0/0` é bloqueado no lado do servidor.
- PresharedKey por peer.
- `--pubkey`: o peer gera a própria chave e a privada nunca passa pelo servidor. Use em celular, notebook de terceiro e roteador de cliente.
- NAT de saída desligado: a VPN não vira saída de internet sem decisão explícita.
- `flock` impede duas alterações simultâneas na mesma interface.

## Testes obrigatórios antes de produção

| Teste | Comando | Esperado |
|---|---|---|
| Serviço | `systemctl is-active wg-quick@wg0` | `active` |
| Boot | `reboot` e depois `wg show wg0` | interface de volta com todos os peers |
| Tabela própria | `nft list table inet wgm_wg0` | regras de isolamento e invalid |
| Porta | `ss -lunp \| grep 51820` | escutando |
| Handshake | `wg-server-manager peer list` após conectar o peer | handshake de poucos segundos |
| Sem queda ao incluir peer | ping contínuo de um peer enquanto roda `peer add` | nenhuma perda |
| Rota da LAN do site | `ip route show dev wg0` | LAN do peer `site` presente |
| Isolamento | de um peer, ping no IP de outro peer | falha |
| Conflito | `peer add X -L <LAN de outro peer>` | recusado com mensagem |
| Remoção | `peer del NOME -y` e reconectar com a config antiga | sem handshake; rota removida |
| Firewall do host | `wg-server-manager status` | nenhum aviso pendente, ou ação tomada |

## Problemas comuns

- **Handshake "nunca":** porta UDP bloqueada no provedor ou no host (veja `status`), endpoint errado (`server set -e`), relógio ou chave pública trocada.
- **Handshake ok, sem tráfego para a LAN do site:** `ip_forward` desligado no roteador do site, firewall do site bloqueando o forward, ou `-L` não cadastrado no servidor.
- **Cliente navega mas não acessa a rede interna:** `-A` do peer não inclui a rede; ajuste com `peer allowed NOME -A auto` e reexporte.
- **Trafega até o servidor e para:** `FORWARD DROP` do Docker ou firewalld; aplique as regras que o `status` mostra.
- **DNS não funciona no cliente Linux:** instale `resolvconf` ou `openresolv` no cliente (o `wg-quick` usa para aplicar `DNS =`).

## Limitações desta versão

IPv4 apenas; não importa `.conf` existente (o `init` recusa sobrescrever); porta de escuta fixa após o `init`. Detalhes e alternativas avaliadas em `docs/ADR-001-gerador-wireguard.md`.

Licença MIT. EdenCore / Sagarys.
