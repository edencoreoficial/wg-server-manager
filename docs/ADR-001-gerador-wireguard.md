# ADR-001: Gerador de servidor e peers WireGuard (wg-server-manager)

**Status:** Proposto
**Data:** 2026-11-07
**Decisores:** Daniel Selbach (Sagarys / EdenCore)

## Contexto

Hoje cada túnel WireGuard em Linux é montado à mão: `wg genkey`, edição do `wg0.conf`, cálculo de IP livre, AllowedIPs dos dois lados, rotas das LANs, forward e NAT. Isso gera três problemas recorrentes:

1. **AllowedIPs sobrepostos.** O WireGuard não acusa erro: o último peer cadastrado assume a rede e o tráfego de um cliente passa a ir para outro. Em ambiente multi-cliente (NOC Sagarys, sites remotos via VPN) isso é vazamento entre clientes.
2. **Reload derrubando o túnel.** `systemctl restart wg-quick@wg0` para incluir um peer derruba todos os outros.
3. **Execução dependente de quem sabe.** O procedimento muda de técnico para técnico, o que fere a regra de manual autoexplicativo.

Restrições: rodar em Debian e nas demais distros com systemd, sem dependência além de pacotes da própria distro, coexistir com hosts que já têm Docker, nftables e allowlists próprias (stack NOC), e servir também como material da EdenCore. A interface desejada é de terminal (sem web), mas sem exigir que o operador saiba a sintaxe do `wg`.

## Decisão

Script Bash único (`wg-server-manager.sh`) com dois modos sobre o mesmo núcleo: menu interativo para quem está começando e subcomandos idempotentes para automação. O estado vive em `/etc/wireguard/wgm/<iface>/` (um arquivo por peer) e o `<iface>.conf` é **gerado** a partir dele, validado e aplicado com `wg syncconf`.

## Opções consideradas

### Opção A: Script Bash com estado próprio (escolhida)

| Dimensão | Avaliação |
|---|---|
| Complexidade | Baixa: um arquivo, dependências da distro |
| Custo | Zero |
| Escalabilidade | Boa até centenas de peers por interface |
| Familiaridade da equipe | Alta (Bash, wg-quick, nftables) |

**Prós:** roda em qualquer distro com `wireguard-tools`; auditável linha a linha; nada exposto na rede; mesmo padrão do wg-client-manager.
**Contras:** Bash exige disciplina com `set -e` e validação; sem API; IPv6 fica para depois.

### Opção B: Painel web (wg-easy, WireGuard-UI, similares)

| Dimensão | Avaliação |
|---|---|
| Complexidade | Média: container, proxy reverso, autenticação |
| Custo | Zero de licença, custo operacional de manter mais um serviço |
| Escalabilidade | Boa |
| Familiaridade da equipe | Média |

**Prós:** visual, QR code na tela.
**Contras:** mais uma superfície de ataque publicada (T1190) guardando todas as chaves; muitos assumem cenário road warrior com NAT e não tratam site-to-site com LANs; dependência de projeto de terceiros.

### Opção C: Python ou Go com TUI

| Dimensão | Avaliação |
|---|---|
| Complexidade | Média/Alta: runtime ou binário por arquitetura |
| Custo | Zero |
| Escalabilidade | Excelente |
| Familiaridade da equipe | Média |

**Prós:** código mais testável, estruturas de dados reais.
**Contras:** runtime extra no servidor (Python) ou build por arquitetura (Go); exagero para o volume atual.

### Opção D: Editar o .conf com marcadores BEGIN/END

**Prós:** menos arquivos.
**Contras:** parsing frágil, edição manual quebra o script, sem metadados por peer. Rejeitada a favor do estado separado com render completo.

## Análise de trade-offs

O peso maior ficou em segurança e operação, não em recurso visual. Um painel web centraliza chaves de todos os clientes atrás de uma tela de login, exatamente o que a stack NOC evita. O Bash cobre o problema real (validação de AllowedIPs, aplicação sem queda, padronização) com o menor custo de manutenção. Se o volume crescer ou surgir necessidade de API, o modelo de estado (um `peer.env` por peer) permite migrar para Python ou Go sem converter dados.

## Decisões de projeto

| Tema | Decisão | Motivo |
|---|---|---|
| Fonte da verdade | `wgm/<iface>/server.env` e `peers/<nome>/peer.env`; o `.conf` é sempre regerado | Elimina divergência e edição manual |
| Leitura do estado | Parser com lista de chaves, sem `source` | Arquivo de estado nunca executa código |
| Aplicação | `wg syncconf` + sincronização de rotas | Peers conectados não caem; `syncconf` não mexe em rotas, o script faz |
| Validação | `wg-quick strip` no arquivo novo antes de trocar; backup das 20 últimas versões | Config inválida nunca entra em produção |
| Conflitos | Recusa sobreposição entre túnel, redes do servidor e AllowedIPs de qualquer peer | Evita sequestro silencioso de rede |
| `0.0.0.0/0` | Proibido no lado do servidor; permitido no lado do peer (`-A full`) | Túnel total é escolha do cliente, nunca rota do hub |
| Chaves | PSK por peer; opção `--pubkey`; `wipe-key` com `shred` | Privada pode nunca tocar o servidor, ou sair dele após entrega |
| Firewall | Tabela própria `inet wgm_<iface>` via PostUp/PostDown; isolamento entre peers ligado; NAT desligado | Não interfere em Docker, `noc-docker-user` ou nftables do host; nunca `flush ruleset` |
| Firewall do host | Só detecta e avisa (firewalld, ufw, FORWARD DROP do Docker, input drop) | Política do host é de quem administra o host |
| Tipos de peer | `client` (recebe DNS) e `site` (LANs atrás, sem DNS) | Site com DNS sequestraria o resolvedor do roteador |
| Exportação | `.conf`, QR code e script RouterOS v7 | Sites remotos da Sagarys são majoritariamente MikroTik |
| Concorrência | `flock` por interface | Dois operadores não corrompem o estado |

## Mapeamento MITRE ATT&CK

| Técnica | Controle |
|---|---|
| T1552.004 Private Keys | Arquivos 600 em pastas 700; `--pubkey`; `wipe-key` com `shred`; remoção de peer apaga chaves |
| T1557 Adversary-in-the-Middle | Recusa de AllowedIPs sobrepostos (um peer não assume a rede de outro) |
| T1021 / T1570 Movimento lateral | Isolamento entre peers no forward por padrão |
| T1090 Proxy | NAT de saída desligado: a VPN não vira saída de internet sem decisão explícita |
| T1133 External Remote Services | Só a porta UDP do túnel é exposta; WireGuard não responde a pacote sem chave válida |
| T1190 Exploit Public-Facing Application | Sem painel web publicado |

Para o SOC: o contador das regras `isolamento entre peers` e `ct state invalid` na tabela `inet wgm_<iface>` é métrica pronta para item no Zabbix (`nft -j list table inet wgm_wg0`). Handshake ausente por mais de 5 minutos em peer `site` é candidato natural a trigger.

## Consequências

- **Fica mais fácil:** criar peer site-to-site com LAN em um comando, entregar config por QR ou RouterOS, alterar AllowedIPs sem derrubar o túnel, auditar quem tem acesso (`peer list`).
- **Fica mais difícil:** editar o `.conf` à mão (é sobrescrito); quem precisar de regra especial usa o firewall do host.
- **Revisitar:** suporte a IPv6; importação de `.conf` existente; exportação de métricas para o Zabbix; integração com OSPF/FRRouting prevista para a ferramenta da EdenCore.

## Itens de ação

1. [ ] Rodar o checklist de testes do README em VM de laboratório Debian 13 e em uma RHEL-like
2. [ ] Testar um peer `site` com MikroTik RouterOS v7 usando a exportação `--mikrotik`
3. [ ] Testar em host com Docker para validar o aviso de FORWARD DROP e as regras sugeridas
4. [ ] Versionar no GitHub da EdenCore (repositório dedicado, mesmo padrão do wg-client-manager)
5. [ ] Criar template Zabbix com handshake por peer e contadores da tabela `wgm`
