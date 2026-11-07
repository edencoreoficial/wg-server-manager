# ADR-002: Painel web do wg-server-manager (wgm-panel)

**Status:** Proposto
**Data:** 2026-11-07
**Decisores:** Daniel Selbach (Sagarys / EdenCore)
**Relacionado:** ADR-001

## Contexto

O CLI resolve a padronização, mas a equipe quer sair do terminal para o dia a dia: criar peer, ajustar allowed address, entregar a config e ver quem está online. O alvo inclui a VPS do NOC, que já roda PostgreSQL/TimescaleDB, Zabbix server e proxy, Grafana e nginx, com pouca RAM livre (cerca de 200 MB no pior caso). Nessa VPS, o `wg0` é o túnel por onde chegam os agentes dos clientes.

## Decisão

Painel próprio em Python, só com biblioteca padrão, sem JavaScript, **ativado por socket do systemd** e encerrado após ociosidade. Ele não tem lógica de WireGuard: toda alteração chama o `wg-server-manager` com lista de argumentos, e a leitura usa o novo comando `json` do script.

## Opções consideradas

| Opção | RAM | Prós | Contras |
|---|---|---|---|
| A. wgm-panel sob demanda (escolhida) | 0 parado, ~22 a 25 MB ativo (medido) | Reaproveita validações do script; zero dependência externa; sem processo residente | Interface simples; sessões perdidas quando encerra |
| B. WireGuard-UI (Go) | ~20 a 40 MB residente | Pronto, visual completo | Reescreve o `wg0.conf` inteiro (conflita com o script e com o túnel do NOC); foco road warrior; residente |
| C. wg-easy (Node.js) | ~60 a 120 MB residente | Muito usado | Pesado para a VPS do NOC; mesmo conflito de dono do `wg0` |
| D. Flask/FastAPI | ~40 a 70 MB | Código mais organizado | Dependências pip para manter e auditar; ganho pequeno para cinco telas |

## Trade-offs

A decisão prioriza não competir por memória com o banco do Zabbix e não criar um segundo dono do `wg0`. Painéis prontos ganham em recurso visual, mas guardam todas as chaves e reescrevem a config sem as checagens de sobreposição de AllowedIPs. Manter a lógica só no script garante que CLI e painel nunca divergem.

## Consequências

- Mais fácil: operação sem terminal, visão de quem está online, entrega de config por download ou QR.
- Mais difícil: sessões não sobrevivem ao encerramento por ociosidade (novo login após 10 minutos parado).
- Revisitar: perfis de usuário (leitura e escrita), 2FA (TOTP), integração com SSO se o painel crescer.

## MITRE ATT&CK

| Técnica | Controle |
|---|---|
| T1190 Exploit Public-Facing Application | Loopback por padrão; via nginx só com allowlist; sem JS; CSP restrita |
| T1110 Brute Force | PBKDF2 600k; bloqueio por IP real; `limit_req` no nginx; auditoria `login_falhou` |
| T1552.004 Private Keys | Config com chave privada recolhida, `no-store`, auditoria `peer_download`, botão de apagar chave |
| T1078 Valid Accounts | Sessão curta, cookie `HttpOnly/Secure/SameSite=Strict`, CSRF |
| T1059 Command and Scripting Interpreter | Script chamado sem shell; entradas validadas no painel e no script |

## Itens de ação

1. [ ] Rodar os testes obrigatórios do `panel/README.md` em VM Debian 13
2. [ ] Testar o acesso pelo nginx em container da stack NOC (gateway Docker + regra na chain `input`)
3. [ ] Regra no Wazuh para `login_bloqueado` e `peer_download` fora do horário
4. [ ] Avaliar TOTP para o login
