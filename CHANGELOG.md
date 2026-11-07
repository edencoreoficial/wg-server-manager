# Changelog

Formato baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/). Versionamento [SemVer](https://semver.org/lang/pt-BR/).

## [1.3.1] - 2026-11-07

### Corrigido
- Checagem de firewall gerava alerta falso de forward em host com Docker: a tabela `ip filter` do iptables-nft era lida como nftables nativo quando não usava extensões xt.
- Com a chain `DOCKER-USER` já gerenciada por regras próprias, o script sugeria `ACCEPT` geral, que passaria por cima dessas regras. Agora só informa.

## [1.3.0] - 2026-11-07

### Adicionado
- Checagem de conflito entre interfaces: porta UDP repetida, rede de túnel sobreposta e LAN de peer repetida em outra interface são recusadas.

### Corrigido
- `init` recusado não deixa mais pasta de estado vazia para trás.

## [1.2.0] - 2026-11-07

### Alterado
- Checagem de firewall do host passa a conferir se a porta e o forward já estão liberados antes de alertar.
- Suporte a nftables nativo com o comando exato para a tabela e a chain do host.
- Forward só é cobrado quando há rede para rotear.

## [1.1.1] - 2026-11-07

### Corrigido
- `install` falhava em todas as distros: o `/etc/os-release` era carregado com `source` e colidia com a variável `VERSION` somente leitura. Agora é lido sem execução.

## [1.1.0] - 2026-11-07

### Adicionado
- Painel web `wgm-panel`, sob demanda via socket do systemd.
- Comando `json` com o estado sem chaves privadas.

## [1.0.0] - 2026-11-07

### Adicionado
- Versão inicial: servidor, peers, allowed address dos dois lados, PresharedKey, exportação em `.conf`, QR code e RouterOS v7, aplicação sem derrubar o túnel.

[1.3.1]: https://github.com/edencoreoficial/wg-server-manager/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/edencoreoficial/wg-server-manager/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/edencoreoficial/wg-server-manager/compare/v1.1.1...v1.2.0
[1.1.1]: https://github.com/edencoreoficial/wg-server-manager/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/edencoreoficial/wg-server-manager/releases/tag/v1.1.0
