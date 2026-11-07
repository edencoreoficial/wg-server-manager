# Como contribuir

Contribuições são bem-vindas: correção de bug, suporte a outra distro, melhoria na documentação ou no painel. Este guia explica como fazer sem retrabalho.

## Antes de começar

- **Bug:** abra uma issue com o modelo "Bug". Inclua a distro, a versão do script (`wg-server-manager version`) e a saída do erro. Remova chaves, IPs públicos e nomes de clientes antes de colar.
- **Vulnerabilidade:** não abra issue pública. Siga o [SECURITY.md](SECURITY.md).
- **Funcionalidade nova:** abra uma issue com o modelo "Sugestão" antes de escrever código. Assim dá para alinhar o escopo antes de você investir tempo.

## Princípios do projeto

Um PR que vai contra estes pontos dificilmente é aceito, mesmo funcionando:

1. **Toda a lógica de WireGuard fica no `wg-server-manager.sh`.** O painel só chama o script. Validação nova entra no script, nunca só no painel.
2. **O script não altera o firewall do host.** Ele cria apenas a própria tabela `inet wgm_<iface>` e, no resto, verifica e mostra o comando. Nunca `flush ruleset`.
3. **Sem dependência fora da distro.** Bash, `wireguard-tools`, `nftables`, `iproute2`. O painel usa só a biblioteca padrão do Python.
4. **Estado nunca é executado.** Arquivos de estado e de sistema são lidos linha a linha, sem `source`.
5. **Recusar é melhor que aplicar errado.** Conflito de rede, porta repetida ou config inválida param a operação antes de tocar no `.conf` em uso.

## Ambiente de teste

Use uma VM ou container de laboratório. Não teste em servidor com túneis de produção.

O script aceita a variável `WG_DIR`, que isola todo o estado em uma pasta temporária:

```bash
export WG_DIR=$(mktemp -d)
sudo -E ./wg-server-manager.sh -i wgtest init -a 10.99.0.1/24 -e vpn.exemplo.com.br
sudo -E ./wg-server-manager.sh -i wgtest peer add TESTE
sudo -E ./wg-server-manager.sh -i wgtest json
```

Sem módulo WireGuard no kernel (container, por exemplo), o `wireguard-go` sobe a interface em espaço de usuário para testes de ponta a ponta.

## Checklist do PR

- [ ] `bash -n wg-server-manager.sh` e `shellcheck -S warning wg-server-manager.sh` sem avisos
- [ ] `python3 -m py_compile panel/wgm-panel.py`
- [ ] Testei o caso que mudou e um caso que deve ser recusado
- [ ] A saída `json` continua sem chave privada nem PresharedKey
- [ ] README e `CHANGELOG.md` atualizados quando o comportamento muda
- [ ] Sem travessão (U+2014) em texto e mensagens

O CI roda as duas primeiras verificações automaticamente em cada PR.

## Estilo

- Mensagens ao usuário em português, sem acento no script (compatibilidade com terminais) e com acento no painel e na documentação.
- Comentário só quando o motivo não é óbvio pelo código.
- Commits no padrão `tipo: descrição` (`feat`, `fix`, `docs`, `refactor`, `test`).

## Licença

Ao enviar um PR, você concorda que sua contribuição seja distribuída sob a [licença MIT](LICENSE) do projeto.
