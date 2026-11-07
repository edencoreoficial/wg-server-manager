# Política de segurança

## Versões com suporte

Correções de segurança saem na versão mais recente. Atualize antes de reportar, para confirmar que o problema ainda existe.

## Como reportar uma vulnerabilidade

**Não abra issue pública.** Uma falha descrita em público pode ser explorada antes da correção.

Use o canal privado do GitHub: aba **Security**, depois **Report a vulnerability**. Só os mantenedores veem o relato.

Inclua:

- versão do script ou do painel e a distro;
- o que é possível fazer explorando a falha (ex.: ler chave de outro peer, executar comando, burlar login);
- passos para reproduzir em ambiente de laboratório;
- sugestão de correção, se tiver.

Nunca envie chaves privadas, PresharedKeys, senhas ou dados de clientes reais. Gere chaves de teste para demonstrar o problema.

## O que esperar

- Confirmação de recebimento em até 5 dias úteis.
- Avaliação e plano de correção em até 15 dias úteis.
- Crédito na release da correção, se você quiser.

## Escopo

Está no escopo: `wg-server-manager.sh`, `panel/wgm-panel.py` e as units e exemplos de configuração deste repositório.

Fora do escopo: vulnerabilidades do próprio WireGuard, do kernel, do Python ou do sistema operacional. Reporte essas aos respectivos projetos.
