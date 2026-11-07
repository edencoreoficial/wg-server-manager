## O que muda

<!-- Descreva a mudança e o motivo. Se resolve uma issue, cite: Closes #123 -->

## Como testei

<!-- Distro, comandos executados e o caso que deve ser recusado -->

## Checklist

- [ ] `shellcheck -S warning wg-server-manager.sh` sem avisos
- [ ] `python3 -m py_compile panel/wgm-panel.py`
- [ ] Testei o caso que mudou e um caso que deve ser recusado
- [ ] A saída `json` continua sem chave privada nem PresharedKey
- [ ] README e CHANGELOG.md atualizados, se o comportamento mudou
- [ ] Nenhuma chave, IP público ou dado de cliente no PR
