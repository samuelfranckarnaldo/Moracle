# Contribuir

Obrigado pelo interesse. O projeto segue uma disciplina simples e estrita.

## Regras

- **So biblioteca padrao.** Nao se acrescentam dependencias de execucao.
- **Testes.** `python3 -m pytest -q` tem de passar. Cada alteracao de
  comportamento traz testes; uma alteracao de seguranca traz tambem testes do
  caso negativo (o que nao pode acontecer).
- **Uma peca de cada vez.** Alteracoes grandes comecam com uma proposta
  (issue) que descreve o contrato: o que muda, o que nao muda, que
  comportamentos antigos deixam de valer. Testes de caracterizacao do
  comportamento atual vem antes da alteracao.
- **Sem alteracoes de ambito silenciosas.** Se a implementacao exigir tocar
  num ficheiro nao previsto, diga-o e justifique no PR.
- **Estado nos testes.** Os testes nunca podem escrever em `config.json`,
  `.state/` ou no cache reais: use `tmp_path` e os monkeypatches das fixtures
  existentes.
- **Seguranca.** Vulnerabilidades: ver [SECURITY.md](SECURITY.md), nunca em
  issues publicas.

## Plataformas

Linux, macOS e Termux. Windows nao e suportado (`fcntl`).
