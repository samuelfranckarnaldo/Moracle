# Changelog

## 0.1.0 (pre-lancamento)

Primeira versao publica. Formatos de `roles.json`, do cache de IOC e do
`config.json` ainda podem mudar antes da 1.0.

### Seguranca
- Autorizacao na CLI local (`defense block`) por chave de API com a permissao
  `defense.block` (variavel de ambiente `MORACLE_API_KEY`).
- `config set`: classificacao por efeito (livre / protegida / desconhecida),
  permissao `config.security_write`, validacao de tipo e limites, escrita
  atomica e evento de auditoria `config.changed`.
- `forensic ioc-import` e `forensic whois`: permissao `ioc.write`; o `whois`
  sem essa permissao e so de leitura; uma gravacao nunca rebaixa
  `malicioso=True` nem perde a `fonte`; evento `ioc.imported`. O feed so aceita
  IPv4 validos e nao internos.
- Cache de IOC: escrita atomica sob lock entre processos, importacao em lote
  tudo-ou-nada, e um cache ilegivel deixa de derrubar o watchdog (continua pelo
  criterio de contagem e emite um alerta de infraestrutura).
- Auditoria duravel da criacao de chaves e roles e da revogacao de chaves
  (`key.created`, `key.revoked`, `role.created`) e da migracao da chave legada
  (`key.migrated`).
- A CLI deixa de aceitar certificados TLS nao verificados fora de loopback
  (`MORACLE_CA_FILE` para uma CA propria).
- `api_key.txt` e criado com permissao 0600 sem janela de exposicao.

### Alteracoes que podem afetar quem atualiza
- Novas permissoes `config.security_write` e `ioc.write`. Um `roles.json` que as
  contenha nao e lido por versoes anteriores.
- `config set` de chaves protegidas/desconhecidas, `ioc-import` e a gravacao do
  `whois` passam a exigir credencial.
- `config.json` e escrito de forma atomica e com modo 0600.
