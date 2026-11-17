# Seguranca

## Reportar uma vulnerabilidade

**Nao abra uma issue publica.** Envie os detalhes em privado para
`[CONTACTO DE SEGURANCA - preencher antes de publicar]` (ou use "Report a
vulnerability" no separador Security do repositorio, se estiver ativo).
Indique a versao, os passos para reproduzir e o impacto.

## O que o Moracle garante

- Acoes protegidas (`defense block`, `config set` de chaves protegidas,
  `forensic ioc-import`, gravacao do `whois`, criacao/revogacao de chaves e
  roles) exigem uma chave de API com a permissao certa e deixam um evento de
  auditoria **duravel antes** de a acao ser executada. Se a auditoria nao
  puder ser gravada, a acao nao acontece. Excecoes por desenho: as chaves de
  configuracao *livres* (`idioma`, `limite_suspeitos_padrao`), que nao tem efeito
  de seguranca, sao alteradas mesmo sem auditoria, e o evento da migracao da
  chave legada e registado depois do facto (em melhor esforco, com aviso).
- Os eventos de auditoria nunca contem segredos (tokens, hashes de chaves,
  valores de configuracao sensiveis).
- A escrita de estado (config, cache de IOC, chaves) e atomica e sob lock
  entre processos.

## O que o Moracle NAO garante (limitacoes conhecidas da 0.1.0)

1. **Bloqueios automaticos nao exigem autorizacao por acao.** `defense
   monitor`/`watch` e `server start` bloqueiam IPs sem credencial propria. Os
   bloqueios ficam auditados com `actor.automatic=true` (rastreabilidade, nao
   autorizacao). Direcao prevista: uma chave dedicada com uma role limitada a
   `defense.block`.
2. **Nao ha enforcement de rede.** A blocklist e um registo; o Moracle nao
   mexe no firewall.
3. **A chave legada** (`.state/api_key.txt`) e um segredo em texto simples com
   poderes de administrador (apos o arranque do servidor e migrada para uma
   chave `server.admin`), e `mc server key` mostra-a. Proteja o diretorio
   `.state/`. Crie chaves com roles minimas e guarde a legada.
4. **Segredos na linha de comandos** (`--admin-key`, `--github-webhook-secret`)
   ficam visiveis na lista de processos em maquinas partilhadas.
5. **TLS.** Por omissao o servidor escuta em `127.0.0.1` em HTTP. Fora do
   localhost use `--tls` (o servidor avisa se nao o fizer). A CLI verifica o
   certificado fora de loopback; para uma CA propria use `MORACLE_CA_FILE`.
6. **Durabilidade.** A escrita atomica sincroniza o ficheiro mas nao o
   diretorio: uma falha de energia pode perder a ultima alteracao.
7. **Cache de IOC com validade.** Entradas (incluindo as importadas) expiram
   apos `ioc_cache_validade_horas` (24 h por omissao); reimporte os feeds
   periodicamente.
8. **O log de comandos legado** (`.state/audit.log`) regista o pedido, nao o
   resultado.
9. Configuracao alterada so e aplicada a processos longos (watchdog) depois de
   reiniciados.

## Boas praticas de instalacao

- Execute como utilizador sem privilegios; o Moracle nao precisa de root.
- Mantenha `.state/`, `config.json` e `*.key` fora do controlo de versoes (o
  `.gitignore` ja os exclui).
- Nunca exponha a Admin API sem TLS.
