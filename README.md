# Moracle

Plataforma de forense digital e defesa ativa escrita em Python, **so com a
biblioteca padrao** (zero dependencias de execucao). Corre em Linux, macOS e
Termux/Android. Nao funciona em Windows (usa `fcntl`).

> **Estado: 0.1.0 (pre-lancamento).** Os formatos de `config.json`, `roles.json`
> e do cache de IOC podem mudar antes da 1.0. Leia [SECURITY.md](SECURITY.md)
> antes de a colocar em qualquer maquina exposta.

## O que faz

- **Forense** (`forensic`): analise de logs, linha temporal de varios logs,
  geolocalizacao/WHOIS de IPs (VirusTotal e AbuseIPDB opcionais), relatorios,
  verificacao de integridade de evidencias, exportacao STIX/MISP, importacao de
  feeds de IOC.
- **Defesa ativa** (`defense`): monitorizacao de um log em tempo real,
  deteccao por padroes, blocklist com expiracao, alertas, modo `watch` com
  reinicio automatico. **A blocklist e um registo de decisao**: o Moracle nao
  altera firewall nem `iptables`; outra integracao a pode consumir.
- **Servidor** (`server`): servidor HTTP proprio (Admin API, webhook do GitHub,
  TLS opcional), gestao de aplicacoes (criar, deploy, rollback, logs) e
  Console web.
- **Seguranca e auditoria**: chaves de API com roles e permissoes, eventos de
  auditoria duraveis com fila de recuperacao, log de acessos estruturado.

## Instalar

```
git clone <url-do-repositorio> moracle
cd moracle
python3 -m pytest -q        # opcional: precisa de pytest (so para testes)
python3 cli.py --help
```

Opcional: um script `mc` no seu PATH que faca `cd ~/moracle && python3 cli.py "$@"`.

## Primeiros passos

Veja [docs/PRIMEIROS_PASSOS.md](docs/PRIMEIROS_PASSOS.md): arrancar o servidor,
criar a primeira role e chave, bloquear um IP, importar IOCs e recuperar de um
cache de IOC ilegivel.

## Permissoes

| Permissao | Para que serve |
|---|---|
| `server.admin` | Tudo, incluindo gerir chaves e roles |
| `defense.read` / `defense.block` | Ler estado, alertas e blocklist / bloquear IPs |
| `ingest.write` | Enviar eventos para deteccao |
| `config.security_write` | Alterar configuracao protegida (`config set`) |
| `ioc.write` | `forensic ioc-import` e gravar resultados do `whois` no cache de IOC |
| `app.*`, `deployment.*` | Gestao de aplicacoes e deploys |

## Configuracao (`config set`)

As chaves classificam-se pelo efeito: **livres** (`idioma`,
`limite_suspeitos_padrao`) nao exigem credencial; **protegidas** (bloqueio,
auditoria, rate limit, webhook, diretorio de saida, validade do cache de IOC)
e **desconhecidas** exigem `config.security_write`. Todos os valores sao
validados antes de gravar e cada alteracao deixa um evento `config.changed`.

## Testes

```
python3 -m pytest -q
```

Alguns testes arrancam processos reais (deploys). Se falharem em bloco, procure
processos `mini_app` orfaos de uma corrida anterior e repita.

## Licenca

MIT. Veja [LICENSE](LICENSE).
