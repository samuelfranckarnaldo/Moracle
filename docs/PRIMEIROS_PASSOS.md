# Primeiros passos

Substitua `mc` por `python3 cli.py` se nao tiver o script instalado.

## 1. Arrancar o servidor

```
mc server start                 # http://127.0.0.1:7000
mc server start --tls           # com TLS (certificado autoassinado se nao der um)
mc server key                   # mostra a chave de administrador (legada)
```

No primeiro arranque a chave legada e migrada para uma chave `server.admin`.

## 2. Criar uma role e uma chave com o minimo de poderes

Use a chave de administrador so para isto e depois guarde-a.

```
ADMIN=<chave de mc server key>

curl -s -X POST http://127.0.0.1:7000/admin/roles \
  -H "Authorization: Bearer $ADMIN" -H "Content-Type: application/json" \
  -d '{"name":"bloqueio","permissions":["defense.block"]}'

curl -s -X POST http://127.0.0.1:7000/admin/keys \
  -H "Authorization: Bearer $ADMIN" -H "Content-Type: application/json" \
  -d '{"name":"cli-bloqueio","role":"bloqueio"}'
```

A resposta da segunda chamada traz `secret`: **so aparece uma vez**. Cada
criacao e revogacao deixa um evento de auditoria (`key.created`,
`role.created`, `key.revoked`).

## 3. Usar a chave na CLI

```
export MORACLE_API_KEY=<secret>
mc defense block 203.0.113.5 --reason "scanner" --expires-hours 24
```

Para importar feeds de IOC e gravar `whois` no cache, crie uma role com
`ioc.write`; para alterar configuracao protegida, uma com
`config.security_write`.

```
mc forensic ioc-import feed.txt --source meu_feed
mc config set defesa.limite_alerta_padrao 5
mc config set limite_suspeitos_padrao 20     # chave livre: sem credencial
```

`forensic whois <ip>` funciona sempre; sem `ioc.write` nao grava no cache.

## 4. Monitorizar um log

```
mc defense monitor /caminho/access.log --dry-run   # so mostra o que bloquearia
mc defense watch /caminho/access.log               # com reinicio automatico
mc defense alerts
```

## 5. Recuperar de um cache de IOC ilegivel

Se o watchdog imprimir `[IOC] cache de IOC ilegivel (causa=...)`, o cache esta
corrompido. O watchdog continua a bloquear pelo criterio de contagem, mas nao
consulta IOCs. O Moracle **nunca** apaga nem recria o ficheiro sozinho:

```
cd <raiz>/<diretorio_saida>          # por omissao: saida/
mv ioc_cache.json ioc_cache.json.quarentena
mc forensic ioc-import feed.txt --source meu_feed
```

Depois reinicie o watchdog (o estado de degradacao so e reposto no arranque).
