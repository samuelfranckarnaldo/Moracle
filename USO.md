# Guia de Uso - Moracle

Referencia de todos os comandos disponiveis. Nomes de comando sao sempre em ingles; mensagens de saida seguem o idioma configurado.

## Instalacao do comando mc

Termux:

cat > $PREFIX/bin/mc << 'INNER_EOF'
#!/data/data/com.termux/files/usr/bin/bash
cd ~/moracle && python3 cli.py "$@"
INNER_EOF
chmod +x $PREFIX/bin/mc

Linux/macOS: mesmo conteudo, trocando o shebang pelo bash local e salvando numa pasta ja no PATH (ex: /usr/local/bin/mc).

## Configuracao

mc config show
mc config set idioma en
mc config set diretorio_saida saida
mc config set webhook_url https://...
mc config audit --limit 20
mc config cleanup --days 30
mc config cleanup --days 30 --dry-run

## Modo Forense

### Analisar um log

mc forensic logs acesso.log
mc forensic logs acesso.log --filter sql_injection,xss
mc forensic logs acesso.log --suspects 5
mc forensic logs acesso.log --report saida.md
mc forensic logs acesso.log --json saida.json

Formatos suportados: texto plano (Apache/Nginx), JSON lines, e syslog - detetados automaticamente.

### Correlacionar multiplos logs

mc forensic timeline acesso.log auth.log app.log --report timeline.md

Junta eventos de fontes diferentes numa timeline unica, deduplicada, com deteccao de anomalia de volume por hora.

### Verificar integridade de uma evidencia

mc forensic verify acesso.log

Recalcula o hash e compara com o registrado na coleta original.

### Consultar informacoes sobre um IP ou dominio

mc forensic whois 203.0.113.5
mc forensic whois 203.0.113.5 --virustotal SUA_API_KEY
mc forensic whois 203.0.113.5 --abuseipdb SUA_API_KEY
mc forensic whois 203.0.113.5 --no-cache
mc forensic whois exemplo.com

### Importar feed de IOCs conhecidos

mc forensic ioc-import lista_maliciosos.txt --source "feed-publico-x"

Aceita um IP por linha, ou CSV com IP na primeira coluna.

### Gerar relatorio forense

mc forensic report --title "Incidente 2026-08" --output relatorio.md
mc forensic report --title "Incidente 2026-08" --output relatorio.pdf --format pdf

PDF requer: pip install reportlab --break-system-packages

### Gerar log sintetico (para testes)

mc forensic synth teste.log --lines 200 --attack-ratio 0.3 --seed 42

## Modo Defesa

### Ver estado do agente

mc defense status

### Monitorar um log em tempo real

mc defense monitor acesso.log
mc defense monitor acesso.log --interval 5 --threshold 3
mc defense monitor acesso.log --dry-run

### Monitorar com reinicio automatico (uso em producao/servico)

mc defense watch acesso.log

### Bloquear um IP manualmente

mc defense block 203.0.113.5 --reason "atividade suspeita"
mc defense block 203.0.113.5 --reason "teste" --expires-hours 24

### Checagem de saude

mc defense health
mc defense health --log-file acesso.log

## Outros

mc tech https://exemplo.com

## Rodando como servico (24/7, local)

Linux (systemd) - salvar em /etc/systemd/system/moracle-defense.service:

[Unit]
Description=Moracle - Defense Mode
After=network.target

[Service]
Type=simple
WorkingDirectory=/caminho/para/moracle
ExecStart=/usr/bin/python3 /caminho/para/moracle/cli.py defense watch /var/log/nginx/access.log
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target

Depois:
sudo systemctl daemon-reload
sudo systemctl enable moracle-defense
sudo systemctl start moracle-defense

Termux:
termux-wake-lock
nohup mc defense watch acesso.log > defense.log 2>&1 &

Windows / macOS: Task Scheduler ou launchd, apontando para o mesmo comando mc defense watch <log>.
