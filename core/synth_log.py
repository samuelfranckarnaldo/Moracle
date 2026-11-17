"""
Gerador de logs sintéticos — permite testar deteção e o modo defesa
sem esperar um ataque real acontecer.
"""
import random
from datetime import datetime, timedelta

IPS_LIMPOS = ["192.168.1.10", "192.168.1.11", "10.0.0.20"]
IPS_ATACANTES = ["45.33.12.99", "185.220.101.5", "91.219.237.14"]

PAYLOADS_ATAQUE = [
    "GET /login?user=admin' OR '1'='1 HTTP/1.1",
    "GET /etc/passwd HTTP/1.1",
    "GET /search?q=<script>alert(1)</script> HTTP/1.1",
    "GET /wp-admin/ HTTP/1.1",
    "POST /login HTTP/1.1",
    "GET /../../etc/shadow HTTP/1.1",
]

PAYLOADS_LIMPOS = [
    "GET /index.html HTTP/1.1",
    "GET /about HTTP/1.1",
    "GET /style.css HTTP/1.1",
    "POST /contact HTTP/1.1",
]


def gerar(caminho_saida, total_linhas=200, proporcao_ataque=0.3, seed=None):
    """Gera um log sintético estilo access.log, com uma mistura de
    tráfego limpo e ataques, pra testar o pipeline sem log real."""
    if seed is not None:
        random.seed(seed)

    agora = datetime.now()
    linhas = []

    for i in range(total_linhas):
        timestamp = (agora - timedelta(seconds=(total_linhas - i) * 3)).strftime("%d/%b/%Y:%H:%M:%S")
        if random.random() < proporcao_ataque:
            ip = random.choice(IPS_ATACANTES)
            payload = random.choice(PAYLOADS_ATAQUE)
            status = random.choice([200, 403, 404])
        else:
            ip = random.choice(IPS_LIMPOS)
            payload = random.choice(PAYLOADS_LIMPOS)
            status = 200

        linhas.append(f'{ip} - - [{timestamp}] "{payload}" {status} {random.randint(200, 5000)}')

    with open(caminho_saida, "w") as f:
        f.write("\n".join(linhas) + "\n")

    return {"linhas": total_linhas, "caminho": caminho_saida}
