"""
Health check HTTP puro (stdlib http.client) - usado antes de promover
um deployment a ACTIVE. Nao depende de requests nem de nenhuma lib
externa.
"""
import http.client
import time
from urllib.parse import urlsplit


def checar_saude(base_url, path="/health", timeout=5, tentativas=3, espera_entre_tentativas=1.0):
    """Retorna (sucesso: bool, detalhe: str). Tenta multiplas vezes
    antes de desistir - um processo recem-iniciado pode levar um
    instante para comecar a aceitar conexoes."""
    partes = urlsplit(base_url)
    host = partes.hostname
    porta = partes.port or (443 if partes.scheme == "https" else 80)
    usar_tls = partes.scheme == "https"

    ultimo_erro = None
    for tentativa in range(1, tentativas + 1):
        try:
            if usar_tls:
                import ssl
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(host, porta, timeout=timeout, context=ctx)
            else:
                conn = http.client.HTTPConnection(host, porta, timeout=timeout)

            conn.request("GET", path)
            resposta = conn.getresponse()
            status = resposta.status
            resposta.read()
            conn.close()

            if 200 <= status < 300:
                return True, f"health check OK (status {status}) na tentativa {tentativa}"
            ultimo_erro = f"status HTTP {status}"
        except Exception as e:
            ultimo_erro = str(e)

        if tentativa < tentativas:
            time.sleep(espera_entre_tentativas)

    return False, f"health check falhou apos {tentativas} tentativas: {ultimo_erro}"
