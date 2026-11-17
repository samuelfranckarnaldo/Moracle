"""
Comprova que rotas 404/405/OPTIONS escapam da pipeline de middleware
(rate limit e auth) porque router.match() acontece ANTES da pipeline
rodar. Um atacante pode martelar rotas inexistentes sem nunca ser
rate-limited, porque o 404 e' gerado de graca, fora da pipeline.

Este teste deve FALHAR contra o codigo atual (comprova o bug) e
PASSAR depois da correcao que move a pipeline para envolver todo o
processo de roteamento, nao so o handler final.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import socket
import time

from server.server import Server, ServerConfig
from server.router import Router
from server.limits import Limits
from server.response import Response
from core.rate_limit_middleware import reset_limiters_para_teste
from core import config


def _porta_livre():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    porta = s.getsockname()[1]
    s.close()
    return porta


def _http_get(porta, path, timeout=3):
    req = f"GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".encode()
    with socket.create_connection(("127.0.0.1", porta), timeout=timeout) as sock:
        sock.sendall(req)
        sock.settimeout(timeout)
        resposta = b""
        try:
            while True:
                pedaco = sock.recv(4096)
                if not pedaco:
                    break
                resposta += pedaco
        except socket.timeout:
            pass
        return resposta


def test_rate_limit_applies_even_to_nonexistent_routes():
    """Martelar uma rota inexistente TAMBEM deve ser rate-limited -
    senao um atacante evita o limite so batendo em paths que nao
    existem, e nunca leva 429."""
    cfg = config.carregar()
    cfg["rate_limit"] = {
        "global_max": 1000, "global_janela_segundos": 60,
        "por_ip_max": 3, "por_ip_janela_segundos": 5,
        "por_rota_max": 1000, "por_rota_janela_segundos": 60,
    }
    config.salvar(cfg)
    reset_limiters_para_teste()

    def rate_limit_middleware(req, ctx, nxt):
        from core.rate_limit_middleware import rate_limit_middleware as real
        return real(req, ctx, nxt)

    from core.rate_limit_middleware import rate_limit_middleware as rl_mw

    router = Router()
    router.add_route("GET", "/existe", lambda req, ctx: Response.text("ok"))

    porta = _porta_livre()
    server_config = ServerConfig(host="127.0.0.1", port=porta, max_workers=5)
    servidor = Server(server_config, router, middlewares=[rl_mw])
    servidor.start(block=False)
    time.sleep(0.2)

    try:
        respostas = [_http_get(porta, "/rota-que-nao-existe") for _ in range(5)]
        codigos_429 = sum(1 for r in respostas if b"429" in r)
        codigos_404 = sum(1 for r in respostas if b"404" in r)

        assert codigos_429 == 2, (
            f"esperado 2 respostas 429 apos o limite de 3, obteve {codigos_429} "
            f"(404 puros: {codigos_404}) - rota 404 esta escapando do rate limit"
        )
    finally:
        servidor.stop()
