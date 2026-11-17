import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import socket
import time

from server.server import Server, ServerConfig
from core.moracle_adapter import build_router
from core.moracle_middleware import auth_middleware
from core.rate_limit_middleware import rate_limit_middleware, reset_limiters_para_teste
from core.api_key import obter_ou_criar
from core.identity import migrate_legacy_admin_key
from core import config


import pytest

pytestmark = pytest.mark.usefixtures("estado_isolado")

def _porta_livre():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    porta = s.getsockname()[1]
    s.close()
    return porta


def _subir_com_limite_baixo():
    cfg = config.carregar()
    cfg["rate_limit"] = {
        "global_max": 1000, "global_janela_segundos": 60,
        "por_ip_max": 3, "por_ip_janela_segundos": 5,
        "por_rota_max": 1000, "por_rota_janela_segundos": 60,
    }
    config.salvar(cfg)
    reset_limiters_para_teste()

    porta = _porta_livre()
    server_config = ServerConfig(host="127.0.0.1", port=porta, max_workers=5)
    router = build_router()
    servidor = Server(server_config, router, middlewares=[rate_limit_middleware, auth_middleware])
    servidor.start(block=False)
    time.sleep(0.2)
    return servidor, porta


def _http_get(porta, path, headers=None, timeout=3):
    headers = headers or {}
    linhas = [f"GET {path} HTTP/1.1", "Host: x", "Connection: close"]
    for nome, valor in headers.items():
        linhas.append(f"{nome}: {valor}")
    requisicao = ("\r\n".join(linhas) + "\r\n\r\n").encode()
    with socket.create_connection(("127.0.0.1", porta), timeout=timeout) as sock:
        sock.sendall(requisicao)
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


def test_rate_limit_returns_429_after_limit_exceeded():
    servidor, porta = _subir_com_limite_baixo()
    chave = obter_ou_criar()
    migrate_legacy_admin_key(os.path.join(config.RAIZ_PROJETO, '.state'))
    try:
        respostas = []
        for _ in range(5):
            resp = _http_get(porta, "/status", headers={"Authorization": f"Bearer {chave}"})
            respostas.append(resp)

        codigos_200 = sum(1 for r in respostas if b"200 OK" in r)
        codigos_429 = sum(1 for r in respostas if b"429" in r)

        assert codigos_200 == 3, f"esperado 3 respostas 200, obteve {codigos_200}"
        assert codigos_429 == 2, f"esperado 2 respostas 429, obteve {codigos_429}"
    finally:
        servidor.stop()


def test_rate_limit_response_has_retry_after_header():
    servidor, porta = _subir_com_limite_baixo()
    chave = obter_ou_criar()
    migrate_legacy_admin_key(os.path.join(config.RAIZ_PROJETO, '.state'))
    try:
        for _ in range(3):
            _http_get(porta, "/status", headers={"Authorization": f"Bearer {chave}"})
        resposta = _http_get(porta, "/status", headers={"Authorization": f"Bearer {chave}"})
        assert b"429" in resposta
        assert b"Retry-After:" in resposta
    finally:
        servidor.stop()
