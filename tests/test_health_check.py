import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import socket
import time

from server.server import Server, ServerConfig
from server.router import Router
from server.response import Response
from deploy_platform.health_check import checar_saude


def _porta_livre():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    porta = s.getsockname()[1]
    s.close()
    return porta


def test_health_check_success():
    router = Router()
    router.add_route("GET", "/health", lambda req, ctx: Response.json({"status": "ok"}))
    porta = _porta_livre()
    config = ServerConfig(host="127.0.0.1", port=porta, max_workers=5)
    servidor = Server(config, router)
    servidor.start(block=False)
    time.sleep(0.2)

    try:
        sucesso, detalhe = checar_saude(f"http://127.0.0.1:{porta}", "/health", tentativas=1)
        assert sucesso is True
        assert "OK" in detalhe
    finally:
        servidor.stop()


def test_health_check_fails_on_error_status():
    router = Router()
    router.add_route("GET", "/health", lambda req, ctx: Response.text("erro", status=500))
    porta = _porta_livre()
    config = ServerConfig(host="127.0.0.1", port=porta, max_workers=5)
    servidor = Server(config, router)
    servidor.start(block=False)
    time.sleep(0.2)

    try:
        sucesso, detalhe = checar_saude(f"http://127.0.0.1:{porta}", "/health", tentativas=1)
        assert sucesso is False
        assert "500" in detalhe
    finally:
        servidor.stop()


def test_health_check_fails_on_connection_refused():
    porta_livre_sem_servidor = _porta_livre()
    sucesso, detalhe = checar_saude(
        f"http://127.0.0.1:{porta_livre_sem_servidor}", "/health",
        tentativas=1, timeout=1,
    )
    assert sucesso is False
