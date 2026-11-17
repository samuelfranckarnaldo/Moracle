import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import socket
import threading
import time

from server.server import Server, ServerConfig
from server.router import Router
from server.limits import Limits
from server.response import Response


def _porta_livre():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    porta = s.getsockname()[1]
    s.close()
    return porta


def test_max_connections_from_limits_is_respected_not_hardcoded():
    """Antes desta correcao, a fila era sempre max_workers*4 (numero
    magico). Agora deve ser exatamente Limits.max_connections."""
    bloqueio = threading.Event()

    def handler_lento(req, ctx):
        bloqueio.wait(timeout=5)
        return Response.text("ok")

    router = Router()
    router.add_route("GET", "/lento", handler_lento)

    porta = _porta_livre()
    limites = Limits(max_connections=2, read_timeout=2, write_timeout=2)
    config = ServerConfig(host="127.0.0.1", port=porta, max_workers=1, limits=limites)
    servidor = Server(config, router)
    servidor.start(block=False)
    time.sleep(0.2)

    conexoes = []
    try:
        for _ in range(5):
            sock = socket.create_connection(("127.0.0.1", porta), timeout=3)
            sock.sendall(b"GET /lento HTTP/1.1\r\nConnection: close\r\n\r\n")
            conexoes.append(sock)
        time.sleep(0.5)

        recusas = 0
        for sock in conexoes:
            sock.settimeout(2)
            resposta = b""
            try:
                while True:
                    pedaco = sock.recv(4096)
                    if not pedaco:
                        break
                    resposta += pedaco
            except (socket.timeout, ConnectionResetError):
                pass
            if b"503" in resposta:
                recusas += 1

        assert recusas >= 2, f"esperado pelo menos 2 recusas com max_connections=2, obteve {recusas}"
    finally:
        bloqueio.set()
        for sock in conexoes:
            try:
                sock.close()
            except OSError:
                pass
        servidor.stop()
