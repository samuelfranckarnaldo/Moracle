"""
Decisao arquitetural explicita: o Moracle Server NAO implementa
keep-alive nesta fase. Cada conexao TCP processa exatamente UMA
requisicao e o servidor fecha a conexao em seguida (equivale a
'Connection: close' sempre, independente do que o cliente pedir).

Isso significa 'maximo de requests por conexao' = 1, por design,
nao por limite numerico configuravel. Se keep-alive for implementado
no futuro, este teste precisa ser atualizado - ele existe para que
essa mudanca de comportamento seja deliberada, nao acidental.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import socket
import time

from server.server import Server, ServerConfig
from server.router import Router
from server.response import Response


def _porta_livre():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    porta = s.getsockname()[1]
    s.close()
    return porta


def test_connection_closes_after_single_request_even_with_keepalive_header():
    router = Router()
    router.add_route("GET", "/x", lambda req, ctx: Response.text("ok"))

    porta = _porta_livre()
    config = ServerConfig(host="127.0.0.1", port=porta, max_workers=5)
    servidor = Server(config, router)
    servidor.start(block=False)
    time.sleep(0.2)

    try:
        with socket.create_connection(("127.0.0.1", porta), timeout=3) as sock:
            sock.sendall(b"GET /x HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n")
            sock.settimeout(2)
            primeira_resposta = b""
            try:
                while True:
                    pedaco = sock.recv(4096)
                    if not pedaco:
                        break
                    primeira_resposta += pedaco
            except socket.timeout:
                pass
            assert b"200 OK" in primeira_resposta

            try:
                sock.sendall(b"GET /x HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                sock.settimeout(1)
                segunda_resposta = sock.recv(4096)
            except (OSError, socket.timeout):
                segunda_resposta = b""

            assert segunda_resposta == b"", (
                "conexao deveria ter sido fechada apos a primeira resposta "
                "(sem keep-alive); recebeu dados na segunda tentativa"
            )
    finally:
        servidor.stop()
