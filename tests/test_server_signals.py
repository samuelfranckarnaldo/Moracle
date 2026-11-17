"""
Testa o lifecycle de graceful shutdown sob sinal real do SO (SIGTERM),
nao apenas chamada programatica de stop(). Verifica que uma requisicao
em andamento no momento do sinal ainda recebe resposta antes do
processo encerrar (drain respeitado).
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import os as os_module
import signal
import socket
import threading
import time

from server.server import Server, ServerConfig
from server.router import Router
from server.limits import Limits
from server.response import Response
from server.lifecycle import ServerState


def _porta_livre():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    porta = s.getsockname()[1]
    s.close()
    return porta


def test_sigterm_triggers_graceful_shutdown_without_pending_request():
    router = Router()
    router.add_route("GET", "/x", lambda req, ctx: Response.text("ok"))

    porta = _porta_livre()
    config = ServerConfig(host="127.0.0.1", port=porta, max_workers=5, drain_timeout=3)
    servidor = Server(config, router)

    handlers_originais = (signal.getsignal(signal.SIGTERM), signal.getsignal(signal.SIGINT))
    try:
        servidor.start(block=False, handle_signals=True)
        time.sleep(0.2)
        assert servidor.lifecycle.state == ServerState.RUNNING

        os_module.kill(os_module.getpid(), signal.SIGTERM)
        time.sleep(0.3)
        assert servidor.lifecycle.state == ServerState.DRAINING

        deadline = time.monotonic() + 5
        while servidor.lifecycle.state != ServerState.STOPPED and time.monotonic() < deadline:
            time.sleep(0.1)

        assert servidor.lifecycle.state == ServerState.STOPPED

        try:
            socket.create_connection(("127.0.0.1", porta), timeout=1)
            conectou = True
        except OSError:
            conectou = False
        assert conectou is False
    finally:
        signal.signal(signal.SIGTERM, handlers_originais[0])
        signal.signal(signal.SIGINT, handlers_originais[1])


def test_sigterm_waits_for_in_flight_request_to_complete():
    liberar = threading.Event()
    resposta_entregue = threading.Event()

    def handler_lento(req, ctx):
        liberar.wait(timeout=5)
        return Response.text("terminei")

    router = Router()
    router.add_route("GET", "/lento", handler_lento)

    porta = _porta_livre()
    limites = Limits(read_timeout=10, write_timeout=10)
    config = ServerConfig(host="127.0.0.1", port=porta, max_workers=5, drain_timeout=5, limits=limites)
    servidor = Server(config, router)

    handlers_originais = (signal.getsignal(signal.SIGTERM), signal.getsignal(signal.SIGINT))
    try:
        servidor.start(block=False, handle_signals=True)
        time.sleep(0.2)

        resultado = {}

        def cliente():
            with socket.create_connection(("127.0.0.1", porta), timeout=8) as sock:
                sock.sendall(b"GET /lento HTTP/1.1\r\nConnection: close\r\n\r\n")
                sock.settimeout(8)
                resposta = b""
                try:
                    while True:
                        pedaco = sock.recv(4096)
                        if not pedaco:
                            break
                        resposta += pedaco
                except socket.timeout:
                    pass
                resultado["resposta"] = resposta
                resposta_entregue.set()

        th_cliente = threading.Thread(target=cliente)
        th_cliente.start()
        time.sleep(0.3)

        os_module.kill(os_module.getpid(), signal.SIGTERM)
        time.sleep(0.3)
        assert servidor.lifecycle.state == ServerState.DRAINING

        liberar.set()
        th_cliente.join(timeout=8)

        assert resposta_entregue.is_set(), "resposta deveria ter sido entregue mesmo apos SIGTERM"
        assert b"terminei" in resultado.get("resposta", b""), "requisicao em andamento nao foi respeitada pelo drain"

        deadline = time.monotonic() + 5
        while servidor.lifecycle.state != ServerState.STOPPED and time.monotonic() < deadline:
            time.sleep(0.1)
        assert servidor.lifecycle.state == ServerState.STOPPED
    finally:
        signal.signal(signal.SIGTERM, handlers_originais[0])
        signal.signal(signal.SIGINT, handlers_originais[1])


def test_drain_timeout_forces_shutdown_even_with_stuck_request():
    """Se uma requisicao nunca termina, o drain nao deve travar o
    processo para sempre - drain_timeout precisa forcar o avanco."""
    nunca_libera = threading.Event()

    def handler_travado(req, ctx):
        nunca_libera.wait(timeout=30)
        return Response.text("nunca deveria chegar aqui a tempo")

    router = Router()
    router.add_route("GET", "/travado", handler_travado)

    porta = _porta_livre()
    limites = Limits(read_timeout=10, write_timeout=10)
    config = ServerConfig(host="127.0.0.1", port=porta, max_workers=5, drain_timeout=1, limits=limites)
    servidor = Server(config, router)

    try:
        servidor.start(block=False, handle_signals=False)
        time.sleep(0.2)

        sock = socket.create_connection(("127.0.0.1", porta), timeout=5)
        sock.sendall(b"GET /travado HTTP/1.1\r\nConnection: close\r\n\r\n")

        time.sleep(0.3)
        inicio = time.monotonic()
        servidor.stop(wait=True)
        duracao = time.monotonic() - inicio

        assert duracao < 10, f"stop() nao deveria travar indefinidamente; levou {duracao}s"
        assert servidor.lifecycle.state == ServerState.STOPPED
    finally:
        nunca_libera.set()
        try:
            sock.close()
        except OSError:
            pass
