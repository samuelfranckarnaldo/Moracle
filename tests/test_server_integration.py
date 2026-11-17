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


def _subir_servidor(router, middlewares=None, limits=None, max_workers=5):
    porta = _porta_livre()
    config = ServerConfig(
        host="127.0.0.1", port=porta, max_workers=max_workers,
        limits=limits or Limits(read_timeout=2, write_timeout=2),
    )
    servidor = Server(config, router, middlewares or [])
    servidor.start(block=False)
    time.sleep(0.2)
    return servidor, porta


def _requisicao_crua(porta, dados, timeout=3):
    with socket.create_connection(("127.0.0.1", porta), timeout=timeout) as sock:
        sock.sendall(dados)
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


def test_basic_get_request():
    router = Router()
    router.add_route("GET", "/health", lambda req, ctx: Response.json({"status": "ok"}))
    servidor, porta = _subir_servidor(router)
    try:
        resposta = _requisicao_crua(porta, b"GET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        assert b"200 OK" in resposta
        assert b'"status": "ok"' in resposta
    finally:
        servidor.stop()


def test_404_for_unknown_route():
    router = Router()
    router.add_route("GET", "/health", lambda req, ctx: Response.text("ok"))
    servidor, porta = _subir_servidor(router)
    try:
        resposta = _requisicao_crua(porta, b"GET /nao-existe HTTP/1.1\r\nConnection: close\r\n\r\n")
        assert b"404" in resposta
    finally:
        servidor.stop()


def test_405_for_wrong_method():
    router = Router()
    router.add_route("GET", "/health", lambda req, ctx: Response.text("ok"))
    servidor, porta = _subir_servidor(router)
    try:
        resposta = _requisicao_crua(porta, b"POST /health HTTP/1.1\r\nConnection: close\r\n\r\n")
        assert b"405" in resposta
        assert b"Allow:" in resposta
    finally:
        servidor.stop()


def test_route_parameters():
    capturado = {}

    def handler(req, ctx):
        capturado["ip"] = ctx.route_params.get("ip")
        return Response.text("ok")

    router = Router()
    router.add_route("POST", "/block/{ip}", handler)
    servidor, porta = _subir_servidor(router)
    try:
        _requisicao_crua(porta, b"POST /block/203.0.113.5 HTTP/1.1\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
        assert capturado["ip"] == "203.0.113.5"
    finally:
        servidor.stop()


def test_application_adapter_and_response_serialization():
    router = Router()
    router.add_route("GET", "/echo", lambda req, ctx: Response.json({"path": req.path}))
    servidor, porta = _subir_servidor(router)
    try:
        resposta = _requisicao_crua(porta, b"GET /echo HTTP/1.1\r\nConnection: close\r\n\r\n")
        assert b'"path": "/echo"' in resposta
    finally:
        servidor.stop()


def test_middleware_runs_before_handler():
    ordem = []

    def mw(req, ctx, nxt):
        ordem.append("middleware")
        return nxt(req, ctx)

    def handler(req, ctx):
        ordem.append("handler")
        return Response.text("ok")

    router = Router()
    router.add_route("GET", "/x", handler)
    servidor, porta = _subir_servidor(router, middlewares=[mw])
    try:
        _requisicao_crua(porta, b"GET /x HTTP/1.1\r\nConnection: close\r\n\r\n")
        assert ordem == ["middleware", "handler"]
    finally:
        servidor.stop()


def test_connection_timeout_returns_408():
    router = Router()
    router.add_route("GET", "/x", lambda req, ctx: Response.text("ok"))
    limites = Limits(read_timeout=0.5, write_timeout=2)
    servidor, porta = _subir_servidor(router, limits=limites)
    try:
        with socket.create_connection(("127.0.0.1", porta), timeout=3) as sock:
            sock.settimeout(3)
            resposta = b""
            try:
                while True:
                    pedaco = sock.recv(4096)
                    if not pedaco:
                        break
                    resposta += pedaco
            except socket.timeout:
                pass
            assert b"408" in resposta
    finally:
        servidor.stop()


def test_thread_pool_limit_returns_503_when_exhausted():
    bloqueio = threading.Event()

    def handler_lento(req, ctx):
        bloqueio.wait(timeout=5)
        return Response.text("ok")

    router = Router()
    router.add_route("GET", "/lento", handler_lento)
    # max_connections explicito - antes a fila usava max_workers*4 como
    # numero magico; agora e Limits.max_connections (default 200), entao
    # este teste precisa fixar um limite baixo para continuar exercitando
    # o cenario de esgotamento.
    limites = Limits(max_connections=4, read_timeout=2, write_timeout=2)
    servidor, porta = _subir_servidor(router, max_workers=1, limits=limites)
    conexoes = []
    try:
        for _ in range(6):
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
            except socket.timeout:
                pass
            if b"503" in resposta:
                recusas += 1
        assert recusas >= 1
    finally:
        bloqueio.set()
        for sock in conexoes:
            try:
                sock.close()
            except OSError:
                pass
        servidor.stop()


def test_multiple_concurrent_requests():
    router = Router()
    router.add_route("GET", "/x", lambda req, ctx: Response.text("ok"))
    servidor, porta = _subir_servidor(router, max_workers=10)
    resultados = []
    lock = threading.Lock()

    def cliente():
        resposta = _requisicao_crua(porta, b"GET /x HTTP/1.1\r\nConnection: close\r\n\r\n")
        with lock:
            resultados.append(b"200 OK" in resposta)

    threads = [threading.Thread(target=cliente) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    try:
        assert all(resultados)
        assert len(resultados) == 10
    finally:
        servidor.stop()


def test_graceful_shutdown_stops_accepting():
    router = Router()
    router.add_route("GET", "/x", lambda req, ctx: Response.text("ok"))
    servidor, porta = _subir_servidor(router)
    servidor.stop()
    time.sleep(1.5)
    try:
        socket.create_connection(("127.0.0.1", porta), timeout=1)
        conectou = True
    except OSError:
        conectou = False
    assert conectou is False
