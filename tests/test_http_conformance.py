"""
Bateria de conformidade HTTP - cobre os itens da lista de correctness
que ainda nao tinham teste dedicado: duplicate headers, query strings,
percent-encoding, HTTP/1.0, 413/431 como resposta HTTP real (nao so
excecao no parser), 500 de aplicacao, HEAD sem corpo, OPTIONS.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import socket
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


def _subir(router, limits=None, max_workers=5):
    porta = _porta_livre()
    config = ServerConfig(
        host="127.0.0.1", port=porta, max_workers=max_workers,
        limits=limits or Limits(read_timeout=2, write_timeout=2),
    )
    servidor = Server(config, router)
    servidor.start(block=False)
    time.sleep(0.2)
    return servidor, porta


def _raw(porta, dados, timeout=3):
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


def test_query_string_parsed_correctly():
    capturado = {}

    def handler(req, ctx):
        capturado["query"] = req.query
        return Response.text("ok")

    router = Router()
    router.add_route("GET", "/x", handler)
    servidor, porta = _subir(router)
    try:
        _raw(porta, b"GET /x?a=1&b=hello HTTP/1.1\r\nConnection: close\r\n\r\n")
        assert capturado["query"] == {"a": "1", "b": "hello"}
    finally:
        servidor.stop()


def test_percent_encoding_decoded_in_query():
    capturado = {}

    def handler(req, ctx):
        capturado["query"] = req.query
        return Response.text("ok")

    router = Router()
    router.add_route("GET", "/x", handler)
    servidor, porta = _subir(router)
    try:
        _raw(porta, b"GET /x?q=ola%20mundo HTTP/1.1\r\nConnection: close\r\n\r\n")
        assert capturado["query"]["q"] == "ola mundo"
    finally:
        servidor.stop()


def test_duplicate_headers_last_value_wins():
    """Comportamento documentado: o parser usa dict simples, entao
    entre headers duplicados o ultimo sobrescreve o anterior. Isso e
    uma decisao explicita, nao um bug - registrado aqui como contrato."""
    capturado = {}

    def handler(req, ctx):
        capturado["valor"] = req.header("x-custom")
        return Response.text("ok")

    router = Router()
    router.add_route("GET", "/x", handler)
    servidor, porta = _subir(router)
    try:
        _raw(porta, b"GET /x HTTP/1.1\r\nX-Custom: primeiro\r\nX-Custom: segundo\r\nConnection: close\r\n\r\n")
        assert capturado["valor"] == "segundo"
    finally:
        servidor.stop()


def test_http_1_0_request_accepted():
    router = Router()
    router.add_route("GET", "/x", lambda req, ctx: Response.text("ok"))
    servidor, porta = _subir(router)
    try:
        resposta = _raw(porta, b"GET /x HTTP/1.0\r\n\r\n")
        assert b"200" in resposta
        assert b"HTTP/1.0" in resposta
    finally:
        servidor.stop()


def test_connection_close_header_present_or_connection_ends():
    router = Router()
    router.add_route("GET", "/x", lambda req, ctx: Response.text("ok"))
    servidor, porta = _subir(router)
    try:
        resposta = _raw(porta, b"GET /x HTTP/1.1\r\nConnection: close\r\n\r\n")
        assert b"200" in resposta
    finally:
        servidor.stop()


def test_413_returned_as_real_http_response_not_just_exception():
    router = Router()
    router.add_route("POST", "/x", lambda req, ctx: Response.text("ok"))
    limites = Limits(max_body_size=10, read_timeout=2, write_timeout=2)
    servidor, porta = _subir(router, limits=limites)
    try:
        corpo = b"x" * 100
        requisicao = (
            b"POST /x HTTP/1.1\r\nContent-Length: " + str(len(corpo)).encode() +
            b"\r\nConnection: close\r\n\r\n" + corpo
        )
        resposta = _raw(porta, requisicao)
        assert b"413" in resposta
    finally:
        servidor.stop()


def test_431_returned_as_real_http_response():
    router = Router()
    router.add_route("GET", "/x", lambda req, ctx: Response.text("ok"))
    limites = Limits(max_header_size=50, read_timeout=2, write_timeout=2)
    servidor, porta = _subir(router, limits=limites)
    try:
        header_grande = "X-Big: " + ("a" * 500)
        requisicao = f"GET /x HTTP/1.1\r\n{header_grande}\r\nConnection: close\r\n\r\n".encode()
        resposta = _raw(porta, requisicao)
        assert b"431" in resposta
    finally:
        servidor.stop()


def test_500_on_unhandled_application_exception():
    def handler_quebrado(req, ctx):
        raise ValueError("erro proposital de aplicacao")

    router = Router()
    router.add_route("GET", "/quebra", handler_quebrado)
    servidor, porta = _subir(router)
    try:
        resposta = _raw(porta, b"GET /quebra HTTP/1.1\r\nConnection: close\r\n\r\n")
        assert b"500" in resposta
    finally:
        servidor.stop()


def test_head_request_has_no_body():
    router = Router()
    router.add_route("GET", "/x", lambda req, ctx: Response.text("conteudo que nao deveria vir"))
    servidor, porta = _subir(router)
    try:
        resposta = _raw(porta, b"HEAD /x HTTP/1.1\r\nConnection: close\r\n\r\n")
        assert b"200" in resposta
        assert b"conteudo que nao deveria vir" not in resposta
    finally:
        servidor.stop()


def test_options_returns_allow_header():
    router = Router()
    router.add_route("GET", "/x", lambda req, ctx: Response.text("ok"))
    router.add_route("POST", "/x", lambda req, ctx: Response.text("ok"))
    servidor, porta = _subir(router)
    try:
        resposta = _raw(porta, b"OPTIONS /x HTTP/1.1\r\nConnection: close\r\n\r\n")
        assert b"204" in resposta
        assert b"Allow:" in resposta
        assert b"GET" in resposta and b"POST" in resposta
    finally:
        servidor.stop()
