"""
Teste de integracao ponta-a-ponta: HostRouter -> host_dispatch_middleware
-> Context -> AccessLogRecord.app_name.

Sinaliza uma lacuna pre-existente: criar_host_dispatch_middleware nao e
instanciado em nenhum bootstrap real do projeto hoje (nenhum Server em
producao troca self.router por context["resolved_router"]). Este teste
prova que o MECANISMO funciona quando o middleware e conectado
explicitamente - nao prova que ele esta conectado em producao, porque
nao esta. Ver debito tecnico registrado.
"""
import os
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server.server import Server, ServerConfig
from server.router import Router
from server.response import Response
from server.access_log import AccessLogger
from deploy_platform.host_router import HostRouter
from deploy_platform.host_dispatch_middleware import criar_host_dispatch_middleware


def _porta_livre():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _http_get(porta, path, host_header):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(2)
        s.connect(("127.0.0.1", porta))
        requisicao = f"GET {path} HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\n\r\n"
        s.sendall(requisicao.encode())
        resposta = b""
        try:
            while True:
                pedaco = s.recv(4096)
                if not pedaco:
                    break
                resposta += pedaco
        except socket.timeout:
            pass
        return resposta


def test_app_name_chega_correto_no_access_log_por_dominio():
    """Dominio A -> app_a, dominio B -> app_b: cada requisicao deve
    gerar um AccessLogRecord com o app_name correspondente, sem
    vazamento entre os dois."""
    router_generico = Router()
    router_generico.add_route("GET", "/ping", lambda req, ctx: Response.text("pong"))

    host_router = HostRouter()
    host_router.registrar_dominio("a.local", router_generico, "app_a")
    host_router.registrar_dominio("b.local", router_generico, "app_b")

    registros = []
    access_logger = AccessLogger(sink=registros.append)

    middleware = criar_host_dispatch_middleware(host_router)

    porta = _porta_livre()
    config = ServerConfig(host="127.0.0.1", port=porta, max_workers=5)
    servidor = Server(config, router_generico, middlewares=[middleware], access_logger=access_logger)
    servidor.start(block=False)
    time.sleep(0.2)

    try:
        _http_get(porta, "/ping", "a.local")
        _http_get(porta, "/ping", "b.local")
    finally:
        servidor.stop()

    assert len(registros) == 2
    app_names = {r.app_name for r in registros}
    assert app_names == {"app_a", "app_b"}


def test_dominio_nao_registrado_sem_padrao_nao_inventa_app_name():
    """Requisicao para dominio desconhecido, sem router padrao
    configurado: middleware retorna 404 antes do handler, e nenhum
    AccessLogRecord com app_name incorreto deve ser gerado para uma
    app que nao existe."""
    router_generico = Router()
    router_generico.add_route("GET", "/ping", lambda req, ctx: Response.text("pong"))

    host_router = HostRouter()
    host_router.registrar_dominio("a.local", router_generico, "app_a")
    # nenhum padrao definido - dominio desconhecido deve cair em 404

    registros = []
    access_logger = AccessLogger(sink=registros.append)
    middleware = criar_host_dispatch_middleware(host_router)

    porta = _porta_livre()
    config = ServerConfig(host="127.0.0.1", port=porta, max_workers=5)
    servidor = Server(config, router_generico, middlewares=[middleware], access_logger=access_logger)
    servidor.start(block=False)
    time.sleep(0.2)

    try:
        resposta = _http_get(porta, "/ping", "desconhecido.local")
    finally:
        servidor.stop()

    assert b"404" in resposta
    assert len(registros) == 1
    assert registros[0].app_name == ""  # nao ha context["app_name"] - middleware barrou antes
