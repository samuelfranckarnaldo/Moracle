"""
Testes de carga/concorrencia em escala: 1/10/50/100 conexoes, pool
saturado, requests lentas simultaneas, shutdown durante carga, TLS
simultaneo, e o teste mais importante - 100 POST /ingest simultaneos
end-to-end via HTTP real, verificando que o estado final em
defense.py permanece consistente (sem perda por race condition).
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import shutil
import socket
import ssl
import threading
import time

from server.server import Server, ServerConfig
from server.router import Router
from server.limits import Limits
from server.response import Response
from core.moracle_adapter import build_router
from core.moracle_middleware import auth_middleware
from core.api_key import obter_ou_criar
from core.identity import migrate_legacy_admin_key
from core import config as core_config
from core.tls_config import obter_contexto_tls
from core import defense


import pytest

pytestmark = pytest.mark.usefixtures("estado_isolado")

def _porta_livre():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    porta = s.getsockname()[1]
    s.close()
    return porta


def _http_raw(porta, requisicao, timeout=8, usar_tls=False):
    if usar_tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        base = socket.create_connection(("127.0.0.1", porta), timeout=timeout)
        sock = ctx.wrap_socket(base, server_hostname="localhost")
    else:
        sock = socket.create_connection(("127.0.0.1", porta), timeout=timeout)

    try:
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
    finally:
        sock.close()


def _get_simples(porta, path="/x", timeout=8, usar_tls=False):
    req = f"GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".encode()
    return _http_raw(porta, req, timeout=timeout, usar_tls=usar_tls)


def _subir_generico(handlers_por_path, max_workers=20, limits=None, tls=False):
    router = Router()
    for path, handler in handlers_por_path.items():
        router.add_route("GET", path, handler)

    porta = _porta_livre()
    tls_context = obter_contexto_tls() if tls else None
    config = ServerConfig(
        host="127.0.0.1", port=porta, max_workers=max_workers,
        limits=limits or Limits(read_timeout=5, write_timeout=5),
        tls_context=tls_context,
    )
    servidor = Server(config, router)
    servidor.start(block=False)
    time.sleep(0.2)
    return servidor, porta


def _disparar_n_conexoes(n, porta, path="/x", timeout=8, usar_tls=False):
    resultados = []
    lock = threading.Lock()

    def cliente():
        resposta = _get_simples(porta, path, timeout=timeout, usar_tls=usar_tls)
        with lock:
            resultados.append(resposta)

    threads = [threading.Thread(target=cliente) for _ in range(n)]
    for th in threads:
        th.start()
    for th in threads:
        th.join(timeout=timeout + 5)

    return resultados


def test_1_connection():
    servidor, porta = _subir_generico({"/x": lambda req, ctx: Response.text("ok")})
    try:
        resultados = _disparar_n_conexoes(1, porta)
        assert len(resultados) == 1
        assert b"200 OK" in resultados[0]
    finally:
        servidor.stop()


def test_10_connections_concurrent():
    servidor, porta = _subir_generico({"/x": lambda req, ctx: Response.text("ok")}, max_workers=20)
    try:
        resultados = _disparar_n_conexoes(10, porta)
        assert len(resultados) == 10
        assert all(b"200 OK" in r for r in resultados)
    finally:
        servidor.stop()


def test_50_connections_concurrent():
    servidor, porta = _subir_generico({"/x": lambda req, ctx: Response.text("ok")}, max_workers=50,
                                       limits=Limits(max_connections=100, read_timeout=5, write_timeout=5))
    try:
        resultados = _disparar_n_conexoes(50, porta)
        assert len(resultados) == 50
        sucessos = sum(1 for r in resultados if b"200 OK" in r)
        assert sucessos == 50
    finally:
        servidor.stop()


def test_100_connections_concurrent():
    servidor, porta = _subir_generico({"/x": lambda req, ctx: Response.text("ok")}, max_workers=50,
                                       limits=Limits(max_connections=150, read_timeout=8, write_timeout=8))
    try:
        resultados = _disparar_n_conexoes(100, porta, timeout=10)
        sucessos = sum(1 for r in resultados if b"200 OK" in r)
        # com max_connections=150 e 100 conexoes, todas deveriam caber
        assert sucessos == 100, f"esperado 100 sucessos, obteve {sucessos} de {len(resultados)} respostas"
    finally:
        servidor.stop()


def test_pool_saturated_some_requests_get_503():
    """100 conexoes contra max_connections=20 - algumas devem ser
    recusadas com 503, comprovando que o limite protege o servidor."""
    bloqueio = threading.Event()

    def handler_lento(req, ctx):
        bloqueio.wait(timeout=6)
        return Response.text("ok")

    servidor, porta = _subir_generico(
        {"/lento": handler_lento}, max_workers=5,
        limits=Limits(max_connections=20, read_timeout=8, write_timeout=8),
    )
    try:
        resultados = _disparar_n_conexoes(60, porta, path="/lento", timeout=10)
        recusas = sum(1 for r in resultados if b"503" in r)
        assert recusas > 0, "esperava pelo menos algumas recusas 503 sob saturacao do pool"
    finally:
        bloqueio.set()
        servidor.stop()


def test_slow_requests_simultaneous_all_complete_correctly():
    """Multiplas requests lentas simultaneas nao devem se misturar -
    cada uma recebe exatamente a resposta que lhe pertence."""
    def handler_eco(req, ctx):
        time.sleep(0.3)
        return Response.text(f"path={req.path}")

    servidor, porta = _subir_generico(
        {"/a": handler_eco, "/b": handler_eco, "/c": handler_eco},
        max_workers=10, limits=Limits(max_connections=30, read_timeout=5, write_timeout=5),
    )
    try:
        resultados = {}
        lock = threading.Lock()

        def cliente(path):
            resposta = _get_simples(porta, path, timeout=8)
            with lock:
                resultados.setdefault(path, []).append(resposta)

        threads = []
        for _ in range(5):
            for path in ["/a", "/b", "/c"]:
                threads.append(threading.Thread(target=cliente, args=(path,)))
        for th in threads:
            th.start()
        for th in threads:
            th.join(timeout=10)

        for path in ["/a", "/b", "/c"]:
            for resposta in resultados[path]:
                assert f"path={path}".encode() in resposta, f"resposta cruzada detectada para {path}"
    finally:
        servidor.stop()


def test_shutdown_during_active_load():
    """Dispara carga concorrente e chama stop() no meio - o servidor
    deve encerrar sem travar indefinidamente e sem crashar."""
    def handler(req, ctx):
        time.sleep(0.2)
        return Response.text("ok")

    servidor, porta = _subir_generico({"/x": handler}, max_workers=20,
                                       limits=Limits(max_connections=50, read_timeout=5, write_timeout=5))

    resultados = []
    lock = threading.Lock()

    def cliente():
        try:
            resposta = _get_simples(porta, timeout=5)
            with lock:
                resultados.append(resposta)
        except OSError:
            pass

    threads = [threading.Thread(target=cliente) for _ in range(20)]
    for th in threads:
        th.start()

    time.sleep(0.1)
    inicio = time.monotonic()
    servidor.stop(wait=True)
    duracao = time.monotonic() - inicio

    for th in threads:
        th.join(timeout=5)

    assert duracao < 20, f"shutdown sob carga nao deveria travar; levou {duracao}s"


def test_tls_simultaneous_connections():
    servidor, porta = _subir_generico({"/x": lambda req, ctx: Response.text("ok")}, max_workers=20, tls=True)
    try:
        resultados = _disparar_n_conexoes(10, porta, timeout=8, usar_tls=True)
        sucessos = sum(1 for r in resultados if b"200 OK" in r)
        assert sucessos == 10, f"esperado 10 conexoes TLS simultaneas bem-sucedidas, obteve {sucessos}"
    finally:
        servidor.stop()


def test_100_ingest_simultaneous_state_stays_consistent():
    """O teste mais importante desta bateria: 100 POST /ingest
    simultaneos via HTTP real (nao chamada direta em memoria),
    cada um bloqueando um IP diferente por SQLi - o estado final em
    blocklist.json precisa ter exatamente 100 entradas, provando que
    o caminho completo parser->router->middleware->adapter->defense.py
    e seguro sob concorrencia real de ponta a ponta."""
    if os.path.exists(defense.STATE_DIR):
        shutil.rmtree(defense.STATE_DIR)

    router = build_router()
    porta = _porta_livre()
    config = ServerConfig(host="127.0.0.1", port=porta, max_workers=30,
                           limits=Limits(max_connections=150, read_timeout=8, write_timeout=8))
    servidor = Server(config, router, middlewares=[auth_middleware])
    servidor.start(block=False)
    time.sleep(0.2)

    chave = obter_ou_criar()
    migrate_legacy_admin_key(os.path.join(core_config.RAIZ_PROJETO, '.state'))
    total = 100

    try:
        respostas = []
        lock = threading.Lock()

        def disparar_ingest(indice):
            payload = {
                "ip": f"198.51.{indice // 256}.{indice % 256}",
                "method": "GET",
                "path": "/product?id=1 UNION SELECT NULL--",
                "user_agent": "curl/8.0",
                "status_code": 200,
            }
            corpo = json.dumps(payload).encode()
            requisicao = (
                b"POST /ingest HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"
                b"Content-Type: application/json\r\nContent-Length: " + str(len(corpo)).encode() +
                b"\r\nAuthorization: Bearer " + chave.encode() + b"\r\n\r\n" + corpo
            )
            resposta = _http_raw(porta, requisicao, timeout=15)
            with lock:
                respostas.append(resposta)

        threads = [threading.Thread(target=disparar_ingest, args=(i,)) for i in range(total)]
        for th in threads:
            th.start()
        for th in threads:
            th.join(timeout=20)

        sucessos_http = sum(1 for r in respostas if b"200 OK" in r)
        assert sucessos_http == total, f"esperado {total} respostas 200, obteve {sucessos_http}"

        blocklist = defense.carregar_blocklist()
        assert len(blocklist) == total, (
            f"estado inconsistente: esperado {total} IPs na blocklist apos "
            f"{total} /ingest simultaneos via HTTP real, obteve {len(blocklist)}"
        )
    finally:
        servidor.stop()
        if os.path.exists(defense.STATE_DIR):
            shutil.rmtree(defense.STATE_DIR)
