"""
Composition Root - instancia Listener, Connection, Parser, Router,
Middleware pipeline e Application Adapter, aplicando ServerConfig.
Nao processa logica de negocio do Moracle.
"""
import signal
import socket
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional, List

from server.errors import MoracleServerError, ConnectionClosedError, ConnectionTimeoutError, ConfigurationError
from server.limits import Limits
from server.connection import Connection
from server.http_parser import parse_request
from server.request import Context
from server.response import Response, serialize_response
from server.router import Router
from server.middleware import compose
from server.threadpool import LimitedThreadPool
from server.lifecycle import Lifecycle, ServerState, LifecycleError
from server.listener import Listener
from server.access_log import AccessLogger, AccessLogRecord


@dataclass
class ServerConfig:
    host: str = "127.0.0.1"
    port: int = 7000
    max_workers: int = 20
    backlog: int = 128
    limits: Limits = field(default_factory=Limits)
    tls_context: Optional[object] = None
    drain_timeout: float = 10.0
    keep_alive: bool = False  # documentado: nao implementado nesta fase,
                               # existe como campo explicito para deixar
                               # a decisao visivel na config, nao escondida

    def validate(self):
        """Validacao formal, chamada antes do bind. Falha cedo e com
        mensagem clara em vez de deixar um valor invalido causar erro
        obscuro so quando o socket ja estiver aberto."""
        erros = []

        if not self.host or not isinstance(self.host, str):
            erros.append("host deve ser uma string nao vazia")

        if not isinstance(self.port, int) or not (1 <= self.port <= 65535):
            erros.append(f"port deve ser um inteiro entre 1 e 65535, recebeu {self.port!r}")

        if not isinstance(self.max_workers, int) or self.max_workers < 1:
            erros.append(f"max_workers deve ser >= 1, recebeu {self.max_workers!r}")

        if not isinstance(self.backlog, int) or self.backlog < 1:
            erros.append(f"backlog deve ser >= 1, recebeu {self.backlog!r}")

        if not isinstance(self.drain_timeout, (int, float)) or self.drain_timeout < 0:
            erros.append(f"drain_timeout deve ser >= 0, recebeu {self.drain_timeout!r}")

        if self.keep_alive:
            erros.append("keep_alive=True nao e suportado nesta fase (decisao arquitetural explicita)")

        for nome_campo in ("max_request_line", "max_header_size", "max_headers_count",
                            "max_body_size", "max_connections"):
            valor = getattr(self.limits, nome_campo, None)
            if not isinstance(valor, int) or valor < 1:
                erros.append(f"limits.{nome_campo} deve ser um inteiro >= 1, recebeu {valor!r}")

        for nome_campo in ("read_timeout", "write_timeout", "request_timeout"):
            valor = getattr(self.limits, nome_campo, None)
            if not isinstance(valor, (int, float)) or valor <= 0:
                erros.append(f"limits.{nome_campo} deve ser um numero > 0, recebeu {valor!r}")

        if self.tls_context is not None:
            import ssl
            if not isinstance(self.tls_context, ssl.SSLContext):
                erros.append(f"tls_context deve ser ssl.SSLContext ou None, recebeu {type(self.tls_context)!r}")

        return erros


class Server:
    def __init__(self, config, router, middlewares=None, access_logger=None):
        self.config = config
        self.router = router
        self.middlewares = middlewares or []
        self.lifecycle = Lifecycle()

        # Validacao acontece ANTES de montar qualquer recurso (thread
        # pool, listener) - com config invalida (ex: max_workers=0),
        # nem o ThreadPoolExecutor da stdlib consegue ser construido,
        # entao precisa falhar aqui, nao em start().
        erros_config = self.config.validate()
        if erros_config:
            mensagem = "invalid ServerConfig:\n  - " + "\n  - ".join(erros_config)
            raise ConfigurationError(mensagem)

        self.pool = LimitedThreadPool(config.max_workers, max_queue=config.limits.max_connections)
        self.listener = Listener(config.host, config.port, config.backlog, config.tls_context)
        self.access_logger = access_logger or AccessLogger()
        self._stop_event = threading.Event()
        self._accept_thread = None
        self._active_count = 0
        self._active_lock = threading.Lock()

    def start(self, block=True, handle_signals=False):
        self.lifecycle.transition(ServerState.CONFIGURED)
        self.lifecycle.transition(ServerState.BINDING)
        try:
            self.listener.bind_and_listen()
        except OSError as e:
            self.lifecycle.transition(ServerState.FAILED)
            raise ConfigurationError(f"failed to bind {self.config.host}:{self.config.port}: {e}")

        self.listener.settimeout(1.0)
        self.lifecycle.transition(ServerState.RUNNING)

        if handle_signals:
            self._register_signal_handlers()

        if block:
            self._accept_loop()
        else:
            self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
            self._accept_thread.start()

    def _register_signal_handlers(self):
        """So funciona quando chamado a partir da thread principal do
        processo (limitacao do modulo signal do Python). Se registrado
        de outra thread, ignora silenciosamente - documentado como
        limitacao conhecida, nao falha o startup por causa disso."""
        def _handler(signum, frame):
            self.stop(wait=False)
        try:
            signal.signal(signal.SIGTERM, _handler)
            signal.signal(signal.SIGINT, _handler)
        except (ValueError, OSError):
            pass

    def _accept_loop(self):
        while not self._stop_event.is_set():
            try:
                client_sock, addr = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            aceito = self.pool.try_submit(self._handle_connection, client_sock, addr)
            if not aceito:
                self._rejeitar_conexao(client_sock)

        drenou_a_tempo = self._wait_for_active_connections(self.config.drain_timeout)
        self.lifecycle.transition(ServerState.STOPPING)
        # Se drenou a tempo, espera o pool esvaziar normalmente (nada
        # deveria estar rodando). Se o drain estourou o timeout (ha
        # requisicao presa), NAO bloqueia esperando ela terminar -
        # forca o avanco do lifecycle mesmo com threads presas em
        # segundo plano, conforme o drain_timeout promete.
        self.pool.shutdown(wait=drenou_a_tempo)
        self.listener.close()
        self.lifecycle.transition(ServerState.STOPPED)

    def _wait_for_active_connections(self, timeout):
        """Retorna True se todas as conexoes ativas terminaram dentro
        do timeout; False se o timeout estourou com conexoes ainda
        em andamento (drain forcado)."""
        inicio = time.monotonic()
        while True:
            with self._active_lock:
                if self._active_count <= 0:
                    return True
            if time.monotonic() - inicio > timeout:
                return False
            time.sleep(0.05)

    def _active_increment(self):
        with self._active_lock:
            self._active_count += 1

    def _active_decrement(self):
        with self._active_lock:
            self._active_count -= 1

    def _rejeitar_conexao(self, client_sock):
        """Envia 503 e fecha sem gerar RST: precisa drenar o que o
        cliente ja enviou antes de close(), senao o kernel manda RST
        em vez de FIN por haver dados nao lidos no buffer."""
        try:
            client_sock.settimeout(0.5)
            try:
                client_sock.recv(65536)
            except OSError:
                pass
            client_sock.sendall(
                b"HTTP/1.1 503 Service Unavailable\r\n"
                b"Content-Length: 0\r\nConnection: close\r\n\r\n"
            )
        except OSError:
            pass
        finally:
            try:
                client_sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            client_sock.close()

    def _handle_connection(self, client_sock, addr):
        self._active_increment()
        try:
            self._handle_connection_inner(client_sock, addr)
        finally:
            self._active_decrement()

    def _handle_connection_inner(self, client_sock, addr):
        limits = self.config.limits
        conexao = Connection(client_sock, addr, limits)
        conexao.set_timeout(limits.read_timeout)

        request_id = uuid.uuid4().hex
        inicio = time.monotonic()
        request = None
        context = None

        try:
            request = parse_request(conexao, limits)
            context = Context(request_id=request_id)
            response = self._dispatch(request, context)
        except ConnectionClosedError:
            conexao.close()
            return
        except ConnectionTimeoutError:
            response = Response.text("Request Timeout", status=408)
        except MoracleServerError as erro:
            status = getattr(erro, "status_code", 500) or 500
            response = Response.text(erro.message or erro.__class__.__name__, status=status)
        except Exception as erro:
            response = Response.text(f"Internal Server Error: {erro}", status=500)

        protocolo = request.protocol_version if request else "HTTP/1.1"
        bytes_enviados = 0
        try:
            conexao.set_timeout(limits.write_timeout)
            for pedaco in serialize_response(response, protocolo):
                conexao.sendall(pedaco)
                bytes_enviados += len(pedaco)
        except (OSError, ConnectionTimeoutError):
            pass

        latencia_ms = (time.monotonic() - inicio) * 1000
        self.access_logger.log(AccessLogRecord(
            request_id=request_id,
            remote_address=str(addr[0]) if addr else "unknown",
            method=request.method if request else "-",
            path=request.path if request else "-",
            protocol_version=protocolo,
            status=response.status,
            bytes_sent=bytes_enviados,
            latency_ms=latencia_ms,
            app_name=context.get("app_name", "") if context else "",
        ))
        conexao.close()

    def _dispatch(self, request, context):
        """A pipeline de middleware envolve TODO o processo de
        roteamento (incluindo 404/405/OPTIONS), nao so o handler final
        de uma rota que existe. Isso e' proposital: rate limit e auth
        precisam se aplicar mesmo a requisicoes para rotas inexistentes
        - senao um atacante evita o rate limit so batendo em paths que
        nao existem, e nunca leva 429."""
        def resolver_e_executar(req, ctx):
            from server.errors import NotFoundError, MethodNotAllowedError

            if req.method == "OPTIONS":
                permitidos = self.router.allowed_methods(req.path)
                return Response(status=204, headers={"Allow": ", ".join(sorted(permitidos))})

            try:
                handler, params = self.router.match(req.method, req.path)
            except MethodNotAllowedError as erro:
                return Response.text(
                    "Method Not Allowed", status=405,
                    headers={"Allow": ", ".join(sorted(erro.allowed_methods))},
                )
            except NotFoundError:
                return Response.text("Not Found", status=404)

            ctx.route_params = params
            return handler(req, ctx)

        pipeline = compose(self.middlewares, resolver_e_executar)

        try:
            response = pipeline(request, context)
        except Exception as erro:
            return Response.text(f"Internal Server Error: {erro}", status=500)

        if request.method == "HEAD" and not response.is_streaming:
            response = Response(status=response.status, headers=dict(response.headers), body=b"")

        return response

    def stop(self, wait=True):
        try:
            self.lifecycle.transition(ServerState.DRAINING)
        except LifecycleError:
            pass
        self._stop_event.set()
        if wait and self._accept_thread is not None:
            self._accept_thread.join(timeout=self.config.drain_timeout + 5)
