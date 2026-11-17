import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import hashlib
import hmac
import json
import socket
import time

from server.server import Server, ServerConfig
from server.router import Router
from deploy_platform.github_webhook import criar_handler_github_webhook, verificar_assinatura


SEGREDO = "segredo-de-teste-123"


def _assinar(corpo_bytes):
    return "sha256=" + hmac.new(SEGREDO.encode(), corpo_bytes, hashlib.sha256).hexdigest()


def _porta_livre():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    porta = s.getsockname()[1]
    s.close()
    return porta


def test_verificar_assinatura_valida():
    corpo = b'{"ref": "refs/heads/main"}'
    assinatura = _assinar(corpo)
    assert verificar_assinatura(SEGREDO, corpo, assinatura) is True


def test_verificar_assinatura_invalida():
    corpo = b'{"ref": "refs/heads/main"}'
    assert verificar_assinatura(SEGREDO, corpo, "sha256=chave_errada") is False


def test_verificar_assinatura_ausente():
    corpo = b'{"ref": "refs/heads/main"}'
    assert verificar_assinatura(SEGREDO, corpo, None) is False


def test_webhook_rejects_invalid_signature_end_to_end():
    chamado = []
    handler = criar_handler_github_webhook(SEGREDO, lambda evento: chamado.append(evento))

    router = Router()
    router.add_route("POST", "/webhooks/github", handler)
    porta = _porta_livre()
    config = ServerConfig(host="127.0.0.1", port=porta, max_workers=5)
    servidor = Server(config, router)
    servidor.start(block=False)
    time.sleep(0.2)

    try:
        corpo = json.dumps({"ref": "refs/heads/main"}).encode()
        req = (
            b"POST /webhooks/github HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"
            b"Content-Type: application/json\r\nContent-Length: " + str(len(corpo)).encode() +
            b"\r\nX-Hub-Signature-256: sha256=assinatura_errada\r\nX-GitHub-Event: push\r\n\r\n" + corpo
        )
        with socket.create_connection(("127.0.0.1", porta), timeout=3) as sock:
            sock.sendall(req)
            sock.settimeout(3)
            resposta = b""
            try:
                while True:
                    p = sock.recv(4096)
                    if not p:
                        break
                    resposta += p
            except socket.timeout:
                pass

        assert b"401" in resposta
        assert chamado == [], "deploy_callback nao deveria ter sido chamado com assinatura invalida"
    finally:
        servidor.stop()


def test_webhook_accepts_valid_push_and_calls_deploy_callback():
    chamado = []
    handler = criar_handler_github_webhook(SEGREDO, lambda evento: chamado.append(evento) or {"deployed": True})

    router = Router()
    router.add_route("POST", "/webhooks/github", handler)
    porta = _porta_livre()
    config = ServerConfig(host="127.0.0.1", port=porta, max_workers=5)
    servidor = Server(config, router)
    servidor.start(block=False)
    time.sleep(0.2)

    try:
        corpo = json.dumps({"ref": "refs/heads/main"}).encode()
        assinatura = _assinar(corpo)
        req = (
            b"POST /webhooks/github HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"
            b"Content-Type: application/json\r\nContent-Length: " + str(len(corpo)).encode() +
            b"\r\nX-Hub-Signature-256: " + assinatura.encode() +
            b"\r\nX-GitHub-Event: push\r\n\r\n" + corpo
        )
        with socket.create_connection(("127.0.0.1", porta), timeout=3) as sock:
            sock.sendall(req)
            sock.settimeout(3)
            resposta = b""
            try:
                while True:
                    p = sock.recv(4096)
                    if not p:
                        break
                    resposta += p
            except socket.timeout:
                pass

        assert b"202" in resposta
        assert len(chamado) == 1
        assert chamado[0]["event"] == "push"
    finally:
        servidor.stop()


def test_webhook_ignores_non_push_release_events():
    chamado = []
    handler = criar_handler_github_webhook(SEGREDO, lambda evento: chamado.append(evento))

    router = Router()
    router.add_route("POST", "/webhooks/github", handler)
    porta = _porta_livre()
    config = ServerConfig(host="127.0.0.1", port=porta, max_workers=5)
    servidor = Server(config, router)
    servidor.start(block=False)
    time.sleep(0.2)

    try:
        corpo = json.dumps({"action": "opened"}).encode()
        assinatura = _assinar(corpo)
        req = (
            b"POST /webhooks/github HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"
            b"Content-Type: application/json\r\nContent-Length: " + str(len(corpo)).encode() +
            b"\r\nX-Hub-Signature-256: " + assinatura.encode() +
            b"\r\nX-GitHub-Event: pull_request\r\n\r\n" + corpo
        )
        with socket.create_connection(("127.0.0.1", porta), timeout=3) as sock:
            sock.sendall(req)
            sock.settimeout(3)
            resposta = b""
            try:
                while True:
                    p = sock.recv(4096)
                    if not p:
                        break
                    resposta += p
            except socket.timeout:
                pass

        assert b"200" in resposta
        assert b"ignored" in resposta
        assert chamado == []
    finally:
        servidor.stop()
