"""
Confirma que access log, application log e security audit sao tres
destinos fisicamente separados - nao misturados num unico arquivo.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import socket
import time
import shutil

from server.server import Server, ServerConfig
from core.moracle_adapter import build_router
from core.moracle_middleware import auth_middleware
from core.api_key import obter_ou_criar
from core.identity import migrate_legacy_admin_key
from core import config as core_config
from core import logging_setup
from core.logging_setup import configurar_logging, resetar_para_teste
from core import defense


import pytest

pytestmark = pytest.mark.usefixtures("estado_isolado")

def _porta_livre():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    porta = s.getsockname()[1]
    s.close()
    return porta


def _http(porta, metodo, path, headers=None, timeout=3):
    headers = headers or {}
    linhas = [f"{metodo} {path} HTTP/1.1", "Host: x", "Connection: close"]
    for nome, valor in headers.items():
        linhas.append(f"{nome}: {valor}")
    requisicao = ("\r\n".join(linhas) + "\r\n\r\n").encode()
    with socket.create_connection(("127.0.0.1", porta), timeout=timeout) as sock:
        sock.sendall(requisicao)
        sock.settimeout(timeout)
        try:
            while sock.recv(4096):
                pass
        except socket.timeout:
            pass


def test_access_and_security_logs_are_separate_files():
    if os.path.exists(logging_setup.LOG_DIR):
        shutil.rmtree(logging_setup.LOG_DIR)
    if os.path.exists(defense.STATE_DIR):
        shutil.rmtree(defense.STATE_DIR)

    resetar_para_teste()
    configurar_logging()

    router = build_router()
    porta = _porta_livre()
    config = ServerConfig(host="127.0.0.1", port=porta, max_workers=5)
    servidor = Server(config, router, middlewares=[auth_middleware])
    servidor.start(block=False)
    time.sleep(0.2)

    try:
        chave = obter_ou_criar()
        migrate_legacy_admin_key(os.path.join(core_config.RAIZ_PROJETO, '.state'))
        _http(porta, "GET", "/status", headers={"Authorization": f"Bearer {chave}"})

        defense.registrar_alerta("203.0.113.9", "SQL Injection", "evento de seguranca de teste")
    finally:
        servidor.stop()

    caminho_access = os.path.join(logging_setup.LOG_DIR, "access.log")
    caminho_security = defense.ALERTS_FILE

    assert os.path.exists(caminho_access), "access.log deveria existir"
    assert os.path.exists(caminho_security), "alerts.log (security audit) deveria existir"
    assert caminho_access != caminho_security, "access e security nao podem ser o mesmo arquivo"

    with open(caminho_access) as f:
        conteudo_access = f.read()
    with open(caminho_security) as f:
        conteudo_security = f.read()

    assert "/status" in conteudo_access
    assert "evento de seguranca de teste" not in conteudo_access, "evento de seguranca vazou para o access log"

    assert "evento de seguranca de teste" in conteudo_security
    assert "/status" not in conteudo_security, "requisicao HTTP vazou para o security audit log"


def test_access_log_contains_required_fields():
    if os.path.exists(logging_setup.LOG_DIR):
        shutil.rmtree(logging_setup.LOG_DIR)
    resetar_para_teste()
    configurar_logging()

    router = build_router()
    porta = _porta_livre()
    config = ServerConfig(host="127.0.0.1", port=porta, max_workers=5)
    servidor = Server(config, router)
    servidor.start(block=False)
    time.sleep(0.2)

    try:
        _http(porta, "GET", "/health")
    finally:
        servidor.stop()

    with open(os.path.join(logging_setup.LOG_DIR, "access.log")) as f:
        linha = f.read()

    assert "GET" in linha
    assert "/health" in linha
    assert "200" in linha
    assert "rid=" in linha  # request_id presente
