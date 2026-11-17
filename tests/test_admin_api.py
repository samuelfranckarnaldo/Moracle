import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import shutil
import socket
import time

from server.server import Server, ServerConfig
from core.moracle_adapter import build_router
from core.moracle_middleware import auth_middleware
from core.api_key import obter_ou_criar
from core.identity import migrate_legacy_admin_key
from core import config
from admin_api.router import registrar_rotas_admin
from admin_api.handlers import get_manager
from deploy_platform import registry

MINI_APP = os.path.join(os.path.dirname(__file__), "helpers", "mini_app.py")
TMPDIR = "/data/data/com.termux/files/home/moracle_test_tmp"


import pytest

pytestmark = pytest.mark.usefixtures("estado_isolado")

def _porta_livre():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    porta = s.getsockname()[1]
    s.close()
    return porta


def _limpar():
    if os.path.exists(registry.PLATFORM_DIR):
        shutil.rmtree(registry.PLATFORM_DIR)


def _subir():
    obter_ou_criar()
    migrate_legacy_admin_key(os.path.join(config.RAIZ_PROJETO, '.state'))
    router = build_router()
    registrar_rotas_admin(router)
    porta = _porta_livre()
    config_srv = ServerConfig(host="127.0.0.1", port=porta, max_workers=10)
    servidor = Server(config_srv, router, middlewares=[auth_middleware])
    servidor.start(block=False)
    time.sleep(0.2)
    return servidor, porta


def _http(porta, metodo, path, corpo=None, headers=None, timeout=8):
    headers = dict(headers or {})
    corpo_bytes = json.dumps(corpo).encode() if corpo is not None else b""
    linhas = [f"{metodo} {path} HTTP/1.1", "Host: x", "Connection: close"]
    if corpo is not None:
        linhas.append(f"Content-Length: {len(corpo_bytes)}")
        linhas.append("Content-Type: application/json")
    for nome, valor in headers.items():
        linhas.append(f"{nome}: {valor}")
    requisicao = ("\r\n".join(linhas) + "\r\n\r\n").encode() + corpo_bytes

    with socket.create_connection(("127.0.0.1", porta), timeout=timeout) as sock:
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


def _status_e_corpo(resposta):
    linhas = resposta.split(b"\r\n\r\n", 1)
    status = int(linhas[0].split(b" ")[1])
    corpo = json.loads(linhas[1]) if len(linhas) > 1 and linhas[1] else {}
    return status, corpo


def test_admin_routes_require_auth():
    _limpar()
    servidor, porta = _subir()
    try:
        resposta = _http(porta, "GET", "/admin/apps")
        status, _ = _status_e_corpo(resposta)
        assert status == 401
    finally:
        servidor.stop()
        _limpar()


def test_create_app_success():
    _limpar()
    servidor, porta = _subir()
    chave = obter_ou_criar()
    try:
        porta_app = _porta_livre()
        resposta = _http(porta, "POST", "/admin/apps", corpo={
            "name": "app-criada", "working_directory": TMPDIR,
            "start_command": [sys.executable, MINI_APP, str(porta_app)],
            "port": porta_app,
        }, headers={"Authorization": f"Bearer {chave}"})

        status, corpo = _status_e_corpo(resposta)
        assert status == 201
        assert corpo["name"] == "app-criada"
    finally:
        servidor.stop()
        _limpar()


def test_create_app_duplicate_returns_409():
    _limpar()
    servidor, porta = _subir()
    chave = obter_ou_criar()
    try:
        payload = {"name": "app-dup", "working_directory": TMPDIR, "start_command": ["true"]}
        _http(porta, "POST", "/admin/apps", corpo=payload, headers={"Authorization": f"Bearer {chave}"})
        resposta = _http(porta, "POST", "/admin/apps", corpo=payload, headers={"Authorization": f"Bearer {chave}"})
        status, _ = _status_e_corpo(resposta)
        assert status == 409
    finally:
        servidor.stop()
        _limpar()


def test_create_app_missing_fields_returns_400():
    _limpar()
    servidor, porta = _subir()
    chave = obter_ou_criar()
    try:
        resposta = _http(porta, "POST", "/admin/apps", corpo={"name": "sem-comando"}, headers={"Authorization": f"Bearer {chave}"})
        status, _ = _status_e_corpo(resposta)
        assert status == 400
    finally:
        servidor.stop()
        _limpar()


def test_get_app_omits_environment_by_default():
    _limpar()
    servidor, porta = _subir()
    chave = obter_ou_criar()
    try:
        _http(porta, "POST", "/admin/apps", corpo={
            "name": "app-env", "working_directory": TMPDIR, "start_command": ["true"],
            "environment": {"SECRET": "nao-deveria-vazar"},
        }, headers={"Authorization": f"Bearer {chave}"})

        resposta = _http(porta, "GET", "/admin/apps/app-env", headers={"Authorization": f"Bearer {chave}"})
        status, corpo = _status_e_corpo(resposta)
        assert status == 200
        assert "environment" not in corpo

        resposta2 = _http(porta, "GET", "/admin/apps/app-env?include_env=true", headers={"Authorization": f"Bearer {chave}"})
        _, corpo2 = _status_e_corpo(resposta2)
        assert corpo2["environment"]["SECRET"] == "nao-deveria-vazar"
    finally:
        servidor.stop()
        _limpar()


def test_get_app_not_found_returns_404():
    _limpar()
    servidor, porta = _subir()
    chave = obter_ou_criar()
    try:
        resposta = _http(porta, "GET", "/admin/apps/nao-existe", headers={"Authorization": f"Bearer {chave}"})
        status, _ = _status_e_corpo(resposta)
        assert status == 404
    finally:
        servidor.stop()
        _limpar()


def test_full_deploy_status_logs_flow():
    _limpar()
    servidor, porta = _subir()
    chave = obter_ou_criar()
    try:
        porta_app = _porta_livre()
        _http(porta, "POST", "/admin/apps", corpo={
            "name": "app-fluxo", "working_directory": TMPDIR,
            "start_command": [sys.executable, MINI_APP, str(porta_app)], "port": porta_app,
        }, headers={"Authorization": f"Bearer {chave}"})

        resp_deploy = _http(porta, "POST", "/admin/apps/app-fluxo/deploy", headers={"Authorization": f"Bearer {chave}"})
        status, corpo = _status_e_corpo(resp_deploy)
        assert status == 200
        assert corpo["status"] == "active"

        resp_status = _http(porta, "GET", "/admin/apps/app-fluxo/status", headers={"Authorization": f"Bearer {chave}"})
        status2, corpo2 = _status_e_corpo(resp_status)
        assert status2 == 200
        assert corpo2["pid"] is not None

        resp_logs = _http(porta, "GET", "/admin/apps/app-fluxo/logs?lines=50", headers={"Authorization": f"Bearer {chave}"})
        status3, corpo3 = _status_e_corpo(resp_logs)
        assert status3 == 200
        assert "stdout" in corpo3

        resp_stop = _http(porta, "POST", "/admin/apps/app-fluxo/stop", headers={"Authorization": f"Bearer {chave}"})
        status4, corpo4 = _status_e_corpo(resp_stop)
        assert status4 == 200
        assert corpo4["pid"] is None

        # stop de novo - idempotente
        resp_stop2 = _http(porta, "POST", "/admin/apps/app-fluxo/stop", headers={"Authorization": f"Bearer {chave}"})
        status5, _ = _status_e_corpo(resp_stop2)
        assert status5 == 200
    finally:
        get_manager().parar("app-fluxo") if registry.obter_app("app-fluxo") else None
        servidor.stop()
        _limpar()


def test_delete_running_app_returns_409():
    _limpar()
    servidor, porta = _subir()
    chave = obter_ou_criar()
    try:
        porta_app = _porta_livre()
        _http(porta, "POST", "/admin/apps", corpo={
            "name": "app-rodando", "working_directory": TMPDIR,
            "start_command": [sys.executable, MINI_APP, str(porta_app)], "port": porta_app,
        }, headers={"Authorization": f"Bearer {chave}"})
        _http(porta, "POST", "/admin/apps/app-rodando/deploy", headers={"Authorization": f"Bearer {chave}"})

        resposta = _http(porta, "DELETE", "/admin/apps/app-rodando", headers={"Authorization": f"Bearer {chave}"})
        status, _ = _status_e_corpo(resposta)
        assert status == 409
    finally:
        get_manager().parar("app-rodando") if registry.obter_app("app-rodando") else None
        servidor.stop()
        _limpar()


def test_delete_stopped_app_returns_204():
    _limpar()
    servidor, porta = _subir()
    chave = obter_ou_criar()
    try:
        _http(porta, "POST", "/admin/apps", corpo={
            "name": "app-parada", "working_directory": TMPDIR, "start_command": ["true"],
        }, headers={"Authorization": f"Bearer {chave}"})

        resposta = _http(porta, "DELETE", "/admin/apps/app-parada", headers={"Authorization": f"Bearer {chave}"})
        status, _ = _status_e_corpo(resposta)
        assert status == 204

        resposta2 = _http(porta, "GET", "/admin/apps/app-parada", headers={"Authorization": f"Bearer {chave}"})
        status2, _ = _status_e_corpo(resposta2)
        assert status2 == 404
    finally:
        servidor.stop()
        _limpar()


def test_deploy_then_rollback_via_http():
    _limpar()
    servidor, porta = _subir()
    chave = obter_ou_criar()
    try:
        porta_v1 = _porta_livre()
        _http(porta, "POST", "/admin/apps", corpo={
            "name": "app-http-rollback", "working_directory": TMPDIR,
            "start_command": [sys.executable, MINI_APP, str(porta_v1)], "port": porta_v1,
        }, headers={"Authorization": f"Bearer {chave}"})

        resp_d1 = _http(porta, "POST", "/admin/apps/app-http-rollback/deploy", headers={"Authorization": f"Bearer {chave}"})
        _, corpo_d1 = _status_e_corpo(resp_d1)
        deployment_id_1 = corpo_d1["deployment_id"]

        resp_lista = _http(porta, "GET", "/admin/deployments?app=app-http-rollback", headers={"Authorization": f"Bearer {chave}"})
        status_lista, corpo_lista = _status_e_corpo(resp_lista)
        assert status_lista == 200
        assert len(corpo_lista["deployments"]) == 1

        resp_rollback = _http(porta, "POST", f"/admin/deployments/{deployment_id_1}/rollback",
                                headers={"Authorization": f"Bearer {chave}"})
        status_rb, corpo_rb = _status_e_corpo(resp_rollback)
        assert status_rb == 200
        assert corpo_rb["status"] == "active"
    finally:
        get_manager().parar("app-http-rollback") if registry.obter_app("app-http-rollback") else None
        servidor.stop()
        _limpar()


def test_rollback_nonexistent_deployment_returns_404():
    _limpar()
    servidor, porta = _subir()
    chave = obter_ou_criar()
    try:
        resposta = _http(porta, "POST", "/admin/deployments/nao-existe/rollback", headers={"Authorization": f"Bearer {chave}"})
        status, _ = _status_e_corpo(resposta)
        assert status == 404
    finally:
        servidor.stop()
        _limpar()


def test_start_without_prior_deploy_returns_422():
    _limpar()
    servidor, porta = _subir()
    chave = obter_ou_criar()
    try:
        _http(porta, "POST", "/admin/apps", corpo={
            "name": "app-sem-deploy", "working_directory": TMPDIR, "start_command": ["true"],
        }, headers={"Authorization": f"Bearer {chave}"})

        resposta = _http(porta, "POST", "/admin/apps/app-sem-deploy/start", headers={"Authorization": f"Bearer {chave}"})
        status, _ = _status_e_corpo(resposta)
        assert status == 422
    finally:
        servidor.stop()
        _limpar()
