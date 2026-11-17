"""
tests/test_apps_authorization.py

Testa a autorizacao granular (Passo Console-A) nas 13 rotas de
Applications/Deployments: distincao 404 (fora do escopo) vs 403
(dentro do escopo, sem permissao), filtragem de listagens, e
app.create autorizado pelo nome solicitado.

Usa a fixture estado_isolado (Passo 4C) para isolamento completo do
.state real, e cria chaves nao-admin diretamente via core.identity
para exercitar cenarios de scope/permissao que a suite existente
(toda baseada em chave admin/wildcard) nunca cobriu.
"""
import json
import socket
import time

import pytest

from server.server import Server, ServerConfig
from core.moracle_adapter import build_router
from core.moracle_middleware import auth_middleware
from core.identity import KeyStore, RoleStore, ServiceRole, create_api_key
from admin_api.router import registrar_rotas_admin
from deploy_platform import registry


pytestmark = pytest.mark.usefixtures("estado_isolado")


def _porta_livre():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    porta = s.getsockname()[1]
    s.close()
    return porta


def _http(porta, metodo, path, corpo=None, headers=None, timeout=5):
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


def _status_e_corpo(resposta_bruta):
    linhas = resposta_bruta.split(b"\r\n")
    status = int(linhas[0].split(b" ")[1])
    corpo_bruto = resposta_bruta.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in resposta_bruta else b""
    try:
        corpo = json.loads(corpo_bruto) if corpo_bruto else {}
    except json.JSONDecodeError:
        corpo = {"raw": corpo_bruto.decode(errors="replace")}
    return status, corpo


class _Ambiente:
    def __init__(self, tmp_path):
        self.state_dir = tmp_path / ".state"
        self.servidor = None
        self.porta = None

    def subir(self):
        role_store = RoleStore(self.state_dir)
        role_store.ensure_admin_role_exists()

        router = build_router()
        registrar_rotas_admin(router)
        self.porta = _porta_livre()
        server_config = ServerConfig(host="127.0.0.1", port=self.porta, max_workers=10)
        self.servidor = Server(server_config, router, middlewares=[auth_middleware])
        self.servidor.start(block=False)
        time.sleep(0.2)
        return self

    def derrubar(self):
        if self.servidor:
            self.servidor.stop()

    def criar_chave(self, role_name, permissions, scoped_app_names=None):
        role_store = RoleStore(self.state_dir)
        try:
            role_store.add(ServiceRole(name=role_name, permissions=frozenset(permissions)))
        except Exception:
            pass  # role ja existe, reaproveita
        key_store = KeyStore(self.state_dir)
        _, token = create_api_key(
            key_store, name=f"chave-{role_name}-{'-'.join(sorted(scoped_app_names or []))}",
            role_name=role_name, scoped_app_names=list(scoped_app_names or []),
        )
        return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def ambiente(tmp_path):
    amb = _Ambiente(tmp_path).subir()
    yield amb
    amb.derrubar()


def _criar_app_direto(nome, domain=None):
    registry.criar_ou_obter_app(nome, domain=domain)


# =============================================================================
# GET /admin/apps/{name} — distincao 404/403
# =============================================================================

def test_get_app_fora_do_escopo_retorna_404(ambiente):
    _criar_app_direto("app-alheio")
    headers = ambiente.criar_chave("leitor", ["app.read"], scoped_app_names=["app-a"])

    resposta = _http(ambiente.porta, "GET", "/admin/apps/app-alheio", headers=headers)
    status, corpo = _status_e_corpo(resposta)

    assert status == 404
    assert corpo["error"] == "application not found"


def test_get_app_dentro_do_escopo_sem_permissao_retorna_403(ambiente):
    _criar_app_direto("app-a")
    headers = ambiente.criar_chave("sem-leitura", ["app.deploy"], scoped_app_names=["app-a"])

    resposta = _http(ambiente.porta, "GET", "/admin/apps/app-a", headers=headers)
    status, corpo = _status_e_corpo(resposta)

    assert status == 403
    assert "app.read" in corpo["error"]


def test_get_app_dentro_do_escopo_com_permissao_autoriza(ambiente):
    _criar_app_direto("app-a")
    headers = ambiente.criar_chave("leitor", ["app.read"], scoped_app_names=["app-a"])

    resposta = _http(ambiente.porta, "GET", "/admin/apps/app-a", headers=headers)
    status, corpo = _status_e_corpo(resposta)

    assert status == 200
    assert corpo["name"] == "app-a"


def test_get_app_inexistente_dentro_do_escopo_global_retorna_404(ambiente):
    """Chave globalmente escopada (scoped_app_names=[]) + app que
    realmente nao existe -> 404 'de verdade' (nao por falta de scope)."""
    headers = ambiente.criar_chave("leitor-global", ["app.read"], scoped_app_names=[])

    resposta = _http(ambiente.porta, "GET", "/admin/apps/nao-existe", headers=headers)
    status, corpo = _status_e_corpo(resposta)

    assert status == 404
    assert corpo["error"] == "application not found"


def test_role_inexistente_retorna_403_access_denied(ambiente):
    """ApiKey com role_name que nao resolve mais -> fail-closed, 403
    generico, nunca 404 (nao e sobre o app, e sobre a identidade)."""
    key_store = KeyStore(ambiente.state_dir)
    _, token = create_api_key(key_store, name="orfa", role_name="role-fantasma")
    headers = {"Authorization": f"Bearer {token}"}

    resposta = _http(ambiente.porta, "GET", "/admin/apps/qualquer", headers=headers)
    status, corpo = _status_e_corpo(resposta)

    assert status == 403
    assert corpo["error"] == "access denied"


# =============================================================================
# GET /admin/apps — listagem filtrada
# =============================================================================

def test_list_apps_filtra_por_escopo(ambiente):
    _criar_app_direto("app-a")
    _criar_app_direto("app-b")
    _criar_app_direto("app-c")
    headers = ambiente.criar_chave("leitor", ["app.read"], scoped_app_names=["app-a", "app-c"])

    resposta = _http(ambiente.porta, "GET", "/admin/apps", headers=headers)
    status, corpo = _status_e_corpo(resposta)

    assert status == 200
    nomes = {a["name"] for a in corpo["applications"]}
    assert nomes == {"app-a", "app-c"}


def test_list_apps_globalmente_escopada_ve_tudo(ambiente):
    _criar_app_direto("app-x")
    _criar_app_direto("app-y")
    headers = ambiente.criar_chave("leitor-global", ["app.read"], scoped_app_names=[])

    resposta = _http(ambiente.porta, "GET", "/admin/apps", headers=headers)
    status, corpo = _status_e_corpo(resposta)

    assert status == 200
    nomes = {a["name"] for a in corpo["applications"]}
    assert {"app-x", "app-y"}.issubset(nomes)


# =============================================================================
# POST /admin/apps — autorizado pelo nome solicitado
# =============================================================================

def test_create_app_dentro_do_escopo_autoriza(ambiente):
    headers = ambiente.criar_chave("criador", ["app.create"], scoped_app_names=["app-permitida"])

    resposta = _http(ambiente.porta, "POST", "/admin/apps", corpo={
        "name": "app-permitida", "working_directory": "/tmp", "start_command": ["echo", "oi"],
    }, headers=headers)
    status, _ = _status_e_corpo(resposta)

    assert status == 201


def test_create_app_fora_do_escopo_retorna_404(ambiente):
    """Chave scoped tentando criar app FORA do proprio scoped_app_names
    -> 404 (nao pode nem confirmar que esse nome esta disponivel para
    outra credencial), conforme contrato aprovado."""
    headers = ambiente.criar_chave("criador", ["app.create"], scoped_app_names=["app-permitida"])

    resposta = _http(ambiente.porta, "POST", "/admin/apps", corpo={
        "name": "app-nao-permitida", "working_directory": "/tmp", "start_command": ["echo", "oi"],
    }, headers=headers)
    status, corpo = _status_e_corpo(resposta)

    assert status == 404
    assert corpo["error"] == "application not found"


def test_create_app_globalmente_escopada_cria_qualquer_nome(ambiente):
    headers = ambiente.criar_chave("criador-global", ["app.create"], scoped_app_names=[])

    resposta = _http(ambiente.porta, "POST", "/admin/apps", corpo={
        "name": "app-qualquer", "working_directory": "/tmp", "start_command": ["echo", "oi"],
    }, headers=headers)
    status, _ = _status_e_corpo(resposta)

    assert status == 201


def test_create_app_sem_permissao_mesmo_dentro_do_escopo_retorna_403(ambiente):
    headers = ambiente.criar_chave("sem-create", ["app.read"], scoped_app_names=["app-a"])

    resposta = _http(ambiente.porta, "POST", "/admin/apps", corpo={
        "name": "app-a", "working_directory": "/tmp", "start_command": ["echo", "oi"],
    }, headers=headers)
    status, corpo = _status_e_corpo(resposta)

    assert status == 403


# =============================================================================
# Deployments — resolucao via deployment.app_name
# =============================================================================

def test_get_deployment_fora_do_escopo_retorna_404_deployment_not_found(ambiente):
    _criar_app_direto("app-privado")
    dep = registry.criar_deployment("app-privado", source_path="/tmp/src")
    headers = ambiente.criar_chave("leitor", ["deployment.read"], scoped_app_names=["outro-app"])

    resposta = _http(ambiente.porta, "GET", f"/admin/deployments/{dep.deployment_id}", headers=headers)
    status, corpo = _status_e_corpo(resposta)

    assert status == 404
    assert corpo["error"] == "deployment not found"  # NAO "application not found"


def test_get_deployment_dentro_do_escopo_autoriza(ambiente):
    _criar_app_direto("app-visivel")
    dep = registry.criar_deployment("app-visivel", source_path="/tmp/src")
    headers = ambiente.criar_chave("leitor", ["deployment.read"], scoped_app_names=["app-visivel"])

    resposta = _http(ambiente.porta, "GET", f"/admin/deployments/{dep.deployment_id}", headers=headers)
    status, corpo = _status_e_corpo(resposta)

    assert status == 200
    assert corpo["deployment_id"] == dep.deployment_id


def test_list_deployments_sem_filtro_de_app_filtra_por_escopo(ambiente):
    _criar_app_direto("app-a")
    _criar_app_direto("app-b")
    registry.criar_deployment("app-a", source_path="/tmp/src-a")
    registry.criar_deployment("app-b", source_path="/tmp/src-b")
    headers = ambiente.criar_chave("leitor", ["deployment.read"], scoped_app_names=["app-a"])

    resposta = _http(ambiente.porta, "GET", "/admin/deployments", headers=headers)
    status, corpo = _status_e_corpo(resposta)

    assert status == 200
    app_names = {d["app_name"] for d in corpo["deployments"]}
    assert app_names == {"app-a"}


def test_list_deployments_com_filtro_app_fora_do_escopo_retorna_404(ambiente):
    _criar_app_direto("app-alheio")
    headers = ambiente.criar_chave("leitor", ["deployment.read"], scoped_app_names=["app-a"])

    resposta = _http(ambiente.porta, "GET", "/admin/deployments?app=app-alheio", headers=headers)
    status, _ = _status_e_corpo(resposta)

    assert status == 404
