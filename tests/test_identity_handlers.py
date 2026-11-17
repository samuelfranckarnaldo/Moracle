"""
tests/test_identity_handlers.py

Testes HTTP end-to-end das cinco rotas de identidade (Passo 4B-C
Parte 4): POST/GET/DELETE /admin/keys, GET/POST /admin/roles.

ISOLAMENTO: core.config.RAIZ_PROJETO e patcheado para tmp_path durante
cada teste. Isso e suficiente para isolar .state/keys.json e
.state/roles.json porque tanto core/moracle_middleware.py::auth_middleware
quanto admin_api/identity_handlers.py::_key_store()/_role_store() leem
config.RAIZ_PROJETO DINAMICAMENTE a cada chamada (nao em tempo de
import) — diferente de core/api_key.py::KEY_PATH e
deploy_platform/registry.py::PLATFORM_DIR, que sao constantes fixadas
em tempo de import e portanto NAO seriam afetadas por este patch.

Por isso o bootstrap de identidade destes testes NAO usa
obter_ou_criar()/migrate_legacy_admin_key() (que dependem de
core.api_key.KEY_PATH, ja congelado) — em vez disso, a chave admin e
criada diretamente via core.identity, apontando explicitamente para
tmp_path/.state.

registry.PLATFORM_DIR nao e isolado por este patch (permanece
apontando para o .state real do projeto) — para os poucos testes que
precisam de Applications reais (validacao de scoped_app_names),
reutiliza-se _limpar() (mesmo mecanismo ja usado em test_admin_api.py
para isolar dados de deployment). Isso e' um gap pre-existente e fora
do escopo desta Parte 4, que trata exclusivamente do isolamento de
identidade (.state/keys.json e .state/roles.json).
"""
import json
import os
import shutil
import socket
import time
from pathlib import Path
import pytest

from server.server import Server, ServerConfig
from server.response import Response
from core.moracle_adapter import build_router
from core.moracle_middleware import auth_middleware
from admin_api.router import registrar_rotas_admin
from core.identity import KeyStore, RoleStore, ServiceRole, SERVER_ADMIN_PERMISSION, create_api_key
from deploy_platform import registry


def _porta_livre():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    porta = s.getsockname()[1]
    s.close()
    return porta


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


def _status_e_corpo(resposta_bruta):
    linhas = resposta_bruta.split(b"\r\n")
    status = int(linhas[0].split(b" ")[1])
    corpo_bruto = resposta_bruta.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in resposta_bruta else b""
    try:
        corpo = json.loads(corpo_bruto) if corpo_bruto else {}
    except json.JSONDecodeError:
        corpo = {"raw": corpo_bruto.decode(errors="replace")}
    return status, corpo


def _limpar_registry():
    if os.path.exists(registry.PLATFORM_DIR):
        shutil.rmtree(registry.PLATFORM_DIR)


class _AmbienteIsolado:
    """Sobe o servidor sobre o estado ja isolado pela fixture global
    estado_isolado (Passo 4C) — nao patcheia nada por conta propria.
    Cria uma chave admin diretamente via core.identity, sem depender
    do bootstrap legado (core.api_key)."""

    def __init__(self, tmp_path: Path):
        self.tmp_path = tmp_path
        self.state_dir = tmp_path / ".state"
        self.servidor = None
        self.porta = None
        self.admin_token = None

    def subir(self):
        role_store = RoleStore(self.state_dir)
        role_store.ensure_admin_role_exists()
        key_store = KeyStore(self.state_dir)
        _, self.admin_token = create_api_key(key_store, name="admin-teste", role_name="admin")

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

    def auth_admin(self):
        return {"Authorization": f"Bearer {self.admin_token}"}

    def criar_chave_nao_admin(self, role_name="operador", permissions=("app.read",), scoped_app_names=None):
        role_store = RoleStore(self.state_dir)
        try:
            role_store.add(ServiceRole(name=role_name, permissions=frozenset(permissions)))
        except Exception:
            pass  # role ja existe, reaproveita
        key_store = KeyStore(self.state_dir)
        _, token = create_api_key(
            key_store, name=f"chave-{role_name}", role_name=role_name,
            scoped_app_names=list(scoped_app_names or []),
        )
        return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def ambiente(tmp_path, estado_isolado):
    amb = _AmbienteIsolado(tmp_path).subir()
    yield amb
    amb.derrubar()


# =============================================================================
# Autenticacao / Autorizacao (aplicavel as 5 rotas — testado numa amostra)
# =============================================================================

def test_sem_authorization_retorna_401(ambiente):
    resposta = _http(ambiente.porta, "GET", "/admin/keys")
    status, _ = _status_e_corpo(resposta)
    assert status == 401


def test_chave_nao_admin_retorna_403(ambiente):
    headers = ambiente.criar_chave_nao_admin()
    resposta = _http(ambiente.porta, "GET", "/admin/keys", headers=headers)
    status, _ = _status_e_corpo(resposta)
    assert status == 403


def test_chave_admin_autoriza(ambiente):
    resposta = _http(ambiente.porta, "GET", "/admin/keys", headers=ambiente.auth_admin())
    status, _ = _status_e_corpo(resposta)
    assert status == 200


# =============================================================================
# POST /admin/keys
# =============================================================================

def test_create_key_sucesso_retorna_secret_uma_vez(ambiente):
    resposta = _http(ambiente.porta, "POST", "/admin/keys", corpo={
        "name": "deploy-prod", "role": "admin",
    }, headers=ambiente.auth_admin())
    status, corpo = _status_e_corpo(resposta)

    assert status == 201
    assert corpo["name"] == "deploy-prod"
    assert corpo["role"] == "admin"
    assert "secret" in corpo and corpo["secret"]
    assert "key_hash" not in corpo
    assert corpo["revoked"] is False
    assert corpo["scoped_app_names"] == []


def test_create_key_nome_ausente_retorna_400(ambiente):
    resposta = _http(ambiente.porta, "POST", "/admin/keys", corpo={
        "role": "admin",
    }, headers=ambiente.auth_admin())
    status, _ = _status_e_corpo(resposta)
    assert status == 400


def test_create_key_role_inexistente_retorna_400(ambiente):
    resposta = _http(ambiente.porta, "POST", "/admin/keys", corpo={
        "name": "chave-x", "role": "role-que-nao-existe",
    }, headers=ambiente.auth_admin())
    status, _ = _status_e_corpo(resposta)
    assert status == 400


def test_create_key_expires_at_invalido_retorna_400(ambiente):
    resposta = _http(ambiente.porta, "POST", "/admin/keys", corpo={
        "name": "chave-x", "role": "admin", "expires_at": "nao-e-uma-data",
    }, headers=ambiente.auth_admin())
    status, _ = _status_e_corpo(resposta)
    assert status == 400


def test_create_key_scoped_app_names_duplicatas_retorna_400(ambiente):
    resposta = _http(ambiente.porta, "POST", "/admin/keys", corpo={
        "name": "chave-x", "role": "admin", "scoped_app_names": ["api", "api"],
    }, headers=ambiente.auth_admin())
    status, _ = _status_e_corpo(resposta)
    assert status == 400


def test_create_key_scoped_app_name_inexistente_retorna_400(ambiente):
    _limpar_registry()
    resposta = _http(ambiente.porta, "POST", "/admin/keys", corpo={
        "name": "chave-x", "role": "admin", "scoped_app_names": ["app-que-nao-existe"],
    }, headers=ambiente.auth_admin())
    status, _ = _status_e_corpo(resposta)
    assert status == 400


def test_create_key_scoped_app_name_existente_aceita(ambiente):
    _limpar_registry()
    registry.criar_ou_obter_app("api-financeira")

    resposta = _http(ambiente.porta, "POST", "/admin/keys", corpo={
        "name": "chave-com-escopo", "role": "admin", "scoped_app_names": ["api-financeira"],
    }, headers=ambiente.auth_admin())
    status, corpo = _status_e_corpo(resposta)

    assert status == 201
    assert corpo["scoped_app_names"] == ["api-financeira"]
    _limpar_registry()


def test_create_key_nome_duplicado_retorna_409(ambiente):
    resposta1 = _http(ambiente.porta, "POST", "/admin/keys", corpo={
        "name": "minha-chave", "role": "admin",
    }, headers=ambiente.auth_admin())
    status1, _ = _status_e_corpo(resposta1)
    assert status1 == 201

    resposta2 = _http(ambiente.porta, "POST", "/admin/keys", corpo={
        "name": "minha-chave", "role": "admin",
    }, headers=ambiente.auth_admin())
    status2, _ = _status_e_corpo(resposta2)
    assert status2 == 409


# =============================================================================
# GET /admin/keys
# =============================================================================

def test_list_keys_nunca_inclui_secret_ou_hash(ambiente):
    _http(ambiente.porta, "POST", "/admin/keys", corpo={
        "name": "chave-listada", "role": "admin",
    }, headers=ambiente.auth_admin())

    resposta = _http(ambiente.porta, "GET", "/admin/keys", headers=ambiente.auth_admin())
    status, corpo = _status_e_corpo(resposta)

    assert status == 200
    nomes = [k["name"] for k in corpo["keys"]]
    assert "chave-listada" in nomes
    for k in corpo["keys"]:
        assert "secret" not in k
        assert "key_hash" not in k
        assert "raw_token" not in k


# =============================================================================
# DELETE /admin/keys/{id}
# =============================================================================

def test_revoke_key_sucesso(ambiente):
    role_store = RoleStore(ambiente.state_dir)
    try:
        role_store.add(ServiceRole(name="descartavel", permissions=frozenset({"app.read"})))
    except Exception:
        pass
    resposta_criacao = _http(ambiente.porta, "POST", "/admin/keys", corpo={
        "name": "chave-a-revogar", "role": "descartavel",
    }, headers=ambiente.auth_admin())
    _, corpo_criacao = _status_e_corpo(resposta_criacao)
    key_id = corpo_criacao["id"]

    resposta = _http(ambiente.porta, "DELETE", f"/admin/keys/{key_id}", headers=ambiente.auth_admin())
    status, corpo = _status_e_corpo(resposta)

    assert status == 200
    assert corpo == {"id": key_id, "revoked": True}


def test_revoke_key_idempotente(ambiente):
    role_store = RoleStore(ambiente.state_dir)
    try:
        role_store.add(ServiceRole(name="descartavel2", permissions=frozenset({"app.read"})))
    except Exception:
        pass
    resposta_criacao = _http(ambiente.porta, "POST", "/admin/keys", corpo={
        "name": "chave-idempotente", "role": "descartavel2",
    }, headers=ambiente.auth_admin())
    _, corpo_criacao = _status_e_corpo(resposta_criacao)
    key_id = corpo_criacao["id"]

    r1 = _http(ambiente.porta, "DELETE", f"/admin/keys/{key_id}", headers=ambiente.auth_admin())
    r2 = _http(ambiente.porta, "DELETE", f"/admin/keys/{key_id}", headers=ambiente.auth_admin())

    status1, _ = _status_e_corpo(r1)
    status2, _ = _status_e_corpo(r2)
    assert status1 == 200
    assert status2 == 200


def test_revoke_key_inexistente_retorna_404(ambiente):
    resposta = _http(ambiente.porta, "DELETE", "/admin/keys/nao-existe", headers=ambiente.auth_admin())
    status, _ = _status_e_corpo(resposta)
    assert status == 404


def test_revoke_ultima_chave_admin_retorna_409(ambiente):
    # ambiente.admin_token e a UNICA chave admin existente
    key_store = KeyStore(ambiente.state_dir)
    todas = key_store.load_all()
    (unica_admin_id,) = [k.id for k in todas.values() if k.role_name == "admin"]

    resposta = _http(ambiente.porta, "DELETE", f"/admin/keys/{unica_admin_id}", headers=ambiente.auth_admin())
    status, corpo = _status_e_corpo(resposta)

    assert status == 409
    assert key_store.get(unica_admin_id).revoked is False


# =============================================================================
# GET /admin/roles
# =============================================================================

def test_list_roles_inclui_admin(ambiente):
    resposta = _http(ambiente.porta, "GET", "/admin/roles", headers=ambiente.auth_admin())
    status, corpo = _status_e_corpo(resposta)

    assert status == 200
    nomes = [r["name"] for r in corpo["roles"]]
    assert "admin" in nomes


# =============================================================================
# POST /admin/roles
# =============================================================================

def test_create_role_sucesso(ambiente):
    resposta = _http(ambiente.porta, "POST", "/admin/roles", corpo={
        "name": "monitoring", "description": "Read-only monitoring",
        "permissions": ["app.read", "app.logs", "deployment.read"],
    }, headers=ambiente.auth_admin())
    status, corpo = _status_e_corpo(resposta)

    assert status == 201
    assert corpo["name"] == "monitoring"
    assert set(corpo["permissions"]) == {"app.read", "app.logs", "deployment.read"}


def test_create_role_permissao_desconhecida_retorna_400(ambiente):
    resposta = _http(ambiente.porta, "POST", "/admin/roles", corpo={
        "name": "invalida", "permissions": ["qualquer.coisa"],
    }, headers=ambiente.auth_admin())
    status, _ = _status_e_corpo(resposta)
    assert status == 400


def test_create_role_sem_permissions_retorna_400(ambiente):
    resposta = _http(ambiente.porta, "POST", "/admin/roles", corpo={
        "name": "vazia", "permissions": [],
    }, headers=ambiente.auth_admin())
    status, _ = _status_e_corpo(resposta)
    assert status == 400


def test_create_role_nome_duplicado_retorna_409_sem_sobrescrever(ambiente):
    _http(ambiente.porta, "POST", "/admin/roles", corpo={
        "name": "duplicavel", "permissions": ["app.read"],
    }, headers=ambiente.auth_admin())

    resposta = _http(ambiente.porta, "POST", "/admin/roles", corpo={
        "name": "duplicavel", "permissions": [SERVER_ADMIN_PERMISSION],
    }, headers=ambiente.auth_admin())
    status, _ = _status_e_corpo(resposta)
    assert status == 409

    # role original nao foi sobrescrita — prova contra escalada de privilegio
    role_store = RoleStore(ambiente.state_dir)
    original = role_store.get("duplicavel")
    assert original.permissions == {"app.read"}


def test_create_role_escalada_privilegio_bloqueada_por_nao_admin(ambiente):
    """Chave nao-admin nao consegue criar NENHUM role, incluindo um
    role SEM server.admin — a rota inteira exige server.admin,
    fechando a via de escalada na origem."""
    headers = ambiente.criar_chave_nao_admin()
    resposta = _http(ambiente.porta, "POST", "/admin/roles", corpo={
        "name": "evil-role", "permissions": ["app.read"],
    }, headers=headers)
    status, _ = _status_e_corpo(resposta)
    assert status == 403
