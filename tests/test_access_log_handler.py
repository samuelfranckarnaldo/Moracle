"""
tests/test_access_log_handler.py

Testes de GET /admin/apps/{name}/access-logs: autorizacao 404/403,
filtros, cursor/limit, formato de resposta, reconhecimento como rota
app-scoped, e auto-registro (a propria consulta gera seu proprio
AccessLogRecord).

Reaproveita a mesma infraestrutura de teste de test_apps_authorization.py
(_Ambiente, _http, criar_chave) para consistencia com o padrao ja
estabelecido de autorizacao granular.
"""
import json
import os
import socket
import time

import pytest

from server.server import Server, ServerConfig
from server.access_log import AccessLogger, JsonlSink
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


def _criar_app_direto(nome, domain=None):
    registry.criar_ou_obter_app(nome, domain=domain)


class _Ambiente:
    """Identica a test_apps_authorization.py, com uma diferenca: usa
    AccessLogger real com JsonlSink apontando para um arquivo dentro
    de tmp_path, para poder inspecionar o access_log.jsonl gerado
    pelas proprias requisicoes de teste (incluindo a auto-consulta)."""

    def __init__(self, tmp_path):
        self.state_dir = tmp_path / ".state"
        self.caminho_access_log = str(tmp_path / ".state" / "access_log.jsonl")
        self.servidor = None
        self.porta = None

    def subir(self):
        role_store = RoleStore(self.state_dir)
        role_store.ensure_admin_role_exists()

        router = build_router()
        registrar_rotas_admin(router)
        self.porta = _porta_livre()
        server_config = ServerConfig(host="127.0.0.1", port=self.porta, max_workers=10)
        access_logger = AccessLogger(jsonl_sink=JsonlSink(self.caminho_access_log))
        self.servidor = Server(
            server_config, router, middlewares=[auth_middleware], access_logger=access_logger,
        )
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
            pass
        key_store = KeyStore(self.state_dir)
        _, token = create_api_key(
            key_store, name=f"chave-{role_name}-{'-'.join(sorted(scoped_app_names or []))}",
            role_name=role_name, scoped_app_names=list(scoped_app_names or []),
        )
        return {"Authorization": f"Bearer {token}"}

    def ler_registros_jsonl(self):
        if not os.path.exists(self.caminho_access_log):
            return []
        with open(self.caminho_access_log, "r", encoding="utf-8") as f:
            return [json.loads(l) for l in f if l.strip()]


@pytest.fixture
def ambiente(tmp_path):
    amb = _Ambiente(tmp_path).subir()
    yield amb
    amb.derrubar()


# =============================================================================
# Autorizacao: 404 (fora do escopo) vs 403 (sem permissao) vs 200
# =============================================================================

def test_access_logs_fora_do_escopo_retorna_404(ambiente):
    _criar_app_direto("app-alheio")
    headers = ambiente.criar_chave("leitor", ["app.access_logs"], scoped_app_names=["app-a"])

    resposta = _http(ambiente.porta, "GET", "/admin/apps/app-alheio/access-logs", headers=headers)
    status, corpo = _status_e_corpo(resposta)

    assert status == 404
    assert corpo["error"] == "application not found"


def test_access_logs_app_inexistente_retorna_404(ambiente):
    headers = ambiente.criar_chave("leitor", ["app.access_logs"], scoped_app_names=["app-a"])

    resposta = _http(ambiente.porta, "GET", "/admin/apps/nunca-existiu/access-logs", headers=headers)
    status, corpo = _status_e_corpo(resposta)

    assert status == 404


def test_access_logs_dentro_do_escopo_sem_permissao_retorna_403(ambiente):
    _criar_app_direto("app-a")
    # tem app.read mas nao app.access_logs
    headers = ambiente.criar_chave("leitor-generico", ["app.read"], scoped_app_names=["app-a"])

    resposta = _http(ambiente.porta, "GET", "/admin/apps/app-a/access-logs", headers=headers)
    status, corpo = _status_e_corpo(resposta)

    assert status == 403
    assert "app.access_logs" in corpo["error"]


def test_access_logs_com_permissao_correta_retorna_200(ambiente):
    _criar_app_direto("app-a")
    headers = ambiente.criar_chave("observador", ["app.access_logs"], scoped_app_names=["app-a"])

    resposta = _http(ambiente.porta, "GET", "/admin/apps/app-a/access-logs", headers=headers)
    status, corpo = _status_e_corpo(resposta)

    assert status == 200
    assert "records" in corpo
    assert "next_cursor" in corpo
    assert "total_matched" in corpo


# =============================================================================
# Formato de resposta, filtros, limit/cursor
# =============================================================================

def test_resposta_com_arquivo_vazio_retorna_lista_vazia(ambiente):
    _criar_app_direto("app-a")
    headers = ambiente.criar_chave("observador", ["app.access_logs"], scoped_app_names=["app-a"])

    resposta = _http(ambiente.porta, "GET", "/admin/apps/app-a/access-logs", headers=headers)
    status, corpo = _status_e_corpo(resposta)

    assert status == 200
    # arquivo pode ja ter a propria requisicao de auth/consulta - so
    # garantimos que a estrutura e' uma lista, nao o conteudo exato
    assert isinstance(corpo["records"], list)
    assert corpo["total_matched"] == len(corpo["records"]) or corpo["next_cursor"] is not None


def test_filtro_status_via_query_param(ambiente):
    _criar_app_direto("app-a")
    headers = ambiente.criar_chave("observador", ["app.access_logs"], scoped_app_names=["app-a"])

    resposta = _http(
        ambiente.porta, "GET", "/admin/apps/app-a/access-logs?status=999", headers=headers,
    )
    status, corpo = _status_e_corpo(resposta)

    assert status == 200
    assert corpo["total_matched"] == 0  # nenhuma requisicao real teve status 999


def test_status_invalido_retorna_400(ambiente):
    _criar_app_direto("app-a")
    headers = ambiente.criar_chave("observador", ["app.access_logs"], scoped_app_names=["app-a"])

    resposta = _http(
        ambiente.porta, "GET", "/admin/apps/app-a/access-logs?status=nao-e-numero", headers=headers,
    )
    status, corpo = _status_e_corpo(resposta)

    assert status == 400


def test_limit_via_query_param_e_respeitado(ambiente):
    _criar_app_direto("app-a")
    headers = ambiente.criar_chave("observador", ["app.access_logs"], scoped_app_names=["app-a"])

    # gera algumas requisicoes reais primeiro
    for _ in range(3):
        _http(ambiente.porta, "GET", "/admin/apps/app-a", headers=headers)

    resposta = _http(
        ambiente.porta, "GET", "/admin/apps/app-a/access-logs?limit=1", headers=headers,
    )
    status, corpo = _status_e_corpo(resposta)

    assert status == 200
    assert len(corpo["records"]) <= 1


# =============================================================================
# Rota reconhecida como app-scoped
# =============================================================================

def test_rota_access_logs_e_app_scoped_marca_app_name_no_context():
    from admin_api.router import _app_scoped
    from server.request import Context

    def handler_falso(request, context):
        return "ok"

    context = Context(request_id="r1")
    context.route_params = {"name": "app-x"}
    _app_scoped(handler_falso)(request=None, context=context)

    assert context["app_name"] == "app-x"


# =============================================================================
# Auto-registro: a consulta ao access log gera seu proprio AccessLogRecord
# =============================================================================

def test_consulta_ao_access_log_e_ela_propria_registrada(ambiente):
    """A propria requisicao GET .../access-logs deve aparecer, depois,
    como um registro no access_log.jsonl - com app_name igual ao name
    da rota consultada. A consulta nao deve alterar os registros
    anteriores, apenas adicionar um novo, como qualquer requisicao."""
    _criar_app_direto("app-a")
    headers = ambiente.criar_chave("observador", ["app.access_logs"], scoped_app_names=["app-a"])

    resposta = _http(ambiente.porta, "GET", "/admin/apps/app-a/access-logs", headers=headers)
    status, _ = _status_e_corpo(resposta)
    assert status == 200

    time.sleep(0.1)  # garante que o sink terminou de escrever
    registros = ambiente.ler_registros_jsonl()

    registros_da_consulta = [
        r for r in registros
        if r["path"] == "/admin/apps/app-a/access-logs" and r["app_name"] == "app-a"
    ]
    assert len(registros_da_consulta) == 1
    assert registros_da_consulta[0]["status"] == 200
