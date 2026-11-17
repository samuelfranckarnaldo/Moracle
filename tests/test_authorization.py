"""
tests/test_authorization.py

Cobre os invariantes obrigatórios do Passo 3 (core/authorization.py):
    - server.admin -> autoriza qualquer permission/app/scope
    - permission ausente -> negado
    - permission presente + scope vazio -> autorizado para qualquer app
    - permission presente + app no scope -> autorizado
    - permission presente + app fora do scope -> negado
    - permission presente sem alvo de app -> autorizado
    - scope correto sem permission -> negado (scope nao concede permissao)
    - role ausente (referencia quebrada) -> negado
    - permission fora do contrato -> levanta UnknownPermissionError
"""

from pathlib import Path

import pytest

from core.identity import (
    ApiKey,
    ServiceRole,
    RoleStore,
    SERVER_ADMIN_PERMISSION,
    UnknownPermissionError,
)
from core.authorization import autorizar, exigir_permissao


def _api_key(scoped_app_names=None, role_name="deploy") -> ApiKey:
    return ApiKey(
        id="k1",
        key_hash="hash-irrelevante-aqui",
        name="chave-teste",
        role_name=role_name,
        created_at="2026-01-01T00:00:00+00:00",
        scoped_app_names=scoped_app_names or [],
    )


# ---------------------------------------------------------------------------
# autorizar() — função pura
# ---------------------------------------------------------------------------

def test_server_admin_autoriza_qualquer_permissao_app_e_scope():
    admin_role = ServiceRole(name="admin", permissions=frozenset({SERVER_ADMIN_PERMISSION}))
    key = _api_key(scoped_app_names=["app-a"], role_name="admin")

    assert autorizar(key, admin_role, "app.delete", app_name="qualquer-app") is True
    assert autorizar(key, admin_role, "defense.block", app_name="outra-app") is True
    assert autorizar(key, admin_role, "app.deploy", app_name=None) is True


def test_permissao_ausente_nega():
    role = ServiceRole(name="somente-leitura", permissions=frozenset({"app.read"}))
    key = _api_key()

    assert autorizar(key, role, "app.deploy", app_name="app-a") is False


def test_permissao_presente_scope_vazio_autoriza_qualquer_app():
    role = ServiceRole(name="deploy", permissions=frozenset({"app.deploy"}))
    key = _api_key(scoped_app_names=[])  # [] == todas as aplicações

    assert autorizar(key, role, "app.deploy", app_name="app-a") is True
    assert autorizar(key, role, "app.deploy", app_name="app-b") is True


def test_permissao_presente_app_no_scope_autoriza():
    role = ServiceRole(name="deploy", permissions=frozenset({"app.deploy"}))
    key = _api_key(scoped_app_names=["api-financeira"])

    assert autorizar(key, role, "app.deploy", app_name="api-financeira") is True


def test_permissao_presente_app_fora_do_scope_nega():
    role = ServiceRole(name="deploy", permissions=frozenset({"app.deploy"}))
    key = _api_key(scoped_app_names=["api-financeira"])

    assert autorizar(key, role, "app.deploy", app_name="site") is False


def test_permissao_presente_sem_alvo_de_app_autoriza():
    role = ServiceRole(name="deploy", permissions=frozenset({"deployment.read"}))
    key = _api_key(scoped_app_names=["app-a"])

    # operacao sem alvo de aplicacao especifico (app_name=None) —
    # ex.: listar deployments em geral
    assert autorizar(key, role, "deployment.read", app_name=None) is True


def test_scope_correto_sem_permissao_nega():
    """Prova central do Passo 3: scope NUNCA concede permissao por si só."""
    role = ServiceRole(name="somente-leitura", permissions=frozenset({"app.read"}))
    key = _api_key(scoped_app_names=["api-financeira"])

    assert autorizar(key, role, "app.deploy", app_name="api-financeira") is False


def test_permissao_fora_do_contrato_levanta_erro():
    role = ServiceRole(name="deploy", permissions=frozenset({"app.deploy"}))
    key = _api_key()

    with pytest.raises(UnknownPermissionError):
        autorizar(key, role, "app.voar", app_name="app-a")


# ---------------------------------------------------------------------------
# exigir_permissao() — wrapper com RoleStore
# ---------------------------------------------------------------------------

def test_exigir_permissao_resolve_role_e_autoriza(tmp_path: Path):
    role_store = RoleStore(tmp_path)
    role_store.upsert(ServiceRole(name="deploy", permissions=frozenset({"app.deploy"})))
    key = _api_key(scoped_app_names=["api-financeira"], role_name="deploy")

    assert exigir_permissao(key, role_store, "app.deploy", app_name="api-financeira") is True
    assert exigir_permissao(key, role_store, "app.deploy", app_name="site") is False


def test_exigir_permissao_com_role_ausente_nega(tmp_path: Path):
    """Referencia quebrada (role_name aponta para um role que nao existe
    mais no RoleStore) deve falhar fechado — NUNCA autorizar."""
    role_store = RoleStore(tmp_path)
    key = _api_key(role_name="role-que-nao-existe")

    assert exigir_permissao(key, role_store, "app.deploy", app_name="app-a") is False


def test_exigir_permissao_server_admin_via_role_store(tmp_path: Path):
    role_store = RoleStore(tmp_path)
    role_store.ensure_admin_role_exists()
    key = _api_key(scoped_app_names=["app-a"], role_name="admin")

    assert exigir_permissao(key, role_store, "app.delete", app_name="qualquer-outra-app") is True


# ---------------------------------------------------------------------------
# resolver_acesso() — decomposicao granular (Console-A)
# ---------------------------------------------------------------------------

from core.authorization import resolver_acesso, ResolucaoAcesso


def test_resolver_acesso_wildcard_autoriza_independente_de_scope_e_permission():
    admin_role = ServiceRole(name="admin", permissions=frozenset({SERVER_ADMIN_PERMISSION}))
    key = _api_key(scoped_app_names=["app-a"], role_name="admin")

    resultado = resolver_acesso(key, admin_role, "app.delete", app_name="qualquer-outra-app")
    assert resultado == ResolucaoAcesso.AUTORIZADO


def test_resolver_acesso_sem_app_name_sem_permissao_retorna_sem_permissao():
    role = ServiceRole(name="somente-leitura", permissions=frozenset({"app.read"}))
    key = _api_key()

    resultado = resolver_acesso(key, role, "app.deploy", app_name=None)
    assert resultado == ResolucaoAcesso.SEM_PERMISSAO


def test_resolver_acesso_sem_app_name_com_permissao_autoriza():
    role = ServiceRole(name="deploy", permissions=frozenset({"deployment.read"}))
    key = _api_key(scoped_app_names=["app-a"])

    resultado = resolver_acesso(key, role, "deployment.read", app_name=None)
    assert resultado == ResolucaoAcesso.AUTORIZADO


def test_resolver_acesso_app_fora_do_escopo_retorna_sem_escopo_mesmo_com_permissao():
    """Prova central da granularidade: scope e checado ANTES de
    permission — um app fora do escopo nunca revela se a permissao
    seria concedida."""
    role = ServiceRole(name="deploy", permissions=frozenset({"app.deploy"}))
    key = _api_key(scoped_app_names=["app-a"])

    resultado = resolver_acesso(key, role, "app.deploy", app_name="app-b")
    assert resultado == ResolucaoAcesso.SEM_ESCOPO


def test_resolver_acesso_app_dentro_do_escopo_sem_permissao_retorna_sem_permissao():
    role = ServiceRole(name="somente-leitura", permissions=frozenset({"app.read"}))
    key = _api_key(scoped_app_names=["app-a"])

    resultado = resolver_acesso(key, role, "app.deploy", app_name="app-a")
    assert resultado == ResolucaoAcesso.SEM_PERMISSAO


def test_resolver_acesso_app_dentro_do_escopo_com_permissao_autoriza():
    role = ServiceRole(name="deploy", permissions=frozenset({"app.deploy"}))
    key = _api_key(scoped_app_names=["api-financeira"])

    resultado = resolver_acesso(key, role, "app.deploy", app_name="api-financeira")
    assert resultado == ResolucaoAcesso.AUTORIZADO


def test_resolver_acesso_scope_global_conta_como_dentro_do_escopo():
    role = ServiceRole(name="deploy", permissions=frozenset({"app.deploy"}))
    key = _api_key(scoped_app_names=[])  # [] == todas as aplicacoes

    resultado = resolver_acesso(key, role, "app.deploy", app_name="qualquer-app")
    assert resultado == ResolucaoAcesso.AUTORIZADO


def test_resolver_acesso_permissao_fora_do_contrato_levanta_erro():
    role = ServiceRole(name="deploy", permissions=frozenset({"app.deploy"}))
    key = _api_key()

    with pytest.raises(UnknownPermissionError):
        resolver_acesso(key, role, "app.voar", app_name="app-a")


def test_autorizar_e_resolver_acesso_sao_consistentes():
    """autorizar() deve concordar com resolver_acesso() em todos os
    casos: True se e somente se AUTORIZADO."""
    role = ServiceRole(name="deploy", permissions=frozenset({"app.deploy"}))
    key = _api_key(scoped_app_names=["app-a"])

    casos = [
        ("app.deploy", "app-a"),   # autorizado
        ("app.deploy", "app-b"),   # sem_escopo
        ("app.read", "app-a"),     # sem_permissao
    ]
    for permission, app_name in casos:
        resultado_granular = resolver_acesso(key, role, permission, app_name=app_name)
        resultado_booleano = autorizar(key, role, permission, app_name=app_name)
        assert resultado_booleano == (resultado_granular == ResolucaoAcesso.AUTORIZADO)
