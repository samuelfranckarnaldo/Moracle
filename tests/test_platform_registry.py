import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import shutil
from deploy_platform import registry
from deploy_platform.models import DeploymentStatus


import pytest

pytestmark = pytest.mark.usefixtures("estado_isolado")

def _limpar():
    if os.path.exists(registry.PLATFORM_DIR):
        shutil.rmtree(registry.PLATFORM_DIR)


def test_criar_app_e_recuperar():
    _limpar()
    try:
        registry.criar_ou_obter_app("minha-app", domain="minha-app.local")
        app = registry.obter_app("minha-app")
        assert app.name == "minha-app"
        assert app.domain == "minha-app.local"
    finally:
        _limpar()


def test_criar_deployment_e_listar():
    _limpar()
    try:
        registry.criar_ou_obter_app("minha-app")
        d1 = registry.criar_deployment("minha-app", "/caminho/app")
        d2 = registry.criar_deployment("minha-app", "/caminho/app")

        deployments = registry.listar_deployments_do_app("minha-app")
        ids = {d.deployment_id for d in deployments}
        assert ids == {d1.deployment_id, d2.deployment_id}
    finally:
        _limpar()


def test_promover_deployment_define_current():
    _limpar()
    try:
        registry.criar_ou_obter_app("minha-app")
        d1 = registry.criar_deployment("minha-app", "/caminho/app")
        registry.promover_deployment("minha-app", d1.deployment_id)

        app = registry.obter_app("minha-app")
        assert app.current_deployment_id == d1.deployment_id
    finally:
        _limpar()


def test_rollback_para_deployment_anterior():
    _limpar()
    try:
        registry.criar_ou_obter_app("minha-app")
        d1 = registry.criar_deployment("minha-app", "/caminho/app")
        d2 = registry.criar_deployment("minha-app", "/caminho/app")

        registry.promover_deployment("minha-app", d2.deployment_id)
        app = registry.obter_app("minha-app")
        assert app.current_deployment_id == d2.deployment_id

        registry.promover_deployment("minha-app", d1.deployment_id)
        app = registry.obter_app("minha-app")
        assert app.current_deployment_id == d1.deployment_id

        deployments_restantes = registry.listar_deployments_do_app("minha-app")
        assert len(deployments_restantes) == 2, "rollback nao deveria apagar deployments antigos"
    finally:
        _limpar()


def test_atualizar_status_deployment():
    _limpar()
    try:
        registry.criar_ou_obter_app("minha-app")
        d1 = registry.criar_deployment("minha-app", "/caminho/app")
        registry.atualizar_status_deployment(d1.deployment_id, DeploymentStatus.ACTIVE.value)

        d1_atualizado = registry.obter_deployment(d1.deployment_id)
        assert d1_atualizado.status == DeploymentStatus.ACTIVE.value
    finally:
        _limpar()


def test_app_por_dominio():
    _limpar()
    try:
        registry.criar_ou_obter_app("app-a", domain="a.local")
        registry.criar_ou_obter_app("app-b", domain="b.local")

        encontrado = registry.app_por_dominio("a.local")
        assert encontrado.name == "app-a"

        nao_encontrado = registry.app_por_dominio("nao-existe.local")
        assert nao_encontrado is None
    finally:
        _limpar()
