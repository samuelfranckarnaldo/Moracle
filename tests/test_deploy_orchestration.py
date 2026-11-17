import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import shutil
import socket
import time

from server.server import Server, ServerConfig
from server.router import Router
from server.response import Response
from deploy_platform import registry, deploy as deploy_mod
from deploy_platform.models import DeploymentStatus
from deploy_platform.host_router import HostRouter


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


def test_deploy_success_promotes_to_active():
    _limpar()
    router_app = Router()
    router_app.add_route("GET", "/health", lambda req, ctx: Response.json({"status": "ok"}))
    porta = _porta_livre()
    config = ServerConfig(host="127.0.0.1", port=porta, max_workers=5)
    servidor = Server(config, router_app)
    servidor.start(block=False)
    time.sleep(0.2)

    try:
        host_router = HostRouter()
        resultado = deploy_mod.deploy(
            app_name="minha-app",
            source_path="/caminho/fake",
            health_check_base_url=f"http://127.0.0.1:{porta}",
            domain="minha-app.local",
            host_router=host_router,
            router=router_app,
        )

        assert resultado.status == DeploymentStatus.ACTIVE.value

        app = registry.obter_app("minha-app")
        assert app.current_deployment_id == resultado.deployment_id

        assert host_router.resolver_router("minha-app.local") is router_app
    finally:
        servidor.stop()
        _limpar()


def test_deploy_failure_marks_failed_and_does_not_promote():
    _limpar()
    try:
        porta_sem_servidor = _porta_livre()
        resultado = deploy_mod.deploy(
            app_name="app-quebrada",
            source_path="/caminho/fake",
            health_check_base_url=f"http://127.0.0.1:{porta_sem_servidor}",
            health_check_tentativas=1,
        )

        assert resultado.status == DeploymentStatus.FAILED.value
        assert resultado.error_message

        app = registry.obter_app("app-quebrada")
        assert app.current_deployment_id is None
    finally:
        _limpar()


def test_deploy_invalid_config_raises_before_creating_deployment():
    _limpar()
    try:
        try:
            deploy_mod.deploy(app_name="", source_path="/x", health_check_base_url="http://x")
            assert False, "deveria ter levantado DeployError"
        except deploy_mod.DeployError:
            pass

        app = registry.obter_app("")
        assert app is None, "nao deveria ter criado app com config invalida"
    finally:
        _limpar()


def test_rollback_promotes_previous_deployment_without_health_check():
    _limpar()
    router_v1 = Router()
    router_v1.add_route("GET", "/health", lambda req, ctx: Response.json({"status": "ok"}))
    porta1 = _porta_livre()
    config1 = ServerConfig(host="127.0.0.1", port=porta1, max_workers=5)
    servidor1 = Server(config1, router_v1)
    servidor1.start(block=False)
    time.sleep(0.2)

    try:
        host_router = HostRouter()
        d1 = deploy_mod.deploy(
            app_name="minha-app", source_path="/v1",
            health_check_base_url=f"http://127.0.0.1:{porta1}",
            domain="minha-app.local", host_router=host_router, router=router_v1,
        )
        assert d1.status == DeploymentStatus.ACTIVE.value

        d2 = registry.criar_deployment("minha-app", "/v2")
        registry.atualizar_status_deployment(d2.deployment_id, DeploymentStatus.ACTIVE.value)
        registry.promover_deployment("minha-app", d2.deployment_id)

        app = registry.obter_app("minha-app")
        assert app.current_deployment_id == d2.deployment_id

        deploy_mod.rollback("minha-app", d1.deployment_id, host_router=host_router, router=router_v1)

        app = registry.obter_app("minha-app")
        assert app.current_deployment_id == d1.deployment_id
        assert host_router.resolver_router("minha-app.local") is router_v1
    finally:
        servidor1.stop()
        _limpar()
