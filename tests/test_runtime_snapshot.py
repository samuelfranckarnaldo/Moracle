import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import shutil
import socket
import time

from deploy_platform.application_manager import ApplicationManager
from deploy_platform import registry
from deploy_platform.models import Deployment, RuntimeSnapshot, DeploymentStatus

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


def test_deployment_from_dict_without_runtime_snapshot_still_loads():
    """Compatibilidade retroativa: JSON persistido antes do
    RuntimeSnapshot existir precisa continuar carregando."""
    dados_antigos = {
        "app_name": "app-velha", "deployment_id": "dep-1", "created_at": 123.0,
        "status": "active", "source_path": "/x", "health_check_path": "/health",
    }
    deployment = Deployment.from_dict(dados_antigos)
    assert deployment.runtime_snapshot is None
    assert deployment.get_runtime_snapshot() is None


def test_runtime_snapshot_serialization_roundtrip():
    snapshot = RuntimeSnapshot(
        working_directory="/app", start_command=["node", "server.js"],
        environment={"PORT": "8000"}, port=8000, health_check_path="/health",
    )
    dados = snapshot.to_dict()
    recuperado = RuntimeSnapshot.from_dict(dados)
    assert recuperado.working_directory == "/app"
    assert recuperado.start_command == ["node", "server.js"]
    assert recuperado.environment == {"PORT": "8000"}


def test_deploy_stores_snapshot_matching_app_config_at_the_time():
    _limpar()
    manager = ApplicationManager()
    try:
        porta = _porta_livre()
        manager.criar_application(
            "app-snap", working_directory=TMPDIR,
            start_command=[sys.executable, MINI_APP, str(porta)], port=porta,
        )
        deployment = manager.deploy("app-snap")

        snapshot = deployment.get_runtime_snapshot()
        assert snapshot is not None
        assert snapshot.start_command == [sys.executable, MINI_APP, str(porta)]
        assert snapshot.port == porta
    finally:
        manager.parar("app-snap") if registry.obter_app("app-snap") else None
        _limpar()


def test_rollback_uses_old_snapshot_not_current_app_config():
    """O teste central desta correcao: dia 1 -> deploy v1. dia 2 ->
    muda a Application para v2 e faz deploy. dia 3 -> rollback pro
    deployment do dia 1. O processo que sobe DEVE rodar o comando do
    dia 1, mesmo com a Application ja configurada para v2."""
    _limpar()
    manager = ApplicationManager()
    try:
        porta_v1 = _porta_livre()
        manager.criar_application(
            "app-versionada", working_directory=TMPDIR,
            start_command=[sys.executable, MINI_APP, str(porta_v1)], port=porta_v1,
        )
        deployment_v1 = manager.deploy("app-versionada")
        assert deployment_v1.status == DeploymentStatus.ACTIVE.value
        snapshot_v1 = deployment_v1.get_runtime_snapshot()
        assert snapshot_v1.port == porta_v1

        # dia 2: muda a Application para uma "v2" com porta diferente
        porta_v2 = _porta_livre()
        app = registry.obter_app("app-versionada")
        app.start_command = [sys.executable, MINI_APP, str(porta_v2)]
        app.port = porta_v2
        registry.salvar_application_completa(app)

        deployment_v2 = manager.deploy("app-versionada", health_check_tentativas=6)
        assert deployment_v2.status == DeploymentStatus.ACTIVE.value, (
            f"deploy v2 falhou: {deployment_v2.error_message}"
        )
        snapshot_v2 = deployment_v2.get_runtime_snapshot()
        assert snapshot_v2.port == porta_v2
        assert snapshot_v2.port != snapshot_v1.port

        # dia 3: rollback pro deployment do dia 1 - precisa religar na porta v1,
        # NAO na porta v2 que e' a config atual da Application
        deployment_rollback = manager.rollback("app-versionada", deployment_v1.deployment_id)
        assert deployment_rollback.status == DeploymentStatus.ACTIVE.value

        app_final = registry.obter_app("app-versionada")
        handle_final = registry.obter_process_handle(app_final.current_process_handle_id)

        # confirma que o processo ativo agora e' o da v1, respondendo na porta v1
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", porta_v1, timeout=3)
        conn.request("GET", "/health")
        resp = conn.getresponse()
        assert resp.status == 200, "rollback deveria ter religado na porta/comando do deployment v1, nao v2"
        conn.close()
    finally:
        manager.parar("app-versionada") if registry.obter_app("app-versionada") else None
        _limpar()


def test_rollback_legacy_deployment_without_snapshot_falls_back_to_app_config():
    """Deployment criado antes do RuntimeSnapshot existir (sem
    snapshot persistido) - rollback deve funcionar via fallback pra
    config atual da Application, sem quebrar."""
    _limpar()
    manager = ApplicationManager()
    try:
        porta = _porta_livre()
        manager.criar_application(
            "app-legado", working_directory=TMPDIR,
            start_command=[sys.executable, MINI_APP, str(porta)], port=porta,
        )
        app = registry.obter_app("app-legado")

        # simula um deployment "antigo" sem runtime_snapshot
        deployment_legado = registry.criar_deployment("app-legado", TMPDIR, "/health")
        registry.atualizar_status_deployment(deployment_legado.deployment_id, DeploymentStatus.ACTIVE.value)
        registry.promover_deployment("app-legado", deployment_legado.deployment_id)

        assert registry.obter_deployment(deployment_legado.deployment_id).runtime_snapshot is None

        resultado = manager.rollback("app-legado", deployment_legado.deployment_id)
        assert resultado.status == DeploymentStatus.ACTIVE.value
    finally:
        manager.parar("app-legado") if registry.obter_app("app-legado") else None
        _limpar()
