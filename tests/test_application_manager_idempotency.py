import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import shutil
import socket

from deploy_platform.application_manager import ApplicationManager
from deploy_platform import registry, process_manager as pm
from deploy_platform.application_lifecycle import ApplicationState

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


def test_stop_twice_is_idempotent():
    _limpar()
    manager = ApplicationManager()
    try:
        porta = _porta_livre()
        manager.criar_application(
            "app-idempotente", working_directory=TMPDIR,
            start_command=[sys.executable, MINI_APP, str(porta)], port=porta,
        )
        manager.deploy("app-idempotente")

        manager.parar("app-idempotente")  # primeira parada
        status1 = manager.status("app-idempotente")
        assert status1["lifecycle_state"] == ApplicationState.STOPPED.name

        manager.parar("app-idempotente")  # segunda parada - nao deve levantar erro
        status2 = manager.status("app-idempotente")
        assert status2["lifecycle_state"] == ApplicationState.STOPPED.name
    finally:
        _limpar()


def test_deploy_then_rollback_then_restart_leave_no_orphan_processes():
    _limpar()
    manager = ApplicationManager()
    try:
        porta1 = _porta_livre()
        manager.criar_application(
            "app-sem-orfao", working_directory=TMPDIR,
            start_command=[sys.executable, MINI_APP, str(porta1)], port=porta1,
        )
        d1 = manager.deploy("app-sem-orfao")

        porta2 = _porta_livre()
        app = registry.obter_app("app-sem-orfao")
        app.start_command = [sys.executable, MINI_APP, str(porta2)]
        app.port = porta2
        registry.salvar_application_completa(app)
        d2 = manager.deploy("app-sem-orfao")

        manager.rollback("app-sem-orfao", d1.deployment_id)
        manager.reiniciar("app-sem-orfao")

        todos_handles = registry.listar_process_handles()
        pids_vivos = [h.pid for h in todos_handles if pm.processo_vivo(h.pid)]
        assert len(pids_vivos) <= 1, f"esperado no maximo 1 processo vivo ao final, achou {len(pids_vivos)}"
    finally:
        manager.parar("app-sem-orfao") if registry.obter_app("app-sem-orfao") else None
        _limpar()
