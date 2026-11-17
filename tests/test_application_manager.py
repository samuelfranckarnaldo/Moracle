import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import shutil
import socket
import threading
import time

from deploy_platform.application_manager import ApplicationManager, ApplicationManagerError
from deploy_platform import registry
from deploy_platform.models import ProcessHandle, DeploymentStatus
from deploy_platform.application_lifecycle import ApplicationState
from deploy_platform import process_manager as pm

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


def test_deploy_success_starts_process_and_promotes():
    _limpar()
    manager = ApplicationManager()
    try:
        porta = _porta_livre()
        manager.criar_application(
            "app-teste", working_directory=TMPDIR,
            start_command=[sys.executable, MINI_APP, str(porta)], port=porta,
        )
        deployment = manager.deploy("app-teste")

        assert deployment.status == DeploymentStatus.ACTIVE.value

        status = manager.status("app-teste")
        assert status["pid"] is not None
        assert status["lifecycle_state"] == ApplicationState.HEALTHY.name
    finally:
        manager.parar("app-teste") if registry.obter_app("app-teste") else None
        _limpar()


def test_deploy_failure_keeps_previous_deployment_for_rollback():
    _limpar()
    manager = ApplicationManager()
    try:
        porta = _porta_livre()
        manager.criar_application(
            "app-teste", working_directory=TMPDIR,
            start_command=[sys.executable, MINI_APP, str(porta)], port=porta,
        )
        d1 = manager.deploy("app-teste")
        assert d1.status == DeploymentStatus.ACTIVE.value

        # segundo deploy aponta pra porta errada -> health check falha
        app = registry.obter_app("app-teste")
        app.port = _porta_livre()  # porta sem nada escutando
        registry.salvar_application_completa(app)

        d2 = manager.deploy("app-teste")
        assert d2.status == DeploymentStatus.FAILED.value

        app_final = registry.obter_app("app-teste")
        assert app_final.current_deployment_id == d1.deployment_id, (
            "deployment anterior deveria continuar CURRENT apos falha do novo"
        )
    finally:
        manager.parar("app-teste") if registry.obter_app("app-teste") else None
        _limpar()


def test_never_two_processes_simultaneously():
    """Chama deploy() duas vezes em sequencia rapida - o processo
    anterior deve estar parado antes do novo iniciar. Confirma
    verificando que so existe 1 PID vivo referenciado pela app ao
    final."""
    _limpar()
    manager = ApplicationManager()
    try:
        porta1 = _porta_livre()
        manager.criar_application(
            "app-unica", working_directory=TMPDIR,
            start_command=[sys.executable, MINI_APP, str(porta1)], port=porta1,
        )
        d1 = manager.deploy("app-unica")
        handle1 = registry.obter_process_handle(
            registry.obter_deployment(d1.deployment_id).process_handle_id
        )
        pid1 = handle1.pid
        assert pm.processo_vivo(pid1) is True

        porta2 = _porta_livre()
        app = registry.obter_app("app-unica")
        app.start_command = [sys.executable, MINI_APP, str(porta2)]
        app.port = porta2
        registry.salvar_application_completa(app)

        d2 = manager.deploy("app-unica")
        assert d2.status == DeploymentStatus.ACTIVE.value

        assert pm.processo_vivo(pid1) is False, "processo antigo deveria ter sido parado"

        handle2 = registry.obter_process_handle(
            registry.obter_deployment(d2.deployment_id).process_handle_id
        )
        assert pm.processo_vivo(handle2.pid) is True
    finally:
        manager.parar("app-unica") if registry.obter_app("app-unica") else None
        _limpar()


def test_rollback_starts_new_process_not_reuses_old_handle():
    _limpar()
    manager = ApplicationManager()
    try:
        porta = _porta_livre()
        manager.criar_application(
            "app-rollback", working_directory=TMPDIR,
            start_command=[sys.executable, MINI_APP, str(porta)], port=porta,
        )
        d1 = manager.deploy("app-rollback")
        handle1_id = registry.obter_deployment(d1.deployment_id).process_handle_id

        d2 = manager.deploy("app-rollback")  # mesmo comando, novo deployment
        handle2_id = registry.obter_deployment(d2.deployment_id).process_handle_id
        assert handle2_id != handle1_id

        d3 = manager.rollback("app-rollback", d1.deployment_id)
        assert d3.status == DeploymentStatus.ACTIVE.value

        handle3_id = registry.obter_deployment(d1.deployment_id).process_handle_id
        assert handle3_id != handle1_id, "rollback deveria criar um NOVO ProcessHandle, nao reusar o antigo"

        app_final = registry.obter_app("app-rollback")
        assert app_final.current_deployment_id == d1.deployment_id
    finally:
        manager.parar("app-rollback") if registry.obter_app("app-rollback") else None
        _limpar()


def test_stop_terminates_real_process():
    _limpar()
    manager = ApplicationManager()
    try:
        porta = _porta_livre()
        manager.criar_application(
            "app-stop", working_directory=TMPDIR,
            start_command=[sys.executable, MINI_APP, str(porta)], port=porta,
        )
        manager.deploy("app-stop")
        status_antes = manager.status("app-stop")
        pid = status_antes["pid"]
        assert pm.processo_vivo(pid) is True

        manager.parar("app-stop")
        assert pm.processo_vivo(pid) is False

        status_depois = manager.status("app-stop")
        assert status_depois["pid"] is None
        assert status_depois["lifecycle_state"] == ApplicationState.STOPPED.name
    finally:
        _limpar()


def test_logs_captures_stdout():
    _limpar()
    manager = ApplicationManager()
    try:
        porta = _porta_livre()
        manager.criar_application(
            "app-logs", working_directory=TMPDIR,
            start_command=[sys.executable, MINI_APP, str(porta)], port=porta,
        )
        manager.deploy("app-logs")
        time.sleep(0.3)

        logs = manager.logs("app-logs")
        assert "stdout" in logs
        assert "stderr" in logs
    finally:
        manager.parar("app-logs") if registry.obter_app("app-logs") else None
        _limpar()


def test_reconcile_confirms_running_process():
    _limpar()
    manager = ApplicationManager()
    try:
        porta = _porta_livre()
        manager.criar_application(
            "app-reconcile", working_directory=TMPDIR,
            start_command=[sys.executable, MINI_APP, str(porta)], port=porta,
        )
        manager.deploy("app-reconcile")

        novo_manager = ApplicationManager()
        resultado = novo_manager.reconciliar_no_startup()

        assert "CONFIRMED_RUNNING" in resultado.values()
    finally:
        manager.parar("app-reconcile") if registry.obter_app("app-reconcile") else None
        _limpar()


def test_reconcile_detects_dead_process_via_stale_handle():
    """Simula um Moracle que reiniciou depois do processo real ter
    morrido: cria um ProcessHandle apontando pra um PID que nao
    existe mais, confirma que reconcile marca como CONFIRMED_DEAD e
    nao como RUNNING."""
    _limpar()
    manager = ApplicationManager()
    try:
        manager.criar_application(
            "app-morta", working_directory=TMPDIR,
            start_command=[sys.executable, MINI_APP, "9999"], port=9999,
        )
        handle_falso = ProcessHandle(
            id="proc-falso", application_id="app-morta", deployment_id="dep-falso",
            pid=999999, starttime="12345", started_at=time.time(),
            stdout_log_path="/dev/null", stderr_log_path="/dev/null",
        )
        registry.salvar_process_handle(handle_falso)
        registry.atualizar_processo_atual_da_app("app-morta", "proc-falso")

        resultado = manager.reconciliar_no_startup()
        assert resultado["proc-falso"] == "CONFIRMED_DEAD"

        app = registry.obter_app("app-morta")
        assert app.current_process_handle_id is None, "handle morto deveria ser limpo da app"
    finally:
        _limpar()


def test_concurrent_deploy_calls_never_produce_two_live_processes():
    """Regra critica: mesmo sob chamadas concorrentes de deploy() na
    MESMA Application, nunca deve haver 2 processos vivos ao mesmo
    tempo - o lock por Application deve serializar isso."""
    _limpar()
    manager = ApplicationManager()
    try:
        porta = _porta_livre()
        manager.criar_application(
            "app-concorrente", working_directory=TMPDIR,
            start_command=[sys.executable, MINI_APP, str(porta)], port=porta,
        )

        erros = []

        def disparar_deploy():
            try:
                manager.deploy("app-concorrente")
            except Exception as e:
                erros.append(e)

        threads = [threading.Thread(target=disparar_deploy) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        assert not erros, f"erros durante deploy concorrente: {erros}"

        todos_handles = registry.listar_process_handles()
        pids_vivos = [h.pid for h in todos_handles if pm.processo_vivo(h.pid)]
        assert len(pids_vivos) <= 1, f"esperado no maximo 1 processo vivo, achou {len(pids_vivos)}"
    finally:
        manager.parar("app-concorrente") if registry.obter_app("app-concorrente") else None
        _limpar()
