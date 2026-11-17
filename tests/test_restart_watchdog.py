import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import shutil
import socket
import time

from deploy_platform.application_manager import ApplicationManager
from deploy_platform.restart_watchdog import RestartWatchdog
from deploy_platform import registry, process_manager as pm

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


def test_never_policy_does_not_restart_on_crash():
    _limpar()
    manager = ApplicationManager()
    watchdog = RestartWatchdog(manager, intervalo_verificacao=1)
    try:
        porta = _porta_livre()
        manager.criar_application(
            "app-never", working_directory=TMPDIR,
            start_command=[sys.executable, MINI_APP, str(porta)], port=porta,
            restart_policy_mode="NEVER",
        )
        manager.deploy("app-never")
        status_antes = manager.status("app-never")
        pid = status_antes["pid"]

        pm.parar_processo(pid, timeout_graceful=3)
        watchdog.verificar_todas_uma_vez()

        app = registry.obter_app("app-never")
        assert app.current_process_handle_id is None, "NEVER nao deveria reiniciar"
    finally:
        _limpar()


def test_on_failure_policy_restarts_after_crash():
    _limpar()
    manager = ApplicationManager()
    watchdog = RestartWatchdog(manager, intervalo_verificacao=1)
    try:
        porta = _porta_livre()
        manager.criar_application(
            "app-restart", working_directory=TMPDIR,
            start_command=[sys.executable, MINI_APP, str(porta)], port=porta,
            restart_policy_mode="ON_FAILURE", restart_policy_backoff_seconds=0.2,
        )
        manager.deploy("app-restart")
        status_antes = manager.status("app-restart")
        pid_antigo = status_antes["pid"]

        pm.parar_processo(pid_antigo, timeout_graceful=3)
        watchdog._verificar_uma_vez("app-restart")

        app = registry.obter_app("app-restart")
        assert app.current_process_handle_id is not None, "ON_FAILURE deveria ter reiniciado"

        novo_handle = registry.obter_process_handle(app.current_process_handle_id)
        assert novo_handle.pid != pid_antigo
        assert pm.processo_vivo(novo_handle.pid) is True
    finally:
        manager.parar("app-restart") if registry.obter_app("app-restart") else None
        _limpar()


def test_respects_max_retries():
    """Aplicacao que sempre crasha imediatamente (start_command
    invalido) - watchdog deve parar de tentar apos max_retries."""
    _limpar()
    manager = ApplicationManager()
    watchdog = RestartWatchdog(manager, intervalo_verificacao=1)
    try:
        manager.criar_application(
            "app-flaky", working_directory=TMPDIR,
            start_command=[sys.executable, "-c", "import sys; sys.exit(1)"],
            port=_porta_livre(),
            restart_policy_mode="ON_FAILURE", restart_policy_max_retries=2,
            restart_policy_backoff_seconds=0.1,
        )
        try:
            manager.deploy("app-flaky")
        except Exception:
            pass  # deploy inicial provavelmente falha no health check, esperado

        for _ in range(5):
            watchdog._verificar_uma_vez("app-flaky")
            time.sleep(0.1)

        assert watchdog._tentativas_por_app.get("app-flaky", 0) <= 2
    finally:
        _limpar()


def test_healthy_process_resets_retry_counter():
    _limpar()
    manager = ApplicationManager()
    watchdog = RestartWatchdog(manager, intervalo_verificacao=1)
    try:
        porta = _porta_livre()
        manager.criar_application(
            "app-saudavel", working_directory=TMPDIR,
            start_command=[sys.executable, MINI_APP, str(porta)], port=porta,
            restart_policy_mode="ON_FAILURE",
        )
        manager.deploy("app-saudavel")
        watchdog._tentativas_por_app["app-saudavel"] = 3  # simula tentativas anteriores

        watchdog._verificar_uma_vez("app-saudavel")

        assert watchdog._tentativas_por_app["app-saudavel"] == 0
    finally:
        manager.parar("app-saudavel") if registry.obter_app("app-saudavel") else None
        _limpar()


def test_watchdog_start_stop_lifecycle():
    _limpar()
    manager = ApplicationManager()
    watchdog = RestartWatchdog(manager, intervalo_verificacao=1)
    try:
        watchdog.iniciar()
        time.sleep(0.3)
        assert watchdog._thread.is_alive()
        watchdog.parar()
        time.sleep(0.2)
        assert not watchdog._thread.is_alive()
    finally:
        _limpar()
