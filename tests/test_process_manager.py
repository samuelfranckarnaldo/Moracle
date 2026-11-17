import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
import socket


def _esperar_arquivo_ter_conteudo(caminho, timeout=5):
    inicio = time.monotonic()
    while time.monotonic() - inicio < timeout:
        if os.path.exists(caminho) and os.path.getsize(caminho) > 0:
            return True
        time.sleep(0.05)
    return False
from unittest.mock import patch, MagicMock

from deploy_platform import process_manager as pm

MINI_APP = os.path.join(os.path.dirname(__file__), "helpers", "mini_app.py")


def _porta_livre():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    porta = s.getsockname()[1]
    s.close()
    return porta


def test_start_command_must_be_a_list():
    try:
        pm.iniciar_processo("nao-e-lista", "/data/data/com.termux/files/home/moracle_test_tmp", {}, "/data/data/com.termux/files/home/moracle_test_tmp/out.log", "/data/data/com.termux/files/home/moracle_test_tmp/err.log")
        assert False, "deveria ter levantado ValueError"
    except ValueError:
        pass


def test_popen_called_with_shell_false_and_list_args():
    with patch("deploy_platform.process_manager.subprocess.Popen") as mock_popen:
        mock_processo = MagicMock()
        mock_processo.pid = 999999
        mock_popen.return_value = mock_processo
        pm.iniciar_processo(["echo", "oi"], "/data/data/com.termux/files/home/moracle_test_tmp", {}, "/data/data/com.termux/files/home/moracle_test_tmp/out.log", "/data/data/com.termux/files/home/moracle_test_tmp/err.log")

        args, kwargs = mock_popen.call_args
        assert args[0] == ["echo", "oi"]
        assert kwargs["shell"] is False
        assert kwargs["cwd"] == "/data/data/com.termux/files/home/moracle_test_tmp"


def test_environment_merged_with_parent_and_explicit_vars():
    porta = _porta_livre()
    caminho_out = f"/data/data/com.termux/files/home/moracle_test_tmp/moracle_test_env_{porta}.out"
    if os.path.exists(caminho_out):
        os.remove(caminho_out)

    script = "import os,sys; sys.stdout.write(os.environ.get('MORACLE_TEST_VAR','ausente'))"
    info = pm.iniciar_processo(
        [sys.executable, "-c", script], "/data/data/com.termux/files/home/moracle_test_tmp", {"MORACLE_TEST_VAR": "presente"},
        caminho_out, "/data/data/com.termux/files/home/moracle_test_tmp/moracle_test_env_err.log",
    )
    assert _esperar_arquivo_ter_conteudo(caminho_out), "processo nao escreveu output a tempo"
    pm.parar_processo(info["pid"], timeout_graceful=2)

    with open(caminho_out) as f:
        conteudo_lido = f.read()
    assert conteudo_lido == "presente"


def test_start_and_stop_real_process():
    porta = _porta_livre()
    caminho_out = f"/data/data/com.termux/files/home/moracle_test_tmp/moracle_test_start_{porta}.out"
    info = pm.iniciar_processo(
        [sys.executable, MINI_APP, str(porta)], "/data/data/com.termux/files/home/moracle_test_tmp", {},
        caminho_out, "/data/data/com.termux/files/home/moracle_test_tmp/moracle_test_start_err.log",
    )
    time.sleep(0.5)

    assert pm.processo_vivo(info["pid"]) is True
    assert info["starttime"] is not None

    parado = pm.parar_processo(info["pid"], timeout_graceful=3)
    assert parado is True
    assert pm.processo_vivo(info["pid"]) is False


def test_processo_vivo_false_for_nonexistent_pid():
    assert pm.processo_vivo(999999) is False


def test_confirmar_identidade_true_for_running_process():
    porta = _porta_livre()
    caminho_out = f"/data/data/com.termux/files/home/moracle_test_tmp/moracle_test_id_{porta}.out"
    info = pm.iniciar_processo(
        [sys.executable, MINI_APP, str(porta)], "/data/data/com.termux/files/home/moracle_test_tmp", {},
        caminho_out, "/data/data/com.termux/files/home/moracle_test_tmp/moracle_test_id_err.log",
    )
    time.sleep(0.3)
    try:
        assert pm.confirmar_identidade(info["pid"], info["starttime"]) is True
    finally:
        pm.parar_processo(info["pid"], timeout_graceful=2)


def test_confirmar_identidade_false_after_process_stopped():
    porta = _porta_livre()
    caminho_out = f"/data/data/com.termux/files/home/moracle_test_tmp/moracle_test_id2_{porta}.out"
    info = pm.iniciar_processo(
        [sys.executable, MINI_APP, str(porta)], "/data/data/com.termux/files/home/moracle_test_tmp", {},
        caminho_out, "/data/data/com.termux/files/home/moracle_test_tmp/moracle_test_id2_err.log",
    )
    time.sleep(0.3)
    pm.parar_processo(info["pid"], timeout_graceful=3)
    assert pm.confirmar_identidade(info["pid"], info["starttime"]) is False


def test_confirmar_identidade_false_when_starttime_mismatches_different_process():
    porta_a = _porta_livre()
    porta_b = _porta_livre()
    info_a = pm.iniciar_processo(
        [sys.executable, MINI_APP, str(porta_a)], "/data/data/com.termux/files/home/moracle_test_tmp", {},
        f"/data/data/com.termux/files/home/moracle_test_tmp/moracle_test_a_{porta_a}.out", "/data/data/com.termux/files/home/moracle_test_tmp/moracle_test_a_err.log",
    )
    time.sleep(0.2)
    info_b = pm.iniciar_processo(
        [sys.executable, MINI_APP, str(porta_b)], "/data/data/com.termux/files/home/moracle_test_tmp", {},
        f"/data/data/com.termux/files/home/moracle_test_tmp/moracle_test_b_{porta_b}.out", "/data/data/com.termux/files/home/moracle_test_tmp/moracle_test_b_err.log",
    )
    time.sleep(0.2)
    try:
        resultado = pm.confirmar_identidade(info_b["pid"], info_a["starttime"])
        assert resultado is False
    finally:
        pm.parar_processo(info_a["pid"], timeout_graceful=2)
        pm.parar_processo(info_b["pid"], timeout_graceful=2)
