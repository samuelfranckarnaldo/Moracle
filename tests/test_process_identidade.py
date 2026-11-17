import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import socket
import subprocess
import time

import pytest

from deploy_platform import registry, process_manager as pm
from deploy_platform.application_manager import (
    ApplicationManager, IdentidadeIndeterminadaError, FalhaAoPararProcessoError,
)
from deploy_platform.application_lifecycle import ApplicationState
from deploy_platform.models import ProcessHandle
from deploy_platform.restart_watchdog import RestartWatchdog

MINI_APP = os.path.join(os.path.dirname(__file__), "helpers", "mini_app.py")

pytestmark = pytest.mark.usefixtures("estado_isolado")


def _porta_livre():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    porta = s.getsockname()[1]
    s.close()
    return porta


@pytest.fixture
def pids():
    lista = []
    yield lista
    for pid in lista:
        try:
            pm.parar_processo(pid, timeout_graceful=2)
        except ValueError:
            pass


def _subir(manager, nome, tmp_path, pids, **kw):
    porta = _porta_livre()
    manager.criar_application(
        nome, working_directory=str(tmp_path),
        start_command=[sys.executable, MINI_APP, str(porta)], port=porta, **kw,
    )
    manager.deploy(nome)
    handle = registry.obter_process_handle(registry.obter_app(nome).current_process_handle_id)
    pids.append(handle.pid)
    return handle


def _indeterminada(monkeypatch):
    monkeypatch.setattr(pm, "confirmar_identidade", lambda pid, starttime: None)


# ---------- process_manager ----------

@pytest.mark.parametrize("pid", [0, -1, 1, True, "5", None, 2.5])
def test_pid_invalido_nunca_e_considerado_vivo(pid):
    assert pm.processo_vivo(pid) is False
    assert pm.confirmar_identidade(pid, "123") is False


@pytest.mark.parametrize("pid", [0, -1, 1, True, "5", None])
def test_parar_processo_recusa_pid_invalido_sem_sinalizar(monkeypatch, pid):
    def _nunca(*a, **k):
        raise AssertionError("nenhum sinal deveria ser enviado")
    monkeypatch.setattr(os, "kill", _nunca)
    monkeypatch.setattr(os, "killpg", _nunca)
    with pytest.raises(ValueError):
        pm.parar_processo(pid)


def test_zumbi_de_outro_pai_conta_como_morto():
    helper = subprocess.Popen(
        [sys.executable, "-c",
         "import subprocess, sys, time; p = subprocess.Popen([sys.executable, '-c', 'pass']); "
         "print(p.pid, flush=True); time.sleep(10)"],
        stdout=subprocess.PIPE, text=True,
    )
    try:
        pid = int(helper.stdout.readline())
        time.sleep(0.5)
        assert pm.processo_vivo(pid) is False
    finally:
        helper.kill()
        helper.wait()


def test_parar_processo_encerra_tambem_os_filhos(tmp_path):
    arquivo_filho = tmp_path / "filho.pid"
    script = (
        "import subprocess, sys, time\n"
        "c = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
        f"open({str(arquivo_filho)!r}, 'w').write(str(c.pid))\n"
        "time.sleep(60)\n"
    )
    info = pm.iniciar_processo([sys.executable, "-c", script], str(tmp_path), {},
                               str(tmp_path / "o.log"), str(tmp_path / "e.log"))
    inicio = time.monotonic()
    while not arquivo_filho.exists() or not arquivo_filho.read_text():
        assert time.monotonic() - inicio < 5, "filho nao subiu"
        time.sleep(0.05)
    pid_filho = int(arquivo_filho.read_text())
    try:
        assert pm.parar_processo(info["pid"], timeout_graceful=3) is True
        time.sleep(0.3)
        assert pm.processo_vivo(pid_filho) is False
    finally:
        try:
            os.kill(pid_filho, 9)
        except OSError:
            pass


# ---------- application_manager ----------

def test_parar_com_identidade_indeterminada_nao_sinaliza(tmp_path, monkeypatch, pids):
    manager = ApplicationManager()
    handle = _subir(manager, "app-unk", tmp_path, pids)
    _indeterminada(monkeypatch)
    estado_antes = manager._lifecycle_da_app("app-unk").state

    with pytest.raises(IdentidadeIndeterminadaError):
        manager.parar("app-unk")

    assert pm.processo_vivo(handle.pid) is True
    assert registry.obter_app("app-unk").current_process_handle_id == handle.id
    assert manager._lifecycle_da_app("app-unk").state == estado_antes


def test_parar_forcado_com_identidade_indeterminada_para_o_processo(tmp_path, monkeypatch, pids):
    manager = ApplicationManager()
    handle = _subir(manager, "app-unk2", tmp_path, pids)
    _indeterminada(monkeypatch)

    manager.parar("app-unk2", forcar=True)

    assert pm.processo_vivo(handle.pid) is False
    assert registry.obter_app("app-unk2").current_process_handle_id is None


def test_deploy_com_identidade_indeterminada_nao_cria_segundo_processo(tmp_path, monkeypatch, pids):
    manager = ApplicationManager()
    handle = _subir(manager, "app-dup", tmp_path, pids)
    _indeterminada(monkeypatch)

    with pytest.raises(IdentidadeIndeterminadaError):
        manager.deploy("app-dup")

    assert registry.obter_app("app-dup").current_process_handle_id == handle.id
    assert pm.processo_vivo(handle.pid) is True


def test_parar_que_nao_encerra_mantem_handle_e_levanta(tmp_path, monkeypatch, pids):
    manager = ApplicationManager()
    handle = _subir(manager, "app-teimosa", tmp_path, pids)
    monkeypatch.setattr(pm, "parar_processo", lambda pid, timeout_graceful=10: False)

    with pytest.raises(FalhaAoPararProcessoError):
        manager.parar("app-teimosa")

    assert registry.obter_app("app-teimosa").current_process_handle_id == handle.id


def test_reconciliar_identidade_indeterminada_mantem_handle(tmp_path, monkeypatch, pids):
    manager = ApplicationManager()
    handle = _subir(manager, "app-rec", tmp_path, pids)
    _indeterminada(monkeypatch)

    resultado = manager.reconciliar_no_startup()

    assert resultado[handle.id] == "UNKNOWN"
    assert registry.obter_app("app-rec").current_process_handle_id == handle.id
    assert manager._lifecycle_da_app("app-rec").state is ApplicationState.CRASHED


def test_reconciliar_handle_antigo_morto_nao_derruba_app_saudavel(tmp_path, pids):
    manager = ApplicationManager()
    handle = _subir(manager, "app-hist", tmp_path, pids)
    antigo = ProcessHandle(
        id="proc-antigo", application_id="app-hist", deployment_id="dep-antigo",
        pid=999999, starttime="1", started_at=time.time(),
        stdout_log_path=str(tmp_path / "a.out"), stderr_log_path=str(tmp_path / "a.err"),
    )
    registry.salvar_process_handle(antigo)

    resultado = manager.reconciliar_no_startup()

    assert resultado[handle.id] == "CONFIRMED_RUNNING"
    assert resultado["proc-antigo"] == "CONFIRMED_DEAD"
    assert manager._lifecycle_da_app("app-hist").state is ApplicationState.RUNNING
    assert registry.obter_app("app-hist").current_process_handle_id == handle.id


def test_status_expoe_identidade(tmp_path, monkeypatch, pids):
    manager = ApplicationManager()
    handle = _subir(manager, "app-st", tmp_path, pids)
    assert manager.status("app-st")["identity"] == "CONFIRMED"

    _indeterminada(monkeypatch)
    st = manager.status("app-st")
    assert st["identity"] == "UNKNOWN"
    assert st["pid"] is None
    assert st["unconfirmed_pid"] == handle.pid


# ---------- watchdog ----------

def test_watchdog_nao_reinicia_nem_desanexa_com_identidade_indeterminada(tmp_path, monkeypatch, pids):
    manager = ApplicationManager()
    watchdog = RestartWatchdog(manager, intervalo_verificacao=1)
    handle = _subir(manager, "app-wd", tmp_path, pids, restart_policy_mode="ON_FAILURE")
    _indeterminada(monkeypatch)

    watchdog._verificar_uma_vez("app-wd")

    assert registry.obter_app("app-wd").current_process_handle_id == handle.id
    assert pm.processo_vivo(handle.pid) is True


# ---------- handlers HTTP ----------

def _subir_servidor_admin():
    from admin_api.router import registrar_rotas_admin
    from core.moracle_adapter import build_router
    from core.moracle_middleware import auth_middleware
    from core.api_key import obter_ou_criar
    from core.identity import migrate_legacy_admin_key
    from server.server import Server, ServerConfig
    from core import config as core_config
    import time as _time

    obter_ou_criar()
    migrate_legacy_admin_key(os.path.join(core_config.RAIZ_PROJETO, ".state"))
    porta = _porta_livre()
    router = build_router()
    registrar_rotas_admin(router)
    servidor = Server(ServerConfig(host="127.0.0.1", port=porta, max_workers=5), router, middlewares=[auth_middleware])
    servidor.start(block=False)
    _time.sleep(0.2)
    return servidor, porta


def _http(porta, metodo, path, corpo=None, headers=None, timeout=5):
    import json as _json
    import socket as _socket
    headers = headers or {}
    corpo_bytes = _json.dumps(corpo).encode() if corpo is not None else b""
    linhas = [f"{metodo} {path} HTTP/1.1", "Host: x", "Connection: close"]
    if corpo is not None:
        linhas.append(f"Content-Length: {len(corpo_bytes)}")
        linhas.append("Content-Type: application/json")
    for nome, valor in headers.items():
        linhas.append(f"{nome}: {valor}")
    requisicao = ("\r\n".join(linhas) + "\r\n\r\n").encode() + corpo_bytes
    with _socket.create_connection(("127.0.0.1", porta), timeout=timeout) as sock:
        sock.sendall(requisicao)
        sock.settimeout(timeout)
        resposta = b""
        try:
            while True:
                pedaco = sock.recv(4096)
                if not pedaco:
                    break
                resposta += pedaco
        except _socket.timeout:
            pass
        return resposta


def _admin_headers():
    from core.api_key import obter_ou_criar
    return {"Authorization": f"Bearer {obter_ou_criar()}"}


def test_stop_com_identidade_indeterminada_devolve_409(tmp_path, monkeypatch, pids):
    servidor, porta = _subir_servidor_admin()
    try:
        manager = ApplicationManager()
        handle = _subir(manager, "app-http-unk", tmp_path, pids)
        _indeterminada(monkeypatch)

        r = _http(porta, "POST", "/admin/apps/app-http-unk/stop", headers=_admin_headers())
        assert b" 409 " in r
        assert pm.processo_vivo(handle.pid) is True
    finally:
        servidor.stop()


def test_stop_force_sem_admin_e_ignorado(tmp_path, monkeypatch, pids):
    from core.identity import RoleStore, KeyStore, create_api_key

    servidor, porta = _subir_servidor_admin()
    try:
        manager = ApplicationManager()
        handle = _subir(manager, "app-http-force1", tmp_path, pids)
        _indeterminada(monkeypatch)

        from core import config as core_config
        estado = os.path.join(core_config.RAIZ_PROJETO, ".state")
        role_store = RoleStore(estado)
        role_store.upsert(__import__("core.identity", fromlist=["ServiceRole"]).ServiceRole(name="so-stop", permissions=frozenset({"app.start_stop"})))
        key_store = KeyStore(estado)
        _, token = create_api_key(key_store, "chave-so-stop", "so-stop")

        r = _http(porta, "POST", "/admin/apps/app-http-force1/stop", corpo={"force": True},
                  headers={"Authorization": f"Bearer {token}"})
        assert b" 409 " in r
        assert pm.processo_vivo(handle.pid) is True
    finally:
        servidor.stop()


def test_stop_force_com_admin_para_o_processo(tmp_path, monkeypatch, pids):
    servidor, porta = _subir_servidor_admin()
    try:
        manager = ApplicationManager()
        handle = _subir(manager, "app-http-force2", tmp_path, pids)
        _indeterminada(monkeypatch)

        r = _http(porta, "POST", "/admin/apps/app-http-force2/stop", corpo={"force": True}, headers=_admin_headers())
        assert b" 200 " in r
        assert pm.processo_vivo(handle.pid) is False
    finally:
        servidor.stop()


def test_deploy_com_identidade_indeterminada_devolve_409(tmp_path, monkeypatch, pids):
    servidor, porta = _subir_servidor_admin()
    try:
        manager = ApplicationManager()
        handle = _subir(manager, "app-http-deploy", tmp_path, pids)
        _indeterminada(monkeypatch)

        r = _http(porta, "POST", "/admin/apps/app-http-deploy/deploy", headers=_admin_headers())
        assert b" 409 " in r
        assert registry.obter_app("app-http-deploy").current_process_handle_id == handle.id
    finally:
        servidor.stop()


# ---------- handlers HTTP ----------

def _subir_servidor_admin():
    from admin_api.router import registrar_rotas_admin
    from core.moracle_adapter import build_router
    from core.moracle_middleware import auth_middleware
    from core.api_key import obter_ou_criar
    from core.identity import migrate_legacy_admin_key
    from server.server import Server, ServerConfig
    from core import config as core_config
    import time as _time

    obter_ou_criar()
    migrate_legacy_admin_key(os.path.join(core_config.RAIZ_PROJETO, ".state"))
    porta = _porta_livre()
    router = build_router()
    registrar_rotas_admin(router)
    servidor = Server(ServerConfig(host="127.0.0.1", port=porta, max_workers=5), router, middlewares=[auth_middleware])
    servidor.start(block=False)
    _time.sleep(0.2)
    return servidor, porta


def _http(porta, metodo, path, corpo=None, headers=None, timeout=5):
    import json as _json
    import socket as _socket
    headers = headers or {}
    corpo_bytes = _json.dumps(corpo).encode() if corpo is not None else b""
    linhas = [f"{metodo} {path} HTTP/1.1", "Host: x", "Connection: close"]
    if corpo is not None:
        linhas.append(f"Content-Length: {len(corpo_bytes)}")
        linhas.append("Content-Type: application/json")
    for nome, valor in headers.items():
        linhas.append(f"{nome}: {valor}")
    requisicao = ("\r\n".join(linhas) + "\r\n\r\n").encode() + corpo_bytes
    with _socket.create_connection(("127.0.0.1", porta), timeout=timeout) as sock:
        sock.sendall(requisicao)
        sock.settimeout(timeout)
        resposta = b""
        try:
            while True:
                pedaco = sock.recv(4096)
                if not pedaco:
                    break
                resposta += pedaco
        except _socket.timeout:
            pass
        return resposta


def _admin_headers():
    from core.api_key import obter_ou_criar
    return {"Authorization": f"Bearer {obter_ou_criar()}"}


def test_stop_com_identidade_indeterminada_devolve_409(tmp_path, monkeypatch, pids):
    servidor, porta = _subir_servidor_admin()
    try:
        manager = ApplicationManager()
        handle = _subir(manager, "app-http-unk", tmp_path, pids)
        _indeterminada(monkeypatch)

        r = _http(porta, "POST", "/admin/apps/app-http-unk/stop", headers=_admin_headers())
        assert b" 409 " in r
        assert pm.processo_vivo(handle.pid) is True
    finally:
        servidor.stop()


def test_stop_force_sem_admin_e_ignorado(tmp_path, monkeypatch, pids):
    from core.identity import RoleStore, KeyStore, create_api_key

    servidor, porta = _subir_servidor_admin()
    try:
        manager = ApplicationManager()
        handle = _subir(manager, "app-http-force1", tmp_path, pids)
        _indeterminada(monkeypatch)

        from core import config as core_config
        estado = os.path.join(core_config.RAIZ_PROJETO, ".state")
        role_store = RoleStore(estado)
        role_store.upsert(__import__("core.identity", fromlist=["ServiceRole"]).ServiceRole(name="so-stop", permissions=frozenset({"app.start_stop"})))
        key_store = KeyStore(estado)
        _, token = create_api_key(key_store, "chave-so-stop", "so-stop")

        r = _http(porta, "POST", "/admin/apps/app-http-force1/stop", corpo={"force": True},
                  headers={"Authorization": f"Bearer {token}"})
        assert b" 409 " in r
        assert pm.processo_vivo(handle.pid) is True
    finally:
        servidor.stop()


def test_stop_force_com_admin_para_o_processo(tmp_path, monkeypatch, pids):
    servidor, porta = _subir_servidor_admin()
    try:
        manager = ApplicationManager()
        handle = _subir(manager, "app-http-force2", tmp_path, pids)
        _indeterminada(monkeypatch)

        r = _http(porta, "POST", "/admin/apps/app-http-force2/stop", corpo={"force": True}, headers=_admin_headers())
        assert b" 200 " in r
        assert pm.processo_vivo(handle.pid) is False
    finally:
        servidor.stop()


def test_deploy_com_identidade_indeterminada_devolve_409(tmp_path, monkeypatch, pids):
    servidor, porta = _subir_servidor_admin()
    try:
        manager = ApplicationManager()
        handle = _subir(manager, "app-http-deploy", tmp_path, pids)
        _indeterminada(monkeypatch)

        r = _http(porta, "POST", "/admin/apps/app-http-deploy/deploy", headers=_admin_headers())
        assert b" 409 " in r
        assert registry.obter_app("app-http-deploy").current_process_handle_id == handle.id
    finally:
        servidor.stop()
