"""
Gerencia processos de sistema operacional para Applications do
Moracle. Nunca usa shell=True - start_command e' sempre lista de
argumentos, subprocess.Popen recebe a lista diretamente.

Identidade do processo e' confirmada via PID + starttime lido de
/proc/<pid>/stat (campo 22 - ticks de CPU desde o boot). Isso evita o
problema classico de reuso de PID. Limitacao documentada: essa
tecnica depende de /proc (Linux); em outro SO, confirmar_identidade()
retorna None (identidade nao confirmavel) e quem chama deve tratar
isso como UNKNOWN, nunca como RUNNING.
"""
import os
import signal
import subprocess
import time


def _pid_valido(pid):
    """Somente inteiros > 1: 0 e negativos sinalizam grupos inteiros de
    processos (kill(0)/kill(-1)) e 1 e' o init."""
    return isinstance(pid, int) and not isinstance(pid, bool) and pid > 1


def _ler_stat_proc(pid):
    """Retorna (estado, starttime) de /proc/<pid>/stat, ou (None, None)."""
    try:
        with open(f"/proc/{pid}/stat") as f:
            conteudo = f.read()
        campos = conteudo.rsplit(")", 1)[1].split()
        return campos[0], campos[19]
    except (OSError, IndexError, ValueError):
        return None, None


def _ler_starttime_proc(pid):
    return _ler_stat_proc(pid)[1]


def processo_vivo(pid):
    """Verifica se o processo ainda esta rodando de verdade - nao
    apenas presente na tabela de processos. Um filho que terminou mas
    nao foi 'reaped' (via waitpid) vira zumbi: kill(pid, 0) ainda
    retorna sucesso para um zumbi, entao precisamos tentar reap-lo
    primeiro (WNOHANG - nao bloqueia se ainda estiver rodando)."""
    if not _pid_valido(pid):
        return False

    try:
        pid_colhido, _status = os.waitpid(pid, os.WNOHANG)
        if pid_colhido == pid:
            return False
    except ChildProcessError:
        pass

    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    # zumbi de outro pai: kill(pid, 0) tem sucesso, mas o processo ja morreu
    return _ler_stat_proc(pid)[0] != "Z"


def confirmar_identidade(pid, starttime_esperado):
    if not processo_vivo(pid):
        return False
    starttime_atual = _ler_starttime_proc(pid)
    if starttime_atual is None or starttime_esperado is None:
        return None
    return starttime_atual == starttime_esperado


def iniciar_processo(start_command, working_directory, environment, stdout_path, stderr_path):
    if not isinstance(start_command, list) or not start_command:
        raise ValueError("start_command deve ser uma lista de argumentos nao vazia")

    ambiente_completo = dict(os.environ)
    ambiente_completo.update(environment or {})

    os.makedirs(os.path.dirname(os.path.abspath(stdout_path)), exist_ok=True)
    os.makedirs(os.path.dirname(os.path.abspath(stderr_path)), exist_ok=True)

    stdout_arquivo = open(stdout_path, "ab")
    stderr_arquivo = open(stderr_path, "ab")

    try:
        processo = subprocess.Popen(
            start_command,
            cwd=working_directory,
            env=ambiente_completo,
            stdout=stdout_arquivo,
            stderr=stderr_arquivo,
            shell=False,
            start_new_session=True,
        )
    finally:
        stdout_arquivo.close()
        stderr_arquivo.close()

    time.sleep(0.1)
    starttime = _ler_starttime_proc(processo.pid)

    return {"pid": processo.pid, "starttime": starttime}


def _sinalizar(pid, sinal):
    """Sinaliza o grupo quando pid e' lider do proprio grupo
    (start_new_session=True), para nao deixar filhos orfaos; senao, so o pid."""
    if os.getpgid(pid) == pid:
        os.killpg(pid, sinal)
    else:
        os.kill(pid, sinal)


def parar_processo(pid, timeout_graceful=10):
    if not _pid_valido(pid):
        raise ValueError(f"pid invalido: {pid!r}")
    if not processo_vivo(pid):
        return True

    try:
        _sinalizar(pid, signal.SIGTERM)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False

    inicio = time.monotonic()
    while time.monotonic() - inicio < timeout_graceful:
        if not processo_vivo(pid):
            return True
        time.sleep(0.1)

    try:
        _sinalizar(pid, signal.SIGKILL)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False

    inicio = time.monotonic()
    while time.monotonic() - inicio < 3:
        if not processo_vivo(pid):
            return True
        time.sleep(0.1)

    return not processo_vivo(pid)
