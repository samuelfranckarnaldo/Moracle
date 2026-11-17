"""
Estado compartilhado com atomicidade real - lock de arquivo (fcntl)
+ escrita atomica via arquivo temporario + os.replace.

Resolve a race condition classica de "read JSON -> modify -> write
JSON" quando duas threads/processos tocam o mesmo arquivo ao mesmo
tempo. O lock cobre TODO o ciclo leitura-modificacao-escrita, nao so
a escrita - senao duas threads ainda podem ler o mesmo estado antigo
antes de qualquer uma escrever.
"""
import fcntl
import json
import os
import tempfile
import time


class FileLock:
    """Lock exclusivo baseado em fcntl.flock sobre um arquivo .lock
    dedicado (nao o arquivo de dados em si, para nao interferir com
    quem le o arquivo de dados diretamente por engano)."""

    def __init__(self, caminho_alvo, timeout=10):
        self.caminho_lock = caminho_alvo + ".lock"
        self.timeout = timeout
        self._fd = None

    def __enter__(self):
        os.makedirs(os.path.dirname(self.caminho_lock), exist_ok=True)
        self._fd = open(self.caminho_lock, "w")
        inicio = time.monotonic()
        while True:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except BlockingIOError:
                if time.monotonic() - inicio > self.timeout:
                    self._fd.close()
                    raise TimeoutError(f"nao foi possivel obter lock em {self.caminho_lock} apos {self.timeout}s")
                time.sleep(0.05)

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._fd is not None:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
            self._fd.close()
            self._fd = None


def _escrever_atomico(caminho, texto):
    diretorio = os.path.dirname(os.path.abspath(caminho))
    fd, caminho_temp = tempfile.mkstemp(dir=diretorio, prefix=".tmp_", suffix=".json")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(texto)
            f.flush()
            os.fsync(f.fileno())
        os.replace(caminho_temp, caminho)
    except Exception:
        if os.path.exists(caminho_temp):
            os.remove(caminho_temp)
        raise


def ler_json(caminho, padrao=None):
    if not os.path.exists(caminho):
        return padrao if padrao is not None else {}
    with open(caminho) as f:
        return json.load(f)


def escrever_json(caminho, dados):
    _escrever_atomico(caminho, json.dumps(dados, indent=2))


def modificar_json_com_lock(caminho, funcao_modificadora, padrao=None, timeout=10):
    """Le, aplica funcao_modificadora(dados_atuais) -> novos_dados, e
    escreve - tudo dentro de um unico lock, atomico ponta a ponta.
    Retorna o que a funcao_modificadora devolveu."""
    with FileLock(caminho, timeout=timeout):
        dados_atuais = ler_json(caminho, padrao)
        novos_dados = funcao_modificadora(dados_atuais)
        escrever_json(caminho, novos_dados)
        return novos_dados


def append_linha_com_lock(caminho, linha, timeout=10):
    """Append thread-safe a um arquivo de log-linha-por-linha (ex:
    alerts.log), usando o mesmo mecanismo de lock."""
    with FileLock(caminho, timeout=timeout):
        os.makedirs(os.path.dirname(os.path.abspath(caminho)), exist_ok=True)
        with open(caminho, "a") as f:
            f.write(linha if linha.endswith("\n") else linha + "\n")
            f.flush()
            os.fsync(f.fileno())
