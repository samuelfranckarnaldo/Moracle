"""
Estados formais do ciclo de vida de um processo de Application,
seguindo o mesmo padrao de server/lifecycle.py (enum + transicoes
validas explicitas, rejeitando qualquer transicao fora do mapa).
"""
from enum import Enum, auto
import threading


class ApplicationState(Enum):
    CREATED = auto()
    STARTING = auto()
    RUNNING = auto()
    HEALTHY = auto()
    UNHEALTHY = auto()
    STOPPING = auto()
    STOPPED = auto()
    CRASHED = auto()


_TRANSICOES_VALIDAS = {
    ApplicationState.CREATED: {ApplicationState.STARTING},
    ApplicationState.STARTING: {ApplicationState.RUNNING, ApplicationState.CRASHED},
    ApplicationState.RUNNING: {ApplicationState.HEALTHY, ApplicationState.UNHEALTHY,
                                ApplicationState.CRASHED, ApplicationState.STOPPING},
    ApplicationState.HEALTHY: {ApplicationState.UNHEALTHY, ApplicationState.CRASHED,
                                ApplicationState.STOPPING},
    ApplicationState.UNHEALTHY: {ApplicationState.HEALTHY, ApplicationState.CRASHED,
                                  ApplicationState.STOPPING},
    ApplicationState.STOPPING: {ApplicationState.STOPPED},
    ApplicationState.STOPPED: {ApplicationState.STARTING},
    ApplicationState.CRASHED: {ApplicationState.STARTING},
}


class ApplicationLifecycleError(Exception):
    pass


class ApplicationLifecycle:
    def __init__(self, estado_inicial=ApplicationState.CREATED):
        self._estado = estado_inicial
        self._lock = threading.Lock()

    @property
    def state(self):
        with self._lock:
            return self._estado

    def transition(self, novo_estado):
        with self._lock:
            permitidos = _TRANSICOES_VALIDAS.get(self._estado, set())
            if novo_estado not in permitidos:
                raise ApplicationLifecycleError(
                    f"invalid transition {self._estado.name} -> {novo_estado.name}"
                )
            self._estado = novo_estado

    def force_set(self, novo_estado):
        """Usado apenas por reconciliacao no startup (recovery), onde
        o estado precisa ser restaurado a partir de persistencia sem
        passar pela maquina de transicoes normal - documentado como
        excecao deliberada, nao uso normal."""
        with self._lock:
            self._estado = novo_estado
