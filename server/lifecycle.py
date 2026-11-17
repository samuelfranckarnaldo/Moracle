"""
Estados formais do ciclo de vida do servidor.
"""
from enum import Enum, auto
import threading


class ServerState(Enum):
    INITIALIZING = auto()
    CONFIGURED = auto()
    BINDING = auto()
    RUNNING = auto()
    DRAINING = auto()
    STOPPING = auto()
    STOPPED = auto()
    FAILED = auto()


_TRANSICOES_VALIDAS = {
    ServerState.INITIALIZING: {ServerState.CONFIGURED, ServerState.FAILED},
    ServerState.CONFIGURED: {ServerState.BINDING, ServerState.FAILED},
    ServerState.BINDING: {ServerState.RUNNING, ServerState.FAILED},
    ServerState.RUNNING: {ServerState.DRAINING, ServerState.FAILED},
    ServerState.DRAINING: {ServerState.STOPPING},
    ServerState.STOPPING: {ServerState.STOPPED},
    ServerState.STOPPED: set(),
    ServerState.FAILED: set(),
}


class LifecycleError(Exception):
    pass


class Lifecycle:
    def __init__(self):
        self._estado = ServerState.INITIALIZING
        self._lock = threading.Lock()

    @property
    def state(self):
        with self._lock:
            return self._estado

    def transition(self, novo_estado):
        with self._lock:
            permitidos = _TRANSICOES_VALIDAS.get(self._estado, set())
            if novo_estado not in permitidos:
                raise LifecycleError(
                    f"invalid transition {self._estado.name} -> {novo_estado.name}"
                )
            self._estado = novo_estado
