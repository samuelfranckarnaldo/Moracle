"""
Rate limiter em memoria, thread-safe, janela deslizante por chave
(IP, rota, ou global). Nao usa lock de arquivo - estado efemero,
nao precisa sobreviver a reinicio, e precisa ser rapido (chamado a
cada requisicao).
"""
import threading
import time
from collections import deque


class SlidingWindowLimiter:
    def __init__(self, max_eventos, janela_segundos):
        self.max_eventos = max_eventos
        self.janela_segundos = janela_segundos
        self._eventos_por_chave = {}
        self._lock = threading.Lock()

    def permitir(self, chave):
        """Retorna (permitido: bool, retry_after_segundos: float|None)."""
        agora = time.monotonic()
        with self._lock:
            fila = self._eventos_por_chave.setdefault(chave, deque())

            while fila and agora - fila[0] > self.janela_segundos:
                fila.popleft()

            if len(fila) >= self.max_eventos:
                mais_antigo = fila[0]
                retry_after = self.janela_segundos - (agora - mais_antigo)
                return False, max(0.0, retry_after)

            fila.append(agora)
            return True, None

    def consultar(self, chave):
        """Como permitir(), mas NAO registra o evento. Use junto com
        registrar() quando varios limiters precisam concordar antes de
        qualquer um consumir cota."""
        if self.max_eventos <= 0:
            return False, float(self.janela_segundos)
        agora = time.monotonic()
        with self._lock:
            fila = self._eventos_por_chave.get(chave)
            if not fila:
                return True, None
            while fila and agora - fila[0] > self.janela_segundos:
                fila.popleft()
            if len(fila) >= self.max_eventos:
                return False, max(0.0, self.janela_segundos - (agora - fila[0]))
            return True, None

    def registrar(self, chave):
        agora = time.monotonic()
        with self._lock:
            self._eventos_por_chave.setdefault(chave, deque()).append(agora)

    def limpar_chaves_antigas(self):
        """Remove chaves cuja fila esvaziou - evita crescimento
        indefinido de memoria com IPs que nao voltam mais."""
        agora = time.monotonic()
        with self._lock:
            chaves_vazias = []
            for chave, fila in self._eventos_por_chave.items():
                while fila and agora - fila[0] > self.janela_segundos:
                    fila.popleft()
                if not fila:
                    chaves_vazias.append(chave)
            for chave in chaves_vazias:
                del self._eventos_por_chave[chave]
