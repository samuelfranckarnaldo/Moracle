"""
Thread pool com limite explicito - substitui o modelo de
'thread-per-connection ilimitado'. Rejeita quando o limite e
atingido, dando backpressure real.
"""
import threading
from concurrent.futures import ThreadPoolExecutor


class LimitedThreadPool:
    def __init__(self, max_workers, max_queue=None):
        self.max_workers = max_workers
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        self._limite_fila = max_queue if max_queue is not None else max_workers * 4
        self._semaforo = threading.BoundedSemaphore(self._limite_fila)

    def try_submit(self, funcao, *args, **kwargs):
        adquirido = self._semaforo.acquire(blocking=False)
        if not adquirido:
            return False

        def wrapper():
            try:
                funcao(*args, **kwargs)
            finally:
                self._semaforo.release()

        self._executor.submit(wrapper)
        return True

    def shutdown(self, wait=True):
        self._executor.shutdown(wait=wait)
