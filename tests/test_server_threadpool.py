import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import threading
from server.threadpool import LimitedThreadPool


def test_submits_and_executes():
    pool = LimitedThreadPool(max_workers=2, max_queue=2)
    resultados = []
    lock = threading.Lock()

    def tarefa(n):
        with lock:
            resultados.append(n)

    for i in range(2):
        assert pool.try_submit(tarefa, i) is True

    pool.shutdown(wait=True)
    assert sorted(resultados) == [0, 1]


def test_rejects_when_queue_full():
    pool = LimitedThreadPool(max_workers=1, max_queue=1)
    bloqueio = threading.Event()

    def tarefa_lenta():
        bloqueio.wait(timeout=2)

    assert pool.try_submit(tarefa_lenta) is True
    aceito = pool.try_submit(tarefa_lenta)
    assert aceito is False

    bloqueio.set()
    pool.shutdown(wait=True)
