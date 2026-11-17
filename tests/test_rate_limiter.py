import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
import threading
from core.rate_limiter import SlidingWindowLimiter


def test_permite_ate_o_limite():
    limiter = SlidingWindowLimiter(max_eventos=3, janela_segundos=10)
    for _ in range(3):
        permitido, _ = limiter.permitir("chave-x")
        assert permitido is True


def test_bloqueia_apos_o_limite():
    limiter = SlidingWindowLimiter(max_eventos=2, janela_segundos=10)
    limiter.permitir("chave-x")
    limiter.permitir("chave-x")
    permitido, retry_after = limiter.permitir("chave-x")
    assert permitido is False
    assert retry_after > 0


def test_janela_desliza_e_libera_espaco():
    limiter = SlidingWindowLimiter(max_eventos=1, janela_segundos=0.3)
    permitido1, _ = limiter.permitir("chave-x")
    assert permitido1 is True
    permitido2, _ = limiter.permitir("chave-x")
    assert permitido2 is False
    time.sleep(0.35)
    permitido3, _ = limiter.permitir("chave-x")
    assert permitido3 is True


def test_chaves_diferentes_sao_independentes():
    limiter = SlidingWindowLimiter(max_eventos=1, janela_segundos=10)
    p1, _ = limiter.permitir("ip-a")
    p2, _ = limiter.permitir("ip-b")
    assert p1 is True
    assert p2 is True


def test_concorrencia_nao_deixa_passar_alem_do_limite():
    limiter = SlidingWindowLimiter(max_eventos=50, janela_segundos=10)
    permitidos = []
    lock = threading.Lock()

    def tentar():
        ok, _ = limiter.permitir("chave-concorrente")
        with lock:
            permitidos.append(ok)

    threads = [threading.Thread(target=tentar) for _ in range(200)]
    for th in threads:
        th.start()
    for th in threads:
        th.join(timeout=10)

    total_permitido = sum(1 for p in permitidos if p)
    assert total_permitido == 50, f"esperado exatamente 50 permitidos, obteve {total_permitido}"
