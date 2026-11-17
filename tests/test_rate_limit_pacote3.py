import time
from types import SimpleNamespace

import pytest

from core import rate_limit_middleware as rl
from core.rate_limiter import SlidingWindowLimiter


@pytest.fixture(autouse=True)
def _limpo():
    rl.reset_limiters_para_teste()
    yield
    rl.reset_limiters_para_teste()


def _config(monkeypatch, **rate_limit):
    monkeypatch.setattr(rl.config, "carregar", lambda: {"rate_limit": rate_limit})
    rl.reset_limiters_para_teste()


def _chamar(ip, metodo, caminho):
    req = SimpleNamespace(remote_address=(ip, 1234), method=metodo, path=caminho)
    return rl.rate_limit_middleware(req, {}, lambda r, c: "ok")


def test_consultar_nao_consome_cota():
    limiter = SlidingWindowLimiter(max_eventos=1, janela_segundos=60)
    assert limiter.consultar("a") == (True, None)
    assert limiter.consultar("a") == (True, None)
    limiter.registrar("a")
    permitido, retry = limiter.consultar("a")
    assert permitido is False and retry > 0


def test_max_zero_nega_sem_excecao():
    limiter = SlidingWindowLimiter(max_eventos=0, janela_segundos=60)
    assert limiter.consultar("a")[0] is False


def test_cliente_barrado_por_ip_nao_consome_limite_global(monkeypatch):
    _config(monkeypatch, global_max=5, global_janela_segundos=60,
            por_ip_max=1, por_ip_janela_segundos=60,
            por_rota_max=1000, por_rota_janela_segundos=60)
    assert _chamar("198.51.100.1", "GET", "/x") == "ok"
    for _ in range(20):
        assert _chamar("198.51.100.1", "GET", "/x") != "ok"
    assert _chamar("198.51.100.2", "GET", "/x") == "ok"
    assert _chamar("198.51.100.3", "GET", "/x") == "ok"


def test_ingest_tem_orcamento_proprio(monkeypatch):
    _config(monkeypatch, global_max=1000, global_janela_segundos=60,
            por_ip_max=1, por_ip_janela_segundos=60,
            por_rota_max=1000, por_rota_janela_segundos=60,
            ingest={"por_ip_max": 5, "por_ip_janela_segundos": 60,
                    "global_max": 100, "global_janela_segundos": 60})
    resultados = [_chamar("198.51.100.1", "POST", "/ingest") for _ in range(8)]
    assert resultados[:5] == ["ok"] * 5
    assert all(r != "ok" for r in resultados[5:])
    assert _chamar("198.51.100.1", "GET", "/health") == "ok"
    assert _chamar("198.51.100.1", "GET", "/health") != "ok"


def test_flood_de_ingest_nao_esgota_o_global_geral(monkeypatch):
    _config(monkeypatch, global_max=2, global_janela_segundos=60,
            por_ip_max=100, por_ip_janela_segundos=60,
            por_rota_max=100, por_rota_janela_segundos=60,
            ingest={"por_ip_max": 1000, "por_ip_janela_segundos": 60,
                    "global_max": 1000, "global_janela_segundos": 60})
    for _ in range(50):
        assert _chamar("198.51.100.1", "POST", "/ingest") == "ok"
    assert _chamar("198.51.100.9", "GET", "/health") == "ok"


def test_limpeza_periodica_remove_chaves_antigas(monkeypatch):
    _config(monkeypatch, global_max=1000, global_janela_segundos=60,
            por_ip_max=100, por_ip_janela_segundos=0.01,
            por_rota_max=100, por_rota_janela_segundos=60)
    _chamar("198.51.100.1", "GET", "/x")
    assert "198.51.100.1" in rl._limiter_por_ip._eventos_por_chave
    time.sleep(0.05)
    rl._ultima_limpeza = -1000.0
    rl._limpar_se_preciso()
    assert "198.51.100.1" not in rl._limiter_por_ip._eventos_por_chave


def test_wsgi_middleware_padrao_aponta_para_porta_7000():
    from integrations.wsgi_middleware import MoracleMiddleware
    assert MoracleMiddleware(lambda e, s: [b""], api_key="k").url == "http://localhost:7000/ingest"


def test_wsgi_middleware_avisa_falha_em_stderr(capsys):
    from integrations.wsgi_middleware import MoracleMiddleware
    mw = MoracleMiddleware(lambda e, s: [b""], url="http://127.0.0.1:1", api_key="k", timeout=0.3)
    mw._ultimo_aviso = -1000.0
    mw._post({"ip": "203.0.113.1", "method": "GET", "path": "/", "user_agent": "x", "status_code": 0})
    assert "nao entregue" in capsys.readouterr().err
