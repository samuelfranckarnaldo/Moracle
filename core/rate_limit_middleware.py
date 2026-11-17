"""
Application middleware de rate limiting - limite global, por IP e
por rota. Nao depende do cliente para se proteger; roda antes da
aplicacao decidir qualquer coisa.

Duas classes de trafego, com orcamentos separados:
  - "ingest": POST /ingest (sensor das aplicacoes instrumentadas). Todo
    o trafego de uma aplicacao chega do mesmo IP (o da propria
    aplicacao), entao nao pode dividir cota com o resto da API.
  - "geral": todas as outras rotas.
Um pedido so consome cota se TODOS os limites aplicaveis o aceitarem:
um cliente barrado pelo limite por IP nao gasta o limite global.
"""
import time

from server.response import Response
from core.rate_limiter import SlidingWindowLimiter
from core import config

ROTA_INGEST = "POST:/ingest"
_INTERVALO_LIMPEZA_SEGUNDOS = 60

_limiter_global = None
_limiter_por_ip = None
_limiter_por_rota = None
_limiter_ingest_global = None
_limiter_ingest_por_ip = None
_ultima_limpeza = 0.0


def _obter_limiters():
    global _limiter_global, _limiter_por_ip, _limiter_por_rota
    if _limiter_global is None:
        cfg = config.carregar().get("rate_limit", {})
        _limiter_global = SlidingWindowLimiter(
            max_eventos=cfg.get("global_max", 500),
            janela_segundos=cfg.get("global_janela_segundos", 60),
        )
        _limiter_por_ip = SlidingWindowLimiter(
            max_eventos=cfg.get("por_ip_max", 60),
            janela_segundos=cfg.get("por_ip_janela_segundos", 60),
        )
        _limiter_por_rota = SlidingWindowLimiter(
            max_eventos=cfg.get("por_rota_max", 30),
            janela_segundos=cfg.get("por_rota_janela_segundos", 10),
        )
    return _limiter_global, _limiter_por_ip, _limiter_por_rota


def _obter_limiters_ingest():
    global _limiter_ingest_global, _limiter_ingest_por_ip
    if _limiter_ingest_global is None:
        cfg = config.carregar().get("rate_limit", {}).get("ingest", {})
        _limiter_ingest_global = SlidingWindowLimiter(
            max_eventos=cfg.get("global_max", 6000),
            janela_segundos=cfg.get("global_janela_segundos", 60),
        )
        _limiter_ingest_por_ip = SlidingWindowLimiter(
            max_eventos=cfg.get("por_ip_max", 3000),
            janela_segundos=cfg.get("por_ip_janela_segundos", 60),
        )
    return _limiter_ingest_global, _limiter_ingest_por_ip


def reset_limiters_para_teste():
    """Usado apenas em testes - forca recriacao dos limiters com a
    config atual, em vez de reusar instancias de um teste anterior."""
    global _limiter_global, _limiter_por_ip, _limiter_por_rota
    global _limiter_ingest_global, _limiter_ingest_por_ip, _ultima_limpeza
    _limiter_global = None
    _limiter_por_ip = None
    _limiter_por_rota = None
    _limiter_ingest_global = None
    _limiter_ingest_por_ip = None
    _ultima_limpeza = 0.0


def _limpar_se_preciso():
    global _ultima_limpeza
    agora = time.monotonic()
    if agora - _ultima_limpeza < _INTERVALO_LIMPEZA_SEGUNDOS:
        return
    _ultima_limpeza = agora
    candidatos = (_limiter_global, _limiter_por_ip, _limiter_por_rota,
                  _limiter_ingest_global, _limiter_ingest_por_ip)
    for limiter in candidatos:
        if limiter is not None:
            limiter.limpar_chaves_antigas()


def _avaliar(checagens):
    """Consulta todos; so registra (consome cota) se todos permitirem."""
    for limiter, chave in checagens:
        permitido, retry_after = limiter.consultar(chave)
        if not permitido:
            return False, retry_after
    for limiter, chave in checagens:
        limiter.registrar(chave)
    return True, None


def rate_limit_middleware(request, context, next):
    _limpar_se_preciso()

    ip = request.remote_address[0] if request.remote_address else "unknown"
    rota = f"{request.method}:{request.path}"[:200]

    if rota == ROTA_INGEST:
        limiter_global, limiter_por_ip = _obter_limiters_ingest()
        checagens = [(limiter_por_ip, ip), (limiter_global, "global")]
    else:
        limiter_global, limiter_por_ip, limiter_por_rota = _obter_limiters()
        checagens = [(limiter_por_ip, ip), (limiter_por_rota, rota), (limiter_global, "global")]

    permitido, retry_after = _avaliar(checagens)
    if not permitido:
        return Response.json(
            {"error": "rate limit exceeded", "retry_after_seconds": round(retry_after, 1)},
            status=429,
            headers={"Retry-After": str(int(retry_after) + 1)},
        )

    return next(request, context)
