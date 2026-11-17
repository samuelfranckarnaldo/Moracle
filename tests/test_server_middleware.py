import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server.middleware import compose


def test_middleware_order():
    ordem = []

    def mw_a(req, ctx, nxt):
        ordem.append("a-in")
        resposta = nxt(req, ctx)
        ordem.append("a-out")
        return resposta

    def mw_b(req, ctx, nxt):
        ordem.append("b-in")
        resposta = nxt(req, ctx)
        ordem.append("b-out")
        return resposta

    def handler(req, ctx):
        ordem.append("handler")
        return "resposta"

    pipeline = compose([mw_a, mw_b], handler)
    resultado = pipeline(None, None)

    assert resultado == "resposta"
    assert ordem == ["a-in", "b-in", "handler", "b-out", "a-out"]


def test_middleware_short_circuit():
    chamado_handler = []

    def mw_bloqueia(req, ctx, nxt):
        return "bloqueado"

    def handler(req, ctx):
        chamado_handler.append(True)
        return "nunca deveria chegar aqui"

    pipeline = compose([mw_bloqueia], handler)
    resultado = pipeline(None, None)

    assert resultado == "bloqueado"
    assert chamado_handler == []


def test_middleware_exception_propagates_for_server_to_catch():
    def mw_explode(req, ctx, nxt):
        raise ValueError("boom")

    def handler(req, ctx):
        return "ok"

    pipeline = compose([mw_explode], handler)
    try:
        pipeline(None, None)
        assert False, "deveria ter levantado excecao"
    except ValueError:
        pass
