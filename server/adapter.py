"""
Application Adapter - contrato entre a infraestrutura HTTP generica e
a logica de negocio do Moracle. E o UNICO lugar onde core/defense.py,
core/logs.py, core/scoring.py deveriam ser importados quando a
integracao das rotas atuais for feita (NAO feita nesta etapa).

Um Handler e qualquer callable(request, context) -> Response.
"""
from typing import Callable
from server.request import Request, Context
from server.response import Response

Handler = Callable[[Request, Context], Response]


def make_adapter(funcao_de_negocio):
    def handler(request, context):
        return funcao_de_negocio(request, context)
    return handler
