"""
Pipeline 'onion' de middleware. Cada middleware recebe
(request, context, next) e devolve uma Response - ou chama next(...)
para continuar, ou retorna uma Response propria (short-circuit).
"""


def compose(middlewares, final_handler):
    def construir(indice):
        if indice == len(middlewares):
            return lambda request, context: final_handler(request, context)
        middleware_atual = middlewares[indice]
        proximo = construir(indice + 1)
        return lambda request, context: middleware_atual(request, context, proximo)
    return construir(0)
