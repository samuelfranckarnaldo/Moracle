import functools
import os

from server.response import Response
from core import config
from core.authorization import exigir_permissao
from core.identity import RoleStore, KNOWN_PERMISSIONS


def requer_permissao(permissao):
    if permissao not in KNOWN_PERMISSIONS:
        raise ValueError(f"permissão fora do contrato: {permissao!r}")

    def decorador(handler):
        @functools.wraps(handler)
        def wrapper(request, context):
            api_key = context.get("api_key")
            if api_key is None:
                return Response.json({"error": "authentication required"}, status=401)
            role_store = RoleStore(os.path.join(config.RAIZ_PROJETO, ".state"))
            if not exigir_permissao(api_key, role_store, permissao):
                return Response.json({"error": f"{permissao} permission required"}, status=403)
            return handler(request, context)
        return wrapper
    return decorador
