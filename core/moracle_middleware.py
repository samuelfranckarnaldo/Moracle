"""
Middleware de aplicacao (nao de servidor) - autentica a requisicao via
Authorization: Bearer <token>, delegando a decisao para core.auth.autenticar()
contra o KeyStore (core.identity). Rotas publicas (/health) passam direto.

Vive aqui, nao em server/, porque "quem pode falar com o Moracle" e regra
de negocio, nao de transporte HTTP.

Responsabilidade estritamente limitada a AUTENTICACAO:
    - Nao verifica permissions.
    - Nao verifica scoped_app_names.
    - Nao dispara migracao/bootstrap de estado (isso e responsabilidade
      da inicializacao em cli.py, antes de Server.start()).

O contrato antigo (header X-Moracle-Key, validado contra
core.api_key.validar()) foi abandonado - nao ha suporte simultaneo aos
dois mecanismos.
"""
import os

from server.response import Response
from core.auth import autenticar
from core.identity import KeyStore
from core import config

ROTAS_PUBLICAS = {"/health", "/webhooks/github", "/console"}

_BEARER_PREFIX = "Bearer "


def _extrair_token(header_authorization):
    if not header_authorization:
        return None
    if not header_authorization.startswith(_BEARER_PREFIX):
        return None
    token = header_authorization[len(_BEARER_PREFIX):].strip()
    return token or None


def auth_middleware(request, context, next):
    if request.path in ROTAS_PUBLICAS or request.path.startswith("/console/"):
        return next(request, context)

    token = _extrair_token(request.header("authorization"))

    key_store = KeyStore(os.path.join(config.RAIZ_PROJETO, ".state"))
    api_key = autenticar(token, key_store)

    if api_key is None:
        return Response.json({"error": "invalid, missing, or expired API key"}, status=401)

    context["api_key"] = api_key

    return next(request, context)
