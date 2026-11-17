"""
Handlers da Admin API para gerenciamento de identidade: API Keys e
Service Roles (Passo 4B). Modulo separado de admin_api/handlers.py
(que trata Applications/Deployments) — dominio diferente, mesmo
padrao de ponte HTTP <-> core.

Todas as cinco rotas exigem server.admin (wildcard). Autenticacao ja
ocorreu no auth_middleware (core/moracle_middleware.py, Passo 4A);
este modulo so precisa verificar AUTORIZACAO.
"""
import os
from datetime import datetime

from server.response import Response
from core import config
from core.identity import (
    ApiKey,
    ServiceRole,
    KeyStore,
    RoleStore,
    create_api_key,
    DuplicateApiKeyNameError,
    DuplicateRoleNameError,
    LastAdminKeyError,
    UnknownPermissionError,
    IdentityError,
)
from core.authorization import exigir_permissao
from core import audit_ciclo as ac
from core import security_runtime as rt
from deploy_platform import registry


def _key_store():
    return KeyStore(os.path.join(config.RAIZ_PROJETO, ".state"))


def _role_store():
    return RoleStore(os.path.join(config.RAIZ_PROJETO, ".state"))


def _require_server_admin(request, context):
    """
    Verifica autorizacao (server.admin) para a ApiKey ja autenticada
    pelo middleware. Retorna (api_key, None) se autorizado, ou
    (None, Response) com o erro apropriado se nao.

    401 nunca ocorre aqui — se a requisicao chegou ate o handler, o
    middleware ja autenticou. Este helper so decide 401 no caso
    defensivo de context nao conter api_key (nao deveria acontecer
    em produção, mas evita AttributeError se algum dia ocorrer).
    """
    api_key = context.get("api_key")
    if api_key is None:
        return None, Response.json({"error": "authentication required"}, status=401)

    role_store = _role_store()
    if not exigir_permissao(api_key, role_store, "server.admin"):
        return None, Response.json({"error": "server.admin permission required"}, status=403)

    return api_key, None


def _auditado(event_type, pedido, gravar, context, repropagar=()):
    """Passo 4b-4: ciclo de auditoria (requested duravel antes da mutacao,
    resultado depois). Devolve (resultado, None) ou (None, Response 503/500).
    Erros de dominio em `repropagar` sobem ao handler. Os payloads nunca
    incluem segredos nem hashes de chave."""
    res = ac.ciclo_auditado(event_type, pedido, gravar, rt.ator_http(context), "http",
                            correlation_id=rt.request_id_de(context), repropagar=repropagar)
    if res.estado == ac.AUDIT_INDISPONIVEL:
        return None, Response.json({"error": "audit unavailable"}, status=503)
    if res.estado == ac.FALHA:
        return None, Response.json({"error": "operation failed"}, status=500)
    return res, None


def _parse_json_body(request, obrigatorio=True):
    import json
    if not request.body:
        if obrigatorio:
            return None, Response.json({"error": "missing JSON body"}, status=400)
        return {}, None
    try:
        dados = json.loads(request.body)
    except json.JSONDecodeError:
        return None, Response.json({"error": "invalid JSON body"}, status=400)
    if not isinstance(dados, dict):
        return None, Response.json({"error": "request body must be a JSON object"}, status=400)
    return dados, None


def _nome_valido(valor):
    """Regra unica de validacao de 'name' (ApiKey ou ServiceRole):
    string nao vazia e nao composta so por whitespace. NAO faz trim —
    o valor persistido e' exatamente o fornecido (decisao 4B-B)."""
    return isinstance(valor, str) and valor.strip() != ""


def _expires_at_valido(valor):
    if valor is None:
        return True
    if not isinstance(valor, str):
        return False
    try:
        datetime.fromisoformat(valor)
        return True
    except ValueError:
        return False


def _serializar_api_key_publica(api_key: ApiKey) -> dict:
    """Metadados de uma ApiKey para resposta HTTP — NUNCA inclui
    key_hash nem o segredo bruto."""
    return {
        "id": api_key.id,
        "name": api_key.name,
        "role": api_key.role_name,
        "created_at": api_key.created_at,
        "expires_at": api_key.expires_at,
        "revoked": api_key.revoked,
        "last_used_at": api_key.last_used_at,
        "scoped_app_names": api_key.scoped_app_names,
    }


def _serializar_role(role: ServiceRole) -> dict:
    return {
        "name": role.name,
        "description": role.description,
        "permissions": sorted(role.permissions),
    }


# =============================================================================
# API Keys
# =============================================================================

def handler_create_key(request, context):
    _, erro = _require_server_admin(request, context)
    if erro:
        return erro

    dados, erro = _parse_json_body(request)
    if erro:
        return erro

    name = dados.get("name")
    role_name = dados.get("role")
    expires_at = dados.get("expires_at")
    scoped_app_names = dados.get("scoped_app_names")

    if not _nome_valido(name):
        return Response.json({"error": "name is required and must be a non-empty string"}, status=400)

    if not isinstance(role_name, str) or not role_name:
        return Response.json({"error": "role is required and must be a string"}, status=400)

    role_store = _role_store()
    if role_store.get(role_name) is None:
        return Response.json({"error": f"role {role_name!r} does not exist"}, status=400)

    if not _expires_at_valido(expires_at):
        return Response.json({"error": "expires_at must be a valid ISO 8601 datetime string"}, status=400)

    if scoped_app_names is not None:
        if not isinstance(scoped_app_names, list):
            return Response.json({"error": "scoped_app_names must be a list"}, status=400)
        if not all(isinstance(a, str) and a for a in scoped_app_names):
            return Response.json({"error": "scoped_app_names must contain only non-empty strings"}, status=400)
        if len(scoped_app_names) != len(set(scoped_app_names)):
            return Response.json({"error": "scoped_app_names must not contain duplicates"}, status=400)

        nomes_existentes = {a.name for a in registry.listar_apps()}
        desconhecidos = [a for a in scoped_app_names if a not in nomes_existentes]
        if desconhecidos:
            return Response.json(
                {"error": f"unknown application(s) in scoped_app_names: {desconhecidos}"},
                status=400,
            )
    else:
        scoped_app_names = []

    key_store = _key_store()
    criada = {}

    def _gravar():
        api_key, raw_token = create_api_key(
            key_store, name=name, role_name=role_name,
            scoped_app_names=scoped_app_names, expires_at=expires_at,
        )
        criada["api_key"], criada["token"] = api_key, raw_token
        return {"target_id": api_key.id}

    pedido = {"name": name, "role": role_name, "scoped_app_names": list(scoped_app_names),
              "expires_at": expires_at}
    try:
        _, erro = _auditado("key.created", pedido, _gravar, context,
                            repropagar=(DuplicateApiKeyNameError,))
    except DuplicateApiKeyNameError:
        return Response.json({"error": "API key name already exists"}, status=409)
    if erro:
        return erro

    resposta = _serializar_api_key_publica(criada["api_key"])
    resposta["secret"] = criada["token"]
    return Response.json(resposta, status=201)


def handler_list_keys(request, context):
    _, erro = _require_server_admin(request, context)
    if erro:
        return erro

    key_store = _key_store()
    chaves = sorted(key_store.load_all().values(), key=lambda k: k.created_at)
    return Response.json({"keys": [_serializar_api_key_publica(k) for k in chaves]})


def handler_revoke_key(request, context):
    _, erro = _require_server_admin(request, context)
    if erro:
        return erro

    key_id = context.route_params.get("id")
    key_store = _key_store()
    role_store = _role_store()

    try:
        _, erro = _auditado(
            "key.revoked", {"target_id": key_id},
            lambda: key_store.revoke_safely(key_id, role_store) or {}, context,
            repropagar=(IdentityError,))
    except LastAdminKeyError:
        return Response.json({"error": "Cannot revoke the last active server.admin key"}, status=409)
    except IdentityError:
        return Response.json({"error": "API key not found"}, status=404)
    if erro:
        return erro

    return Response.json({"id": key_id, "revoked": True})


# =============================================================================
# Roles
# =============================================================================

def handler_list_roles(request, context):
    _, erro = _require_server_admin(request, context)
    if erro:
        return erro

    role_store = _role_store()
    roles = sorted(role_store.load_all().values(), key=lambda r: r.name)
    return Response.json({"roles": [_serializar_role(r) for r in roles]})


def handler_create_role(request, context):
    _, erro = _require_server_admin(request, context)
    if erro:
        return erro

    dados, erro = _parse_json_body(request)
    if erro:
        return erro

    name = dados.get("name")
    description = dados.get("description") or ""
    permissions = dados.get("permissions")

    if not _nome_valido(name):
        return Response.json({"error": "name is required and must be a non-empty string"}, status=400)

    if description is not None and not isinstance(description, str):
        return Response.json({"error": "description must be a string"}, status=400)

    if not isinstance(permissions, list) or not permissions:
        return Response.json({"error": "permissions is required and must be a non-empty list"}, status=400)
    if not all(isinstance(p, str) for p in permissions):
        return Response.json({"error": "permissions must contain only strings"}, status=400)

    try:
        role = ServiceRole(name=name, permissions=frozenset(permissions), description=description)
    except UnknownPermissionError as e:
        return Response.json({"error": str(e)}, status=400)

    role_store = _role_store()
    pedido = {"name": role.name, "permissions": sorted(role.permissions)}
    try:
        _, erro = _auditado("role.created", pedido, lambda: role_store.add(role) or {}, context,
                            repropagar=(DuplicateRoleNameError,))
    except DuplicateRoleNameError:
        return Response.json({"error": "Role already exists"}, status=409)
    if erro:
        return erro

    return Response.json(_serializar_role(role), status=201)
