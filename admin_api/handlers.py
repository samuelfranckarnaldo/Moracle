"""
Handlers da Admin API - traduzem Request/Response HTTP para chamadas
ao ApplicationManager e ao registry. Nao contem logica de negocio
propria: toda decisao de deploy/rollback/lifecycle ja existe em
deploy_platform/application_manager.py - este modulo so faz a ponte
HTTP <-> Application Manager.

Auth: nao ha logica de autenticacao aqui. Todas as rotas /admin/*
sao protegidas pelo mesmo auth_middleware que ja protege o resto da
API do Moracle (core/moracle_middleware.py) - decisao desta etapa:
uma unica API key para tudo, sem Service Roles ainda.
"""
import json

import os

from server.response import Response
from deploy_platform import registry, process_manager as pm
from deploy_platform.application_manager import (
    ApplicationManager, ApplicationManagerError,
    IdentidadeIndeterminadaError, FalhaAoPararProcessoError,
)
from core import config
from core.identity import RoleStore
from core.authorization import resolver_acesso, ResolucaoAcesso
from core import access_log_query

_manager = ApplicationManager()


def _role_store():
    return RoleStore(os.path.join(config.RAIZ_PROJETO, ".state"))


def _mapear_404_para_deployment(response_erro):
    """
    _autorizar_recurso() gera mensagens pensadas para o recurso
    'application' (ex.: 'application not found'). Rotas de deployment
    resolvem scope via deployment.app_name, mas o recurso HTTP
    consultado pelo cliente e o deployment, nao a application -- a
    mensagem de erro deve refletir isso.

    So ajusta o corpo de respostas 404 (SEM_ESCOPO); 403
    (SEM_PERMISSAO) ja tem mensagem generica o suficiente
    ("missing permission: ...") e nao precisa de seu proprio ajuste.
    Passa adiante inalterada qualquer resposta que nao seja 404.
    """
    if response_erro.status == 404:
        return Response.json({"error": "deployment not found"}, status=404)
    return response_erro


def _autorizar_recurso(context, permission, app_name):
    """
    Politica HTTP 404/403 aprovada (Passo Console-A), usando
    resolver_acesso() como unica fonte da regra de autorizacao:

        SEM_ESCOPO    -> 404 (app fora do universo da chave -- nunca
                          confirma existencia de recurso alheio)
        SEM_PERMISSAO -> 403 (app visivel, mas falta a permissao)
        AUTORIZADO    -> None (handler prossegue)

    api_key vem de context, setado pelo auth_middleware (Passo 4A).
    role_name que nao resolve mais para nenhum ServiceRole e
    inconsistencia de estado de identidade -- fail-closed, 403
    generico (nao 404, nao menciona server.admin especificamente).
    """
    api_key = context.get("api_key")
    role_store = _role_store()
    role = role_store.get(api_key.role_name)
    if role is None:
        return Response.json({"error": "access denied"}, status=403)

    resultado = resolver_acesso(api_key, role, permission, app_name=app_name)

    if resultado == ResolucaoAcesso.SEM_ESCOPO:
        return Response.json({"error": "application not found"}, status=404)
    if resultado == ResolucaoAcesso.SEM_PERMISSAO:
        return Response.json({"error": f"missing permission: {permission}"}, status=403)
    return None


def get_manager():
    """Ponto unico de acesso ao ApplicationManager - permite trocar a
    instancia em testes sem reescrever todos os handlers."""
    return _manager


def _parse_json_body(request, obrigatorio=True):
    if not request.body:
        if obrigatorio:
            return None, Response.json({"error": "missing JSON body"}, status=400)
        return {}, None
    try:
        return json.loads(request.body), None
    except json.JSONDecodeError:
        return None, Response.json({"error": "invalid JSON body"}, status=400)


def _processo_confirmado_vivo(app):
    if not app.current_process_handle_id:
        return False
    handle = registry.obter_process_handle(app.current_process_handle_id)
    if handle is None:
        return False
    return pm.confirmar_identidade(handle.pid, handle.starttime) is True


# ---------- Applications ----------

def handler_create_app(request, context):
    dados, erro = _parse_json_body(request)
    if erro:
        return erro

    name = dados.get("name")
    working_directory = dados.get("working_directory")
    start_command = dados.get("start_command")

    if not name or not isinstance(name, str):
        return Response.json({"error": "name is required and must be a string"}, status=400)

    erro_auth = _autorizar_recurso(context, "app.create", app_name=name)
    if erro_auth:
        return erro_auth

    if not working_directory or not isinstance(working_directory, str):
        return Response.json({"error": "working_directory is required"}, status=400)
    if not isinstance(start_command, list) or not start_command:
        return Response.json({"error": "start_command must be a non-empty list of arguments"}, status=400)

    if registry.obter_app(name) is not None:
        return Response.json({"error": f"application {name!r} already exists"}, status=409)

    port = dados.get("port")
    if port is not None and not isinstance(port, int):
        return Response.json({"error": "port must be an integer"}, status=400)

    app = get_manager().criar_application(
        name=name, working_directory=working_directory, start_command=start_command,
        environment=dados.get("environment") or {}, port=port,
        health_check_path=dados.get("health_check_path", "/health"),
        domain=dados.get("domain"),
        restart_policy_mode=dados.get("restart_policy_mode", "NEVER"),
        restart_policy_max_retries=dados.get("restart_policy_max_retries"),
        restart_policy_backoff_seconds=dados.get("restart_policy_backoff_seconds", 5.0),
    )
    return Response.json(app.to_dict(), status=201)


def handler_list_apps(request, context):
    api_key = context.get("api_key")
    apps = registry.listar_apps()

    if not api_key.is_globally_scoped:
        apps = [a for a in apps if a.name in api_key.scoped_app_names]

    resumo = [
        {"name": a.name, "domain": a.domain, "current_deployment_id": a.current_deployment_id}
        for a in apps
    ]
    return Response.json({"applications": resumo})


def handler_get_app(request, context):
    name = context.route_params.get("name")

    erro_auth = _autorizar_recurso(context, "app.read", app_name=name)
    if erro_auth:
        return erro_auth

    app = registry.obter_app(name)
    if app is None:
        return Response.json({"error": "application not found"}, status=404)

    dados = app.to_dict()
    if request.query.get("include_env") != "true":
        dados.pop("environment", None)

    try:
        dados["status"] = get_manager().status(name)
    except ApplicationManagerError:
        pass

    return Response.json(dados)


def handler_delete_app(request, context):
    name = context.route_params.get("name")

    erro_auth = _autorizar_recurso(context, "app.delete", app_name=name)
    if erro_auth:
        return erro_auth

    app = registry.obter_app(name)
    if app is None:
        return Response.json({"error": "application not found"}, status=404)

    if _processo_confirmado_vivo(app):
        return Response.json({"error": "application still has a running process, stop it before deleting"}, status=409)

    registry.remover_app(name)
    return Response(status=204)


# ---------- Ciclo de processo ----------

def handler_start_app(request, context):
    name = context.route_params.get("name")

    erro_auth = _autorizar_recurso(context, "app.start_stop", app_name=name)
    if erro_auth:
        return erro_auth

    app = registry.obter_app(name)
    if app is None:
        return Response.json({"error": "application not found"}, status=404)
    if not app.current_deployment_id:
        return Response.json({"error": "no deployment yet, use POST /admin/apps/{name}/deploy first"}, status=422)
    if _processo_confirmado_vivo(app):
        return Response.json({"error": "process already running for this application"}, status=409)

    try:
        get_manager().iniciar(name, app.current_deployment_id)
    except (IdentidadeIndeterminadaError, FalhaAoPararProcessoError) as e:
        return Response.json({"error": str(e)}, status=409)
    except ApplicationManagerError as e:
        return Response.json({"error": str(e)}, status=400)

    return Response.json(get_manager().status(name))


def handler_stop_app(request, context):
    name = context.route_params.get("name")

    erro_auth = _autorizar_recurso(context, "app.start_stop", app_name=name)
    if erro_auth:
        return erro_auth

    if registry.obter_app(name) is None:
        return Response.json({"error": "application not found"}, status=404)

    dados, erro = _parse_json_body(request, obrigatorio=False)
    if erro:
        return erro
    api_key = context.get("api_key")
    role = _role_store().get(api_key.role_name) if api_key is not None else None
    forcar = bool(dados.get("force")) and role is not None and role.is_wildcard

    try:
        get_manager().parar(name, forcar=forcar)  # idempotente
    except (IdentidadeIndeterminadaError, FalhaAoPararProcessoError) as e:
        return Response.json({"error": str(e)}, status=409)
    return Response.json(get_manager().status(name))


def handler_restart_app(request, context):
    name = context.route_params.get("name")

    erro_auth = _autorizar_recurso(context, "app.start_stop", app_name=name)
    if erro_auth:
        return erro_auth

    if registry.obter_app(name) is None:
        return Response.json({"error": "application not found"}, status=404)

    try:
        deployment = get_manager().reiniciar(name)
    except (IdentidadeIndeterminadaError, FalhaAoPararProcessoError) as e:
        return Response.json({"error": str(e)}, status=409)
    except ApplicationManagerError as e:
        return Response.json({"error": str(e)}, status=400)

    return Response.json(deployment.to_dict())


def handler_status_app(request, context):
    name = context.route_params.get("name")

    erro_auth = _autorizar_recurso(context, "app.read", app_name=name)
    if erro_auth:
        return erro_auth

    try:
        status = get_manager().status(name)
    except ApplicationManagerError:
        return Response.json({"error": "application not found"}, status=404)
    return Response.json(status)


def handler_logs_app(request, context):
    name = context.route_params.get("name")

    erro_auth = _autorizar_recurso(context, "app.logs", app_name=name)
    if erro_auth:
        return erro_auth

    if registry.obter_app(name) is None:
        return Response.json({"error": "application not found"}, status=404)

    try:
        linhas = int(request.query.get("lines", "100"))
    except ValueError:
        linhas = 100
    linhas = max(1, min(linhas, 5000))  # limite: nunca despejar arquivo inteiro sem controle

    return Response.json(get_manager().logs(name, linhas=linhas))


def handler_access_logs_app(request, context):
    """
    GET /admin/apps/{name}/access-logs

    Le o Access Log Estruturado (server/access_log.py) filtrado por
    esta app. Full-scan sobre o arquivo ativo access_log.jsonl - nao
    le arquivos rotacionados/arquivados (fora de escopo ate decisao
    futura). total_matched exige leitura completa, nao e' barato.

    Nota: esta propria requisicao gera seu proprio AccessLogRecord
    (app_name=name, via _app_scoped em router.py) como qualquer outra
    requisicao ao mc server - a consulta nao altera nem contamina os
    registros que esta consultando, apenas cria um novo registro
    proprio, como qualquer requisicao HTTP.
    """
    name = context.route_params.get("name")

    erro_auth = _autorizar_recurso(context, "app.access_logs", app_name=name)
    if erro_auth:
        return erro_auth

    if registry.obter_app(name) is None:
        return Response.json({"error": "application not found"}, status=404)

    caminho_jsonl = os.path.join(config.RAIZ_PROJETO, ".state", "access_log.jsonl")

    from_ts = request.query.get("from") or None
    to_ts = request.query.get("to") or None
    method = request.query.get("method") or None
    path_contains = request.query.get("path_contains") or None

    status_raw = request.query.get("status")
    status = None
    if status_raw is not None:
        try:
            status = int(status_raw)
        except ValueError:
            return Response.json({"error": "invalid status: must be an integer"}, status=400)

    try:
        limit = int(request.query.get("limit", "500"))
    except ValueError:
        limit = 500

    cursor = request.query.get("cursor") or None

    records, next_cursor, total_matched = access_log_query.buscar(
        caminho_jsonl,
        app_name=name,
        from_ts=from_ts,
        to_ts=to_ts,
        status=status,
        method=method,
        path_contains=path_contains,
        limit=limit,
        cursor=cursor,
    )

    return Response.json({
        "records": records,
        "next_cursor": next_cursor,
        "total_matched": total_matched,
    })


def handler_deploy_app(request, context):
    name = context.route_params.get("name")

    erro_auth = _autorizar_recurso(context, "app.deploy", app_name=name)
    if erro_auth:
        return erro_auth

    if registry.obter_app(name) is None:
        return Response.json({"error": "application not found"}, status=404)

    dados, erro = _parse_json_body(request, obrigatorio=False)
    if erro:
        return erro

    try:
        deployment = get_manager().deploy(
            name,
            health_check_base_url=dados.get("health_check_base_url"),
            health_check_tentativas=dados.get("health_check_tentativas", 3),
        )
    except (IdentidadeIndeterminadaError, FalhaAoPararProcessoError) as e:
        return Response.json({"error": str(e)}, status=409)
    return Response.json(deployment.to_dict())


# ---------- Deployments ----------

def handler_list_deployments(request, context):
    api_key = context.get("api_key")
    app_name = request.query.get("app")

    if app_name:
        erro_auth = _autorizar_recurso(context, "deployment.read", app_name=app_name)
        if erro_auth:
            return erro_auth
        deployments = registry.listar_deployments_do_app(app_name)
    else:
        apps = registry.listar_apps()
        if not api_key.is_globally_scoped:
            apps = [a for a in apps if a.name in api_key.scoped_app_names]
        deployments = []
        for app in apps:
            deployments.extend(registry.listar_deployments_do_app(app.name))

    return Response.json({"deployments": [d.to_dict() for d in deployments]})


def handler_get_deployment(request, context):
    deployment_id = context.route_params.get("id")
    deployment = registry.obter_deployment(deployment_id)
    if deployment is None:
        return Response.json({"error": "deployment not found"}, status=404)

    erro_auth = _autorizar_recurso(context, "deployment.read", app_name=deployment.app_name)
    if erro_auth:
        return _mapear_404_para_deployment(erro_auth)

    return Response.json(deployment.to_dict())


def handler_rollback_deployment(request, context):
    deployment_id = context.route_params.get("id")
    deployment = registry.obter_deployment(deployment_id)
    if deployment is None:
        return Response.json({"error": "deployment not found"}, status=404)

    erro_auth = _autorizar_recurso(context, "deployment.rollback", app_name=deployment.app_name)
    if erro_auth:
        return _mapear_404_para_deployment(erro_auth)

    dados, erro = _parse_json_body(request, obrigatorio=False)
    if erro:
        return erro

    try:
        resultado = get_manager().rollback(
            deployment.app_name, deployment_id,
            health_check_base_url=dados.get("health_check_base_url"),
            health_check_tentativas=dados.get("health_check_tentativas", 3),
        )
    except ApplicationManagerError as e:
        return Response.json({"error": str(e)}, status=400)

    return Response.json(resultado.to_dict())
