"""
Registra as rotas /admin/* no Router do nucleo (server/router.py).
Nao cria um Router separado por padrao - as rotas admin convivem no
mesmo Router das rotas do Moracle (/health, /status, /ingest, etc.),
recebendo a mesma autenticacao ja aplicada pelo auth_middleware.

Rotas app-scoped (listadas explicitamente em _ROTAS_APP_SCOPED) marcam
context["app_name"] a partir de route_params["name"] antes de chamar
o handler real. Isso e' o contrato de identidade de aplicacao do
Access Log Estruturado: app_name so e' preenchido para rotas que esta
lista whitelista como pertencentes a uma aplicacao - nunca inferido
genericamente de qualquer rota que tenha um parametro chamado "name"
(ex: uma futura /admin/users/{name} NAO deve virar app_name).
"""
from admin_api import handlers
from admin_api import identity_handlers


def _app_scoped(handler):
    """Marca a requisicao como pertencente a uma aplicacao, usando o
    route_params ja resolvido pelo Router do nucleo. So deve envolver
    handlers de rotas onde {name} e', de fato, o identificador de uma
    aplicacao - ver _ROTAS_APP_SCOPED abaixo."""
    def wrapper(request, context):
        context["app_name"] = context.route_params.get("name", "")
        return handler(request, context)
    return wrapper


def registrar_rotas_admin(router):
    router.add_route("POST", "/admin/apps", handlers.handler_create_app)
    router.add_route("GET", "/admin/apps", handlers.handler_list_apps)
    router.add_route("GET", "/admin/apps/{name}", _app_scoped(handlers.handler_get_app))
    router.add_route("DELETE", "/admin/apps/{name}", _app_scoped(handlers.handler_delete_app))

    router.add_route("POST", "/admin/apps/{name}/start", _app_scoped(handlers.handler_start_app))
    router.add_route("POST", "/admin/apps/{name}/stop", _app_scoped(handlers.handler_stop_app))
    router.add_route("POST", "/admin/apps/{name}/restart", _app_scoped(handlers.handler_restart_app))
    router.add_route("GET", "/admin/apps/{name}/status", _app_scoped(handlers.handler_status_app))
    router.add_route("GET", "/admin/apps/{name}/logs", _app_scoped(handlers.handler_logs_app))
    router.add_route("GET", "/admin/apps/{name}/access-logs", _app_scoped(handlers.handler_access_logs_app))
    router.add_route("POST", "/admin/apps/{name}/deploy", _app_scoped(handlers.handler_deploy_app))

    router.add_route("GET", "/admin/deployments", handlers.handler_list_deployments)
    router.add_route("GET", "/admin/deployments/{id}", handlers.handler_get_deployment)
    router.add_route("POST", "/admin/deployments/{id}/rollback", handlers.handler_rollback_deployment)

    router.add_route("POST", "/admin/keys", identity_handlers.handler_create_key)
    router.add_route("GET", "/admin/keys", identity_handlers.handler_list_keys)
    router.add_route("DELETE", "/admin/keys/{id}", identity_handlers.handler_revoke_key)

    router.add_route("GET", "/admin/roles", identity_handlers.handler_list_roles)
    router.add_route("POST", "/admin/roles", identity_handlers.handler_create_role)

    return router
