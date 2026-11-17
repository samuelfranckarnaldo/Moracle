"""
Middleware de plataforma que resolve qual Router usar com base no
Host header, antes de delegar para o handler real. Fica ANTES do
router.match() do app resolvido.

Tambem anexa a identidade da aplicacao (app_name) ao context, vinda
da mesma associacao dominio->router do HostRouter - nunca inferida
aqui nem em nenhum outro lugar do pipeline.
"""
from server.response import Response
from deploy_platform.host_router import HostRouter


def criar_host_dispatch_middleware(host_router: HostRouter):
    def middleware(request, context, next):
        host_header = request.header("host")
        try:
            router_resolvido = host_router.resolver_router(host_header)
            app_name_resolvido = host_router.resolver_app_name(host_header)
        except Exception:
            return Response.text("Not Found", status=404)

        context["resolved_router"] = router_resolvido
        context["app_name"] = app_name_resolvido
        return next(request, context)

    return middleware
