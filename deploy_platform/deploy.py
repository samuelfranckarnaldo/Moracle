"""
Orquestra o fluxo de deployment:

codigo -> validar config -> criar deployment -> (iniciar app, se
start_callback fornecido) -> health check -> promover ou falhar.

'Iniciar aplicacao' e' pluggavel via start_callback (ex: subir um
processo, ou apenas confirmar que o Router ja esta pronto) - o
Moracle nao assume dono do processo de build/run de qualquer
linguagem arbitraria.
"""
from deploy_platform import registry
from deploy_platform.models import DeploymentStatus
from deploy_platform.health_check import checar_saude


class DeployError(Exception):
    def __init__(self, message, deployment_id=None):
        super().__init__(message)
        self.message = message
        self.deployment_id = deployment_id


def validar_config_deploy(app_name, source_path, health_check_path):
    erros = []
    if not app_name or not isinstance(app_name, str):
        erros.append("app_name deve ser uma string nao vazia")
    if not source_path or not isinstance(source_path, str):
        erros.append("source_path deve ser uma string nao vazia")
    if not health_check_path or not health_check_path.startswith("/"):
        erros.append("health_check_path deve comecar com '/'")
    return erros


def deploy(app_name, source_path, health_check_base_url, health_check_path="/health",
           domain=None, host_router=None, router=None, start_callback=None,
           health_check_tentativas=3):
    """
    Fluxo completo de deployment. Retorna o Deployment final (com
    status ACTIVE ou FAILED). Levanta DeployError se a config for
    invalida antes mesmo de criar o deployment.

    host_router + router: se fornecidos, o router da aplicacao e'
    registrado no HostRouter da plataforma quando o deploy for bem
    sucedido - e' isso que efetivamente 'disponibiliza' a app.
    """
    erros_config = validar_config_deploy(app_name, source_path, health_check_path)
    if erros_config:
        raise DeployError("configuracao de deploy invalida: " + "; ".join(erros_config))

    registry.criar_ou_obter_app(app_name, domain=domain)
    deployment = registry.criar_deployment(app_name, source_path, health_check_path)

    registry.atualizar_status_deployment(deployment.deployment_id, DeploymentStatus.STARTING.value)

    if start_callback is not None:
        try:
            start_callback()
        except Exception as e:
            registry.atualizar_status_deployment(
                deployment.deployment_id, DeploymentStatus.FAILED.value,
                error_message=f"start_callback falhou: {e}",
            )
            return registry.obter_deployment(deployment.deployment_id)

    registry.atualizar_status_deployment(deployment.deployment_id, DeploymentStatus.HEALTH_CHECK.value)

    saudavel, detalhe = checar_saude(
        health_check_base_url, health_check_path, tentativas=health_check_tentativas
    )

    if not saudavel:
        registry.atualizar_status_deployment(
            deployment.deployment_id, DeploymentStatus.FAILED.value, error_message=detalhe
        )
        return registry.obter_deployment(deployment.deployment_id)

    registry.atualizar_status_deployment(deployment.deployment_id, DeploymentStatus.ACTIVE.value)
    registry.promover_deployment(app_name, deployment.deployment_id)

    if host_router is not None and router is not None and domain:
        host_router.registrar_dominio(domain, router, app_name)

    return registry.obter_deployment(deployment.deployment_id)


def rollback(app_name, deployment_id, host_router=None, router=None):
    """Promove um deployment ja existente de volta a CURRENT - nao
    cria deployment novo, nao roda health check de novo (assume que
    o deployment anterior ja foi validado quando criado)."""
    deployment = registry.obter_deployment(deployment_id)
    if deployment is None or deployment.app_name != app_name:
        raise DeployError(f"deployment {deployment_id!r} nao encontrado para app {app_name!r}")

    registry.promover_deployment(app_name, deployment_id)

    if host_router is not None and router is not None:
        app = registry.obter_app(app_name)
        if app and app.domain:
            host_router.registrar_dominio(app.domain, router, app_name)

    return deployment
