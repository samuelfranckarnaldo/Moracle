"""
Persistencia de Applications e Deployments - reusa atomic_state.py
(lock + escrita atomica) ja validado sob 100 threads concorrentes no
core do Moracle. Nao reinventa mecanismo de concorrencia aqui.
"""
import os
import time
import uuid

from core.atomic_state import modificar_json_com_lock, ler_json
from core import config
from deploy_platform.models import Application, Deployment, DeploymentStatus, ProcessHandle, RuntimeSnapshot

PLATFORM_DIR = os.path.join(config.RAIZ_PROJETO, ".state", "platform")
APPS_FILE = os.path.join(PLATFORM_DIR, "applications.json")
DEPLOYMENTS_FILE = os.path.join(PLATFORM_DIR, "deployments.json")
PROCESS_HANDLES_FILE = os.path.join(PLATFORM_DIR, "process_handles.json")


def _garantir_dir():
    os.makedirs(PLATFORM_DIR, exist_ok=True)


def criar_ou_obter_app(nome, domain=None):
    _garantir_dir()

    def _modificar(apps_atuais):
        apps_atuais = dict(apps_atuais)
        if nome not in apps_atuais:
            apps_atuais[nome] = Application(name=nome, domain=domain).to_dict()
        elif domain:
            apps_atuais[nome]["domain"] = domain
        return apps_atuais

    apps = modificar_json_com_lock(APPS_FILE, _modificar, padrao={})
    return Application.from_dict(apps[nome])


def obter_app(nome):
    apps = ler_json(APPS_FILE, {})
    if nome not in apps:
        return None
    return Application.from_dict(apps[nome])


def listar_apps():
    apps = ler_json(APPS_FILE, {})
    return [Application.from_dict(a) for a in apps.values()]


def app_por_dominio(dominio):
    for app in listar_apps():
        if app.domain == dominio:
            return app
    return None


def criar_deployment(app_name, source_path, health_check_path="/health", runtime_snapshot=None):
    """runtime_snapshot: dict (RuntimeSnapshot.to_dict()) opcional -
    quando fornecido, congela a configuracao de execucao deste
    deployment especifico. Parametro aditivo com default None -
    chamadores existentes continuam funcionando sem mudanca."""
    _garantir_dir()
    deployment_id = f"deployment-{uuid.uuid4().hex[:8]}"
    deployment = Deployment(
        app_name=app_name,
        deployment_id=deployment_id,
        created_at=time.time(),
        source_path=source_path,
        health_check_path=health_check_path,
        runtime_snapshot=runtime_snapshot,
    )

    def _salvar_deployment(deployments_atuais):
        deployments_atuais = dict(deployments_atuais)
        deployments_atuais[deployment_id] = deployment.to_dict()
        return deployments_atuais

    modificar_json_com_lock(DEPLOYMENTS_FILE, _salvar_deployment, padrao={})

    def _registrar_no_app(apps_atuais):
        apps_atuais = dict(apps_atuais)
        app_dict = apps_atuais.get(app_name) or Application(name=app_name).to_dict()
        app_dict["deployment_ids"] = app_dict.get("deployment_ids", []) + [deployment_id]
        apps_atuais[app_name] = app_dict
        return apps_atuais

    modificar_json_com_lock(APPS_FILE, _registrar_no_app, padrao={})
    return deployment


def atualizar_status_deployment(deployment_id, status, error_message=None):
    def _modificar(deployments_atuais):
        deployments_atuais = dict(deployments_atuais)
        if deployment_id in deployments_atuais:
            deployments_atuais[deployment_id]["status"] = status
            if error_message:
                deployments_atuais[deployment_id]["error_message"] = error_message
        return deployments_atuais

    modificar_json_com_lock(DEPLOYMENTS_FILE, _modificar, padrao={})


def obter_deployment(deployment_id):
    deployments = ler_json(DEPLOYMENTS_FILE, {})
    if deployment_id not in deployments:
        return None
    return Deployment.from_dict(deployments[deployment_id])


def promover_deployment(app_name, deployment_id):
    """Torna este deployment o CURRENT do app - equivalente a
    'colocar em producao'. Nao apaga deployments antigos (permite
    rollback)."""
    def _modificar(apps_atuais):
        apps_atuais = dict(apps_atuais)
        app_dict = apps_atuais.get(app_name) or Application(name=app_name).to_dict()
        app_dict["current_deployment_id"] = deployment_id
        apps_atuais[app_name] = app_dict
        return apps_atuais

    modificar_json_com_lock(APPS_FILE, _modificar, padrao={})


def listar_deployments_do_app(app_name):
    app = obter_app(app_name)
    if not app:
        return []
    return [obter_deployment(did) for did in app.deployment_ids if obter_deployment(did)]


def salvar_process_handle(process_handle):
    """Persiste um ProcessHandle - lock+escrita atomica, mesmo padrao
    de tudo mais neste registry."""
    _garantir_dir()

    def _salvar(handles_atuais):
        handles_atuais = dict(handles_atuais)
        handles_atuais[process_handle.id] = process_handle.to_dict()
        return handles_atuais

    modificar_json_com_lock(PROCESS_HANDLES_FILE, _salvar, padrao={})


def obter_process_handle(handle_id):
    handles = ler_json(PROCESS_HANDLES_FILE, {})
    if handle_id not in handles:
        return None
    return ProcessHandle.from_dict(handles[handle_id])


def listar_process_handles():
    handles = ler_json(PROCESS_HANDLES_FILE, {})
    return [ProcessHandle.from_dict(h) for h in handles.values()]


def salvar_application_completa(application):
    """Persiste uma Application com todos os campos de runtime
    (working_directory, start_command, etc.) - diferente de
    criar_ou_obter_app, que so cuida de name/domain."""
    _garantir_dir()

    def _salvar(apps_atuais):
        apps_atuais = dict(apps_atuais)
        apps_atuais[application.name] = application.to_dict()
        return apps_atuais

    modificar_json_com_lock(APPS_FILE, _salvar, padrao={})


def atualizar_deployment_processo(deployment_id, application_id, process_handle_id):
    def _modificar(deployments_atuais):
        deployments_atuais = dict(deployments_atuais)
        if deployment_id in deployments_atuais:
            deployments_atuais[deployment_id]["application_id"] = application_id
            deployments_atuais[deployment_id]["process_handle_id"] = process_handle_id
        return deployments_atuais

    modificar_json_com_lock(DEPLOYMENTS_FILE, _modificar, padrao={})


def atualizar_processo_atual_da_app(app_name, process_handle_id):
    def _modificar(apps_atuais):
        apps_atuais = dict(apps_atuais)
        app_dict = apps_atuais.get(app_name) or Application(name=app_name).to_dict()
        app_dict["current_process_handle_id"] = process_handle_id
        apps_atuais[app_name] = app_dict
        return apps_atuais

    modificar_json_com_lock(APPS_FILE, _modificar, padrao={})


def remover_app(app_name):
    """Remove uma Application do registro. Nao verifica se ha processo
    rodando - essa checagem e' responsabilidade de quem chama (Admin
    API), que deve recusar a remocao se houver processo ativo."""
    def _modificar(apps_atuais):
        apps_atuais = dict(apps_atuais)
        apps_atuais.pop(app_name, None)
        return apps_atuais

    modificar_json_com_lock(APPS_FILE, _modificar, padrao={})
