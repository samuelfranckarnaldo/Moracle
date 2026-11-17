"""
Application Manager - orquestra process_manager, application_lifecycle
e registry para dar ao Moracle o ciclo de vida completo de processos
de Application: criar, iniciar, parar, reiniciar, status, logs,
deploy (parar atual -> iniciar novo -> health check -> promover/FAILED)
e rollback real (parar atual -> iniciar processo com o RUNTIME
SNAPSHOT do deployment alvo, nao a config atual da Application ->
health check -> promover).

Cada Deployment carrega seu proprio RuntimeSnapshot (working_directory,
start_command, environment, port, health_check_path) congelado no
momento em que foi criado. Isso torna rollback correto de verdade:
reexecuta exatamente o que rodava naquele deployment, mesmo que a
Application ja tenha sido reconfigurada depois.

Todo o ciclo start/stop/health/persistencia de uma mesma Application
acontece sob um unico lock por Application - garante que nunca dois
processos da mesma Application rodam simultaneamente, mesmo sob
chamadas concorrentes de deploy()/rollback()/reiniciar().

parar() e' idempotente: chamar em uma Application ja parada retorna
STOPPED sem erro.

Recovery: ao inicializar, le os ProcessHandles persistidos e
reconcilia o estado real (processo ainda vivo? e' o mesmo processo,
confirmado por PID+starttime, ou o PID foi reaproveitado por outro
processo?). Nunca assume que um PID "vivo" e' o processo certo sem
confirmar a identidade.
"""
import os
import threading
import time
import uuid

from deploy_platform import registry, process_manager as pm
from deploy_platform.models import Application, ProcessHandle, DeploymentStatus, RuntimeSnapshot
from deploy_platform.application_lifecycle import ApplicationLifecycle, ApplicationState, ApplicationLifecycleError
from deploy_platform.health_check import checar_saude
from core import config

LOGS_DIR = os.path.join(config.RAIZ_PROJETO, ".state", "platform", "process_logs")


class ApplicationManagerError(Exception):
    pass


class IdentidadeIndeterminadaError(ApplicationManagerError):
    """A identidade do processo nao pode ser confirmada: nenhum sinal foi enviado."""


class FalhaAoPararProcessoError(ApplicationManagerError):
    """O processo continua vivo depois de SIGTERM/SIGKILL."""


class ApplicationManager:
    def __init__(self):
        self._locks_por_app = {}
        self._locks_meta_lock = threading.Lock()
        self._lifecycles = {}

    def _lock_da_app(self, app_name):
        with self._locks_meta_lock:
            if app_name not in self._locks_por_app:
                self._locks_por_app[app_name] = threading.Lock()
            return self._locks_por_app[app_name]

    def _lifecycle_da_app(self, app_name):
        if app_name not in self._lifecycles:
            self._lifecycles[app_name] = ApplicationLifecycle()
        return self._lifecycles[app_name]

    # ---------- criação ----------

    def criar_application(self, name, working_directory, start_command,
                           environment=None, port=None, health_check_path="/health",
                           domain=None, restart_policy_mode="NEVER",
                           restart_policy_max_retries=None,
                           restart_policy_backoff_seconds=5.0):
        if not isinstance(start_command, list) or not start_command:
            raise ApplicationManagerError("start_command deve ser lista de argumentos nao vazia")

        app = Application(
            name=name, domain=domain, working_directory=working_directory,
            start_command=start_command, environment=environment or {},
            port=port, health_check_path=health_check_path,
            restart_policy_mode=restart_policy_mode,
            restart_policy_max_retries=restart_policy_max_retries,
            restart_policy_backoff_seconds=restart_policy_backoff_seconds,
        )
        registry.salvar_application_completa(app)
        self._lifecycle_da_app(name)
        return app

    # ---------- runtime snapshot ----------

    def _snapshot_atual_da_app(self, app):
        """Congela a configuracao ATUAL da Application - usado quando
        um novo deploy() e' criado (o snapshot passa a representar
        aquele deployment especifico dali em diante)."""
        return RuntimeSnapshot(
            working_directory=app.working_directory,
            start_command=app.start_command,
            environment=dict(app.environment or {}),
            port=app.port,
            health_check_path=app.health_check_path,
        )

    def _snapshot_de_deployment(self, app, deployment):
        """Le o snapshot congelado de um deployment ja existente.
        Fallback documentado: deployments criados antes do
        RuntimeSnapshot existir nao tem um - nesse caso usamos a
        config atual da Application (comportamento antigo), o que e'
        uma limitacao conhecida, nao um erro silencioso."""
        if deployment is not None:
            snapshot = deployment.get_runtime_snapshot()
            if snapshot is not None:
                return snapshot
        return self._snapshot_atual_da_app(app)

    # ---------- ciclo de processo ----------

    def _caminhos_de_log(self, deployment_id):
        os.makedirs(LOGS_DIR, exist_ok=True)
        return (
            os.path.join(LOGS_DIR, f"{deployment_id}.stdout.log"),
            os.path.join(LOGS_DIR, f"{deployment_id}.stderr.log"),
        )

    def _iniciar_processo_com_snapshot(self, app_name, deployment_id, snapshot):
        stdout_path, stderr_path = self._caminhos_de_log(deployment_id)
        info = pm.iniciar_processo(
            snapshot.start_command, snapshot.working_directory, snapshot.environment,
            stdout_path, stderr_path,
        )
        handle = ProcessHandle(
            id=f"proc-{uuid.uuid4().hex[:8]}",
            application_id=app_name,
            deployment_id=deployment_id,
            pid=info["pid"],
            starttime=info["starttime"],
            started_at=time.time(),
            stdout_log_path=stdout_path,
            stderr_log_path=stderr_path,
        )
        registry.salvar_process_handle(handle)
        registry.atualizar_deployment_processo(deployment_id, app_name, handle.id)
        registry.atualizar_processo_atual_da_app(app_name, handle.id)
        return handle

    def _parar_processo_atual(self, app, forcar=False, timeout_graceful=10):
        if not app.current_process_handle_id:
            return
        handle = registry.obter_process_handle(app.current_process_handle_id)
        if handle is None:
            return
        identidade = pm.confirmar_identidade(handle.pid, handle.starttime)
        if identidade is False:
            return  # ja nao e' mais o mesmo processo, nada a parar
        if identidade is None and not forcar:
            raise IdentidadeIndeterminadaError(
                f"identidade do processo {handle.pid} de {app.name!r} nao pode ser confirmada; "
                "nenhum sinal foi enviado (use forcar para parar mesmo assim)"
            )
        if not pm.parar_processo(handle.pid, timeout_graceful=timeout_graceful):
            raise FalhaAoPararProcessoError(
                f"processo {handle.pid} de {app.name!r} continua vivo apos SIGTERM/SIGKILL"
            )

    def iniciar(self, app_name, deployment_id):
        """Inicia um processo para um deployment especifico, usando o
        RuntimeSnapshot DAQUELE deployment (nao a config atual da
        Application). Deve ser chamado sob o lock da Application -
        deploy()/rollback() ja seguram esse lock."""
        app = registry.obter_app(app_name)
        if app is None:
            raise ApplicationManagerError(f"application {app_name!r} nao encontrada")

        deployment = registry.obter_deployment(deployment_id)
        snapshot = self._snapshot_de_deployment(app, deployment)

        if not snapshot.start_command:
            raise ApplicationManagerError(f"deployment {deployment_id!r} sem start_command utilizavel")

        lifecycle = self._lifecycle_da_app(app_name)
        try:
            lifecycle.transition(ApplicationState.STARTING)
        except ApplicationLifecycleError:
            lifecycle.force_set(ApplicationState.STARTING)

        handle = self._iniciar_processo_com_snapshot(app_name, deployment_id, snapshot)
        lifecycle.transition(ApplicationState.RUNNING)
        return handle

    def parar(self, app_name, timeout_graceful=10, forcar=False):
        """Idempotente: chamar numa Application ja parada retorna
        STOPPED sem levantar erro."""
        lock = self._lock_da_app(app_name)
        with lock:
            app = registry.obter_app(app_name)
            if app is None:
                raise ApplicationManagerError(f"application {app_name!r} nao encontrada")

            lifecycle = self._lifecycle_da_app(app_name)
            estado_anterior = lifecycle.state
            try:
                lifecycle.transition(ApplicationState.STOPPING)
            except ApplicationLifecycleError:
                lifecycle.force_set(ApplicationState.STOPPING)

            try:
                self._parar_processo_atual(app, forcar=forcar, timeout_graceful=timeout_graceful)
            except ApplicationManagerError:
                # nada foi confirmado como parado: mantem o handle e restaura o estado
                lifecycle.force_set(estado_anterior)
                raise
            registry.atualizar_processo_atual_da_app(app_name, None)

            try:
                lifecycle.transition(ApplicationState.STOPPED)
            except ApplicationLifecycleError:
                lifecycle.force_set(ApplicationState.STOPPED)

    def status(self, app_name):
        app = registry.obter_app(app_name)
        if app is None:
            raise ApplicationManagerError(f"application {app_name!r} nao encontrada")

        lifecycle = self._lifecycle_da_app(app_name)
        resultado = {"application": app_name, "lifecycle_state": lifecycle.state.name,
                     "pid": None, "uptime_seconds": None, "identity": "NONE"}

        if app.current_process_handle_id:
            handle = registry.obter_process_handle(app.current_process_handle_id)
            if handle:
                vivo = pm.confirmar_identidade(handle.pid, handle.starttime)
                resultado["identity"] = "CONFIRMED" if vivo is True else ("DEAD" if vivo is False else "UNKNOWN")
                if vivo is True:
                    resultado["pid"] = handle.pid
                    resultado["uptime_seconds"] = time.time() - handle.started_at
                elif vivo is None:
                    resultado["unconfirmed_pid"] = handle.pid
        return resultado

    def logs(self, app_name, linhas=100):
        app = registry.obter_app(app_name)
        if app is None or not app.current_process_handle_id:
            return {"stdout": "", "stderr": ""}
        handle = registry.obter_process_handle(app.current_process_handle_id)
        if handle is None:
            return {"stdout": "", "stderr": ""}

        def _ler_ultimas_linhas(caminho):
            if not os.path.exists(caminho):
                return ""
            with open(caminho, "rb") as f:
                conteudo = f.read().decode("utf-8", errors="replace")
            return "\n".join(conteudo.splitlines()[-linhas:])

        return {"stdout": _ler_ultimas_linhas(handle.stdout_log_path),
                "stderr": _ler_ultimas_linhas(handle.stderr_log_path)}

    # ---------- deploy / rollback (opção A: parar -> iniciar -> health -> promover) ----------

    def deploy(self, app_name, health_check_base_url=None, health_check_tentativas=3):
        """Fluxo: parar processo atual -> criar deployment (congela a
        config ATUAL da Application no seu RuntimeSnapshot) -> iniciar
        novo processo com esse snapshot -> health check -> promove
        (ACTIVE) ou marca FAILED, preservando o deployment anterior
        intacto para rollback. Tudo sob o lock da Application."""
        lock = self._lock_da_app(app_name)
        with lock:
            app = registry.obter_app(app_name)
            if app is None or not app.start_command:
                raise ApplicationManagerError(f"application {app_name!r} nao encontrada ou sem start_command")

            self._parar_processo_atual(app)
            registry.atualizar_processo_atual_da_app(app_name, None)

            snapshot = self._snapshot_atual_da_app(app)
            deployment = registry.criar_deployment(
                app_name, app.working_directory, app.health_check_path,
                runtime_snapshot=snapshot.to_dict(),
            )
            registry.atualizar_status_deployment(deployment.deployment_id, DeploymentStatus.STARTING.value)

            try:
                self.iniciar(app_name, deployment.deployment_id)
            except Exception as e:
                registry.atualizar_status_deployment(
                    deployment.deployment_id, DeploymentStatus.FAILED.value,
                    error_message=f"falha ao iniciar processo: {e}",
                )
                self._lifecycle_da_app(app_name).force_set(ApplicationState.CRASHED)
                return registry.obter_deployment(deployment.deployment_id)

            registry.atualizar_status_deployment(deployment.deployment_id, DeploymentStatus.HEALTH_CHECK.value)

            url_saude = health_check_base_url or f"http://127.0.0.1:{snapshot.port}"
            saudavel, detalhe = checar_saude(url_saude, snapshot.health_check_path, tentativas=health_check_tentativas)

            if not saudavel:
                registry.atualizar_status_deployment(
                    deployment.deployment_id, DeploymentStatus.FAILED.value, error_message=detalhe,
                )
                self._lifecycle_da_app(app_name).transition(ApplicationState.UNHEALTHY)
                return registry.obter_deployment(deployment.deployment_id)

            registry.atualizar_status_deployment(deployment.deployment_id, DeploymentStatus.ACTIVE.value)
            registry.promover_deployment(app_name, deployment.deployment_id)
            self._lifecycle_da_app(app_name).transition(ApplicationState.HEALTHY)
            return registry.obter_deployment(deployment.deployment_id)

    def rollback(self, app_name, deployment_id, health_check_base_url=None, health_check_tentativas=3):
        """Rollback real: parar processo atual -> iniciar NOVO
        processo usando o RuntimeSnapshot DO DEPLOYMENT ALVO (nao a
        config atual da Application) -> health check -> promove ou
        falha, preservando o deployment que estava ativo antes."""
        lock = self._lock_da_app(app_name)
        with lock:
            deployment_alvo = registry.obter_deployment(deployment_id)
            if deployment_alvo is None or deployment_alvo.app_name != app_name:
                raise ApplicationManagerError(f"deployment {deployment_id!r} nao encontrado para {app_name!r}")

            app = registry.obter_app(app_name)
            if app is None:
                raise ApplicationManagerError(f"application {app_name!r} nao encontrada")

            snapshot = self._snapshot_de_deployment(app, deployment_alvo)
            if not snapshot.start_command:
                raise ApplicationManagerError(f"deployment {deployment_id!r} sem start_command utilizavel para rollback")

            self._parar_processo_atual(app)
            registry.atualizar_processo_atual_da_app(app_name, None)

            try:
                self._iniciar_processo_com_snapshot(app_name, deployment_id, snapshot)
            except Exception as e:
                self._lifecycle_da_app(app_name).force_set(ApplicationState.CRASHED)
                raise ApplicationManagerError(f"rollback falhou ao iniciar processo: {e}")

            self._lifecycle_da_app(app_name).force_set(ApplicationState.RUNNING)

            url_saude = health_check_base_url or f"http://127.0.0.1:{snapshot.port}"
            saudavel, detalhe = checar_saude(url_saude, snapshot.health_check_path, tentativas=health_check_tentativas)

            if not saudavel:
                registry.atualizar_status_deployment(
                    deployment_id, DeploymentStatus.FAILED.value, error_message=f"rollback health check falhou: {detalhe}",
                )
                self._lifecycle_da_app(app_name).transition(ApplicationState.UNHEALTHY)
                raise ApplicationManagerError(f"rollback: health check falhou apos iniciar processo: {detalhe}")

            registry.atualizar_status_deployment(deployment_id, DeploymentStatus.ACTIVE.value)
            registry.promover_deployment(app_name, deployment_id)
            self._lifecycle_da_app(app_name).transition(ApplicationState.HEALTHY)
            return registry.obter_deployment(deployment_id)

    def reiniciar(self, app_name):
        app = registry.obter_app(app_name)
        if app is None or not app.current_deployment_id:
            raise ApplicationManagerError(f"application {app_name!r} sem deployment ativo para reiniciar")
        return self.deploy(app_name)

    # ---------- recovery / reconcile ----------

    def reconciliar_no_startup(self):
        """Le todos os ProcessHandles persistidos e confirma se o
        processo que cada um referencia ainda e' o mesmo (PID +
        starttime). Nunca assume que um PID 'vivo' e' o processo
        certo - PID pode ter sido reaproveitado pelo SO. Resultado
        possivel por handle: CONFIRMED_RUNNING, CONFIRMED_DEAD,
        UNKNOWN (nao foi possivel confirmar identidade - tratado como
        CRASHED por seguranca, nunca como RUNNING)."""
        resultado = {}
        for handle in registry.listar_process_handles():
            identidade = pm.confirmar_identidade(handle.pid, handle.starttime)
            app = registry.obter_app(handle.application_id)
            e_atual = app is not None and app.current_process_handle_id == handle.id

            if identidade is True:
                rotulo = "CONFIRMED_RUNNING"
            elif identidade is False:
                rotulo = "CONFIRMED_DEAD"
            else:
                rotulo = "UNKNOWN"

            if not e_atual:
                # handle historico (deploy anterior, app removida): nunca mexe no
                # estado da app; processo ainda vivo aqui e' um processo vazado.
                resultado[handle.id] = "ORPHAN_RUNNING" if identidade is True else rotulo
                continue

            resultado[handle.id] = rotulo
            lifecycle = self._lifecycle_da_app(handle.application_id)
            if identidade is True:
                lifecycle.force_set(ApplicationState.RUNNING)
            elif identidade is False:
                lifecycle.force_set(ApplicationState.CRASHED)
                registry.atualizar_processo_atual_da_app(handle.application_id, None)
            else:
                # UNKNOWN: nunca RUNNING, mas o handle continua ligado a app para nao
                # virar processo orfao (parar/deploy recusam ate o operador decidir)
                lifecycle.force_set(ApplicationState.CRASHED)

        return resultado
