"""
Monitora Applications com restart_policy != NEVER: detecta crash
(processo morreu sem parar() ter sido chamado) e reinicia respeitando
max_retries e backoff_seconds. Mesmo espirito de core/watchdog.py
(espera fixa, nao exponencial - simples e previsivel, facil de
testar).
"""
import sys
import threading
import time

from deploy_platform import registry, process_manager as pm
from deploy_platform.application_lifecycle import ApplicationState


class RestartWatchdog:
    def __init__(self, application_manager, intervalo_verificacao=2):
        self.manager = application_manager
        self.intervalo_verificacao = intervalo_verificacao
        self._stop_event = threading.Event()
        self._thread = None
        self._tentativas_por_app = {}
        self._avisados = set()

    def _verificar_uma_vez(self, app_name):
        app = registry.obter_app(app_name)
        if app is None:
            return

        if not app.current_process_handle_id:
            return  # aplicacao parada deliberadamente, nada a monitorar

        handle = registry.obter_process_handle(app.current_process_handle_id)
        if handle is None:
            return

        identidade = pm.confirmar_identidade(handle.pid, handle.starttime)
        if identidade is True:
            self._tentativas_por_app[app_name] = 0  # processo saudavel, zera contador
            return

        if identidade is None:
            # nunca assumimos rodando NEM morto sem confirmacao: nada de
            # reconciliar, desanexar ou reiniciar (evita orfao e duplicata)
            if handle.id not in self._avisados:
                self._avisados.add(handle.id)
                print(f"[watchdog] {app_name}: identidade do processo {handle.pid} indeterminada; "
                      "reinicio e reconciliacao automaticos suspensos", file=sys.stderr)
            return

        # processo morreu (False)
        # Reconciliar sempre acontece, independente da policy: um
        # processo morto nunca deveria continuar sendo referenciado
        # como "current", mesmo que a Application nao va reiniciar.
        lifecycle = self.manager._lifecycle_da_app(app_name)
        lifecycle.force_set(ApplicationState.CRASHED)
        registry.atualizar_processo_atual_da_app(app_name, None)

        if app.restart_policy_mode == "NEVER":
            return  # reconciliado, mas nao reinicia - decisao explicita da policy

        if app.restart_policy_mode not in ("ON_FAILURE", "ALWAYS"):
            return

        tentativas_atuais = self._tentativas_por_app.get(app_name, 0)
        if app.restart_policy_max_retries is not None and tentativas_atuais >= app.restart_policy_max_retries:
            return  # esgotou tentativas, nao reinicia mais

        time.sleep(app.restart_policy_backoff_seconds)
        self._tentativas_por_app[app_name] = tentativas_atuais + 1

        try:
            self.manager.deploy(app_name)
        except Exception:
            pass  # proxima verificacao tenta de novo, respeitando max_retries

    def verificar_todas_uma_vez(self):
        """Exposto separadamente do loop continuo para permitir teste
        deterministico (sem depender de sleep/threading no teste)."""
        for app in registry.listar_apps():
            self._verificar_uma_vez(app.name)

    def _loop(self):
        while not self._stop_event.is_set():
            self.verificar_todas_uma_vez()
            time.sleep(self.intervalo_verificacao)

    def iniciar(self):
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def parar(self):
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=self.intervalo_verificacao + 5)
