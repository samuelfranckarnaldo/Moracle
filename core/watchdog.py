"""
Watchdog multiplataforma — mantém o defense.monitorar() rodando,
reiniciando sozinho se o processo cair por qualquer motivo.
Funciona igual em Linux, Windows, macOS e Termux (puro Python, sem
dependências de SO).
"""
import time
import traceback
from core import defense
from core.i18n import t


def rodar_com_reinicio(log_file, intervalo=None, limite_alerta=None, espera_reinicio=5):
    while True:
        try:
            defense.monitorar(log_file, intervalo=intervalo, limite_alerta=limite_alerta)
            break  # saiu limpo (Ctrl+C dentro do monitorar) — não reinicia
        except KeyboardInterrupt:
            break
        except Exception:
            print(f"[WATCHDOG] Falha inesperada, reiniciando em {espera_reinicio}s...")
            traceback.print_exc()
            time.sleep(espera_reinicio)
