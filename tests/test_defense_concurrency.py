import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import threading
import shutil

from core import defense, config


import pytest

pytestmark = pytest.mark.usefixtures("estado_isolado")

def _limpar_estado_teste():
    if os.path.exists(defense.STATE_DIR):
        shutil.rmtree(defense.STATE_DIR)


def test_bloqueio_concorrente_100_threads_sem_perda():
    """100 threads bloqueando 100 IPs diferentes ao mesmo tempo -
    nenhum deve se perder por causa de escrita concorrente."""
    _limpar_estado_teste()
    try:
        total_threads = 100
        erros = []

        def bloquear(indice):
            try:
                defense.bloquear_ip(f"10.0.{indice // 256}.{indice % 256}", motivo=f"teste {indice}")
            except Exception as e:
                erros.append(e)

        threads = [threading.Thread(target=bloquear, args=(i,)) for i in range(total_threads)]
        for th in threads:
            th.start()
        for th in threads:
            th.join(timeout=15)

        assert not erros, f"erros durante bloqueio concorrente: {erros}"
        blocklist = defense.carregar_blocklist()
        assert len(blocklist) == total_threads, f"esperado {total_threads} IPs, achou {len(blocklist)}"
    finally:
        _limpar_estado_teste()


def test_alertas_concorrentes_nenhuma_linha_perdida():
    _limpar_estado_teste()
    try:
        total = 50

        def registrar(i):
            defense.registrar_alerta(f"192.168.1.{i}", "teste", f"conteudo {i}")

        threads = [threading.Thread(target=registrar, args=(i,)) for i in range(total)]
        for th in threads:
            th.start()
        for th in threads:
            th.join(timeout=15)

        alertas = defense.ler_alertas_recentes(limite=total + 10)
        assert len(alertas) == total, f"esperado {total} linhas, achou {len(alertas)}"
    finally:
        _limpar_estado_teste()
