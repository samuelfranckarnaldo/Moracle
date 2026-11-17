import json
import os

import pytest

from core import defense
from core.validacao_defesa import normalizar_ip, validar_expiracao, sanitizar_motivo

pytestmark = pytest.mark.usefixtures("estado_isolado")


@pytest.mark.parametrize("valor,esperado", [
    ("203.0.113.5", "203.0.113.5"),
    ("2001:DB8::1", "2001:db8::1"),
    ("::ffff:203.0.113.5", "203.0.113.5"),
])
def test_ip_valido_e_normalizado(valor, esperado):
    assert normalizar_ip(valor) == esperado


@pytest.mark.parametrize("valor", [
    "", " 1.2.3.4", "1.2.3.4\n", "999.1.1.1", "1.2.3", "abc", "١.٢.٣.٤",
    "127.0.0.1", "::1", "::ffff:127.0.0.1", "0.0.0.0", "224.0.0.1",
    "169.254.1.1", "fe80::1", "2001:db8::1%eth0", None, 5, ["1.1.1.1"],
])
def test_ip_invalido_ou_nao_bloqueavel(valor):
    with pytest.raises(ValueError):
        normalizar_ip(valor)


@pytest.mark.parametrize("valor,esperado", [(None, None), (0, None), (0.0, None), (1, 1), (2.5, 2.5), (8760, 8760)])
def test_expiracao_valida(valor, esperado):
    assert validar_expiracao(valor) == esperado


@pytest.mark.parametrize("valor", ["x", "5", True, False, -1, float("nan"), float("inf"), 8761, [1], {"a": 1}])
def test_expiracao_invalida(valor):
    with pytest.raises(ValueError):
        validar_expiracao(valor)


def test_sanitizar_motivo():
    assert sanitizar_motivo("a\nb\x1b[31m") == "a b [31m"
    assert sanitizar_motivo(None) == ""
    assert len(sanitizar_motivo("x" * 500)) == 200


def test_bloquear_ip_rejeita_expiracao_invalida_sem_gravar():
    with pytest.raises(ValueError):
        defense.bloquear_ip("203.0.113.9", expira_em_horas="x")
    assert defense.carregar_blocklist() == {}


def test_limpar_expirados_tolera_entradas_corrompidas():
    os.makedirs(defense.STATE_DIR, exist_ok=True)
    antigo = "2020-01-01T00:00:00+00:00"
    blocklist = {
        "203.0.113.1": {"bloqueado_em": antigo, "expira_em_horas": "x"},
        "203.0.113.2": {"bloqueado_em": "lixo", "expira_em_horas": 1},
        "203.0.113.3": "nao-e-dict",
        "203.0.113.4": {"expira_em_horas": 1},
        "203.0.113.5": {"bloqueado_em": antigo, "expira_em_horas": 1},
        "203.0.113.6": {"bloqueado_em": "2020-01-01T00:00:00", "expira_em_horas": 1},
    }
    with open(defense.BLOCKLIST_FILE, "w") as f:
        json.dump(blocklist, f)
    removidos = defense.limpar_expirados()
    assert sorted(removidos) == ["203.0.113.5", "203.0.113.6"]
    assert set(defense.carregar_blocklist()) == {"203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4"}
