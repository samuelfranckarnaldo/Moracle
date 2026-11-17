"""Passo 3a - fila persistente e reconciliacao idempotente (criterios 5 e 14)."""
import json
import os
import stat

import pytest

from core import security_audit as sa
from tests.helpers.audit_fakes import AlertadorFalso, DestinoFalso


def _destinos(tmp_path):
    return (sa.DestinoJsonl(str(tmp_path / "principal" / "eventos.jsonl")),
            sa.FilaDuravel(str(tmp_path / "fila" / "fila_eventos.jsonl")))


def _ev(i, decision_id=None, seq=None):
    return sa.novo_evento("t.evento", "ok", payload={"i": i}, decision_id=decision_id, seq=seq)


def _ids(destino):
    return [e["event_id"] for e in destino.ler_eventos()]


def test_fila_e_persistente_apos_reinicio(tmp_path):
    principal, fila = _destinos(tmp_path)
    ev = _ev(1, "d1", 1)
    assert fila.gravar(ev) is True
    # "reinicio": instancias novas sobre os mesmos caminhos
    principal2, fila2 = _destinos(tmp_path)
    assert _ids(fila2) == [ev["event_id"]]
    assert not fila2.esta_vazia()
    assert stat.S_IMODE(os.stat(fila2.caminho()).st_mode) == 0o600
    r = sa.reconciliar(fila2, principal2)
    assert r.movidos == 1 and r.restantes == 0
    assert _ids(principal2) == [ev["event_id"]]
    assert fila2.esta_vazia()


def test_reconciliacao_preserva_ids_seq_e_timestamp_e_acrescenta_reconciled_at(tmp_path):
    principal, fila = _destinos(tmp_path)
    ev = sa.novo_evento("EXECUTADA", "executed", decision_id="d7", seq=3,
                        timestamp="2026-01-02T03:04:05+00:00", payload={"ip": "1.2.3.4"})
    fila.gravar(ev)
    sa.reconciliar(fila, principal)
    (gravado,) = principal.ler_eventos()
    for campo in ("event_id", "decision_id", "seq", "timestamp", "event_type", "outcome", "payload"):
        assert gravado[campo] == ev[campo]
    assert "reconciled_at" in gravado and gravado["reconciled_at"] != ev["timestamp"]
    assert "reconciled_at" not in ev  # o original nao e alterado


def test_reconciliar_duas_vezes_nao_duplica(tmp_path):  # criterio 14
    principal, fila = _destinos(tmp_path)
    evs = [_ev(i, "d1", i + 1) for i in range(5)]
    for e in evs:
        fila.gravar(e)
    r1 = sa.reconciliar(fila, principal)
    r2 = sa.reconciliar(fila, principal)
    assert r1.movidos == 5 and r2.movidos == 0
    assert sorted(_ids(principal)) == sorted(e["event_id"] for e in evs)
    assert len(_ids(principal)) == 5


def test_reemissao_com_o_mesmo_event_id_na_fila_nao_reinsere(tmp_path):  # criterio 14
    principal, fila = _destinos(tmp_path)
    ev = _ev(1)
    assert principal.gravar(ev) is True
    fila.gravar(ev)  # mesma tentativa reaparece na fila (event_id reutilizado)
    r = sa.reconciliar(fila, principal)
    assert r.descartados_duplicados == 1 and r.movidos == 0
    assert _ids(principal) == [ev["event_id"]]
    assert fila.esta_vazia()


def test_dedup_por_decision_id_e_seq_mesmo_com_event_id_diferente(tmp_path):
    principal, fila = _destinos(tmp_path)
    a = _ev(1, "d1", 2)
    b = sa.novo_evento("t.evento", "ok", decision_id="d1", seq=2)  # outro event_id, mesma transicao
    principal.gravar(a)
    fila.gravar(b)
    r = sa.reconciliar(fila, principal)
    assert r.descartados_duplicados == 1 and len(_ids(principal)) == 1
    # seq diferente na mesma decisao NAO e duplicado
    c = sa.novo_evento("t.evento", "ok", decision_id="d1", seq=3)
    fila.gravar(c)
    assert sa.reconciliar(fila, principal).movidos == 1
    assert len(_ids(principal)) == 2


def test_interrupcao_entre_gravar_no_principal_e_reescrever_a_fila_nao_duplica(tmp_path, monkeypatch):
    principal, fila = _destinos(tmp_path)
    evs = [_ev(i, "d1", i + 1) for i in range(3)]
    for e in evs:
        fila.gravar(e)

    def cai(caminho, linhas):
        raise OSError("queda antes de remover da fila")
    monkeypatch.setattr(sa, "_reescrever_fila", cai)
    r = sa.reconciliar(fila, principal)  # nao levanta
    assert r.erro == "OSError" and r.principal_indisponivel is False  # I/O tratado sem levantar
    # os eventos estao nos DOIS lados
    assert len(_ids(principal)) == 3 and len(_ids(fila)) == 3

    monkeypatch.undo()
    principal2, fila2 = _destinos(tmp_path)
    r2 = sa.reconciliar(fila2, principal2)
    assert r2.descartados_duplicados == 3 and r2.movidos == 0
    assert len(_ids(principal2)) == 3 and fila2.esta_vazia()


def test_evento_so_sai_da_fila_depois_da_confirmacao_do_principal(tmp_path):
    principal, fila = _destinos(tmp_path)
    evs = [_ev(i) for i in range(4)]
    for e in evs:
        fila.gravar(e)

    class PrincipalQueFalhaNoTerceiro(sa.DestinoJsonl):
        def __init__(self, base):
            super().__init__(base.caminho())
            self.n = 0
        def gravar(self, ev):
            self.n += 1
            if self.n == 3:
                self.ultimo_erro = "OSError"
                return False
            return super().gravar(ev)

    p = PrincipalQueFalhaNoTerceiro(principal)
    r = sa.reconciliar(fila, p)
    assert r.movidos == 2 and r.principal_indisponivel is True and r.restantes == 2
    assert _ids(fila) == [evs[2]["event_id"], evs[3]["event_id"]]
    assert _ids(principal) == [evs[0]["event_id"], evs[1]["event_id"]]
    # recuperado o principal, o resto flui sem duplicar
    r2 = sa.reconciliar(fila, principal)
    assert r2.movidos == 2 and fila.esta_vazia()
    assert len(set(_ids(principal))) == 4 == len(_ids(principal))


def test_principal_ilegivel_deixa_a_fila_intacta(tmp_path):
    principal, fila = _destinos(tmp_path)
    fila.gravar(_ev(1))
    antes = open(fila.caminho(), "rb").read()

    class PrincipalIlegivel(sa.DestinoJsonl):
        def ids_existentes(self):
            raise OSError("sem leitura")
    r = sa.reconciliar(fila, PrincipalIlegivel(principal.caminho()))
    assert r.principal_indisponivel is True and r.movidos == 0
    assert open(fila.caminho(), "rb").read() == antes


def test_linha_ilegivel_na_fila_permanece_sem_bloquear_as_demais(tmp_path):
    principal, fila = _destinos(tmp_path)
    fila.gravar(_ev(1))
    with open(fila.caminho(), "a", encoding="utf-8") as f:
        f.write("isto nao e json\n")
    fila.gravar(_ev(2))
    r = sa.reconciliar(fila, principal)
    assert r.movidos == 2 and r.ilegiveis == 1 and r.restantes == 1
    assert open(fila.caminho(), encoding="utf-8").read().strip() == "isto nao e json"


def test_reconciliacao_respeita_o_maximo_por_chamada(tmp_path):
    principal, fila = _destinos(tmp_path)
    for i in range(5):
        fila.gravar(_ev(i))
    r = sa.reconciliar(fila, principal, maximo=2)
    assert r.movidos == 2 and r.restantes == 3
    assert sa.reconciliar(fila, principal, maximo=10).movidos == 3


def test_reconciliar_fila_inexistente_ou_vazia_nao_faz_nada(tmp_path):
    principal, fila = _destinos(tmp_path)
    r = sa.reconciliar(fila, principal)
    assert (r.movidos, r.restantes) == (0, 0)
    assert not os.path.exists(principal.caminho())


def test_auditor_reconcilia_oportunisticamente_antes_de_emitir(tmp_path):  # Q6
    principal, fila = _destinos(tmp_path)
    pendente = _ev(1, "d1", 1)
    fila.gravar(pendente)
    auditor = sa.Auditor(principal, fila, alertador=AlertadorFalso())
    novo = _ev(2, "d2", 1)
    assert auditor.emitir(novo, "automatico") == "principal"
    ids = _ids(principal)
    assert pendente["event_id"] in ids and novo["event_id"] in ids
    assert fila.esta_vazia()


def test_degradacao_e_recuperacao_ponta_a_ponta(tmp_path):
    principal, fila = _destinos(tmp_path)
    estado = {"cai": True}

    class PrincipalInstavel(sa.DestinoJsonl):
        def gravar(self, ev):
            if estado["cai"]:
                self.ultimo_erro = "OSError"
                return False
            return super().gravar(ev)
        def ids_existentes(self):
            if estado["cai"]:
                raise OSError("fora")
            return super().ids_existentes()

    p = PrincipalInstavel(principal.caminho())
    auditor = sa.Auditor(p, fila, alertador=AlertadorFalso())
    e1, e2 = _ev(1, "d1", 1), _ev(2, "d1", 2)
    assert auditor.emitir(e1, "automatico") == "fila"
    assert auditor.emitir(e2, "automatico") == "fila"
    assert not fila.esta_vazia() and auditor.degradacoes == 2
    estado["cai"] = False
    e3 = _ev(3, "d1", 3)
    assert auditor.emitir(e3, "automatico") == "principal"
    assert [e["seq"] for e in sorted(principal.ler_eventos(), key=lambda e: e["seq"])] == [1, 2, 3]
    assert fila.esta_vazia()
