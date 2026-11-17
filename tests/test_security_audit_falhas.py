"""Passo 3a - semantica de falha do Auditor (criterios 2/3/4/11/12/13 no nivel do audit)."""
import sys

import pytest

from core import security_audit as sa
from tests.helpers.audit_fakes import AlertadorFalso, DestinoFalso, StderrCapturado


def _ev(tipo="AUTORIZADA", decision_id="d1", seq=2):
    return sa.novo_evento(tipo, "authorized", decision_id=decision_id, seq=seq)


def _auditor(principal_falha=False, fila_falha=False):
    p, f = DestinoFalso("principal", principal_falha), DestinoFalso("fila", fila_falha)
    a = AlertadorFalso()
    return sa.Auditor(p, f, alertador=a), p, f, a


def test_modo_invalido_e_rejeitado():
    auditor, *_ = _auditor()
    with pytest.raises(ValueError):
        auditor.emitir(_ev(), "outro")


def test_principal_saudavel_grava_no_principal_e_nao_toca_a_fila():
    for modo in ("humano", "automatico"):
        auditor, p, f, a = _auditor()
        assert auditor.emitir(_ev(), modo) == "principal"
        assert len(p.eventos) == 1 and f.tentativas == 0 and a.chamadas == []


def test_humano_com_principal_falhando_nao_executa_mesmo_com_fila_saudavel():  # criterio 11
    auditor, p, f, a = _auditor(principal_falha=True, fila_falha=False)
    ev = _ev()
    with pytest.raises(sa.AuditIndisponivel) as info:
        auditor.emitir(ev, "humano")
    assert info.value.destinos_falhos == ("principal",)
    assert info.value.event_id == ev["event_id"] and info.value.decision_id == "d1"
    assert f.tentativas == 0 and f.eventos == []  # a fila NAO substitui o principal
    assert len(a.chamadas) == 1  # alerta emitido


def test_automatico_com_principal_falhando_so_prossegue_depois_da_fila_confirmar():  # criterios 3 e 12
    auditor, p, f, a = _auditor(principal_falha=True)
    ev = _ev()
    assert auditor.emitir(ev, "automatico") == "fila"
    assert f.eventos == [ev]  # o MESMO evento, mesmo event_id/decision_id/seq
    assert auditor.degradacoes == 1


def test_automatico_com_os_dois_falhando_nao_prossegue_e_alerta():  # criterios 4 e 12
    auditor, p, f, a = _auditor(principal_falha=True, fila_falha=True)
    with pytest.raises(sa.AuditIndisponivel) as info:
        auditor.emitir(_ev(), "automatico")
    assert info.value.destinos_falhos == ("principal", "fila")
    assert len(a.chamadas) == 1
    mensagem, dados = a.chamadas[0]
    assert dados["destinos_falhos"] == ["principal", "fila"]
    assert dados["decision_id"] == "d1"


def test_audit_indisponivel_e_categoria_propria():
    assert not issubclass(sa.AuditIndisponivel, (ValueError, OSError))
    assert sa.AuditIndisponivel.__mro__[1] is Exception


def test_alerta_nao_carrega_payload_nem_segredos():
    auditor, p, f, a = _auditor(principal_falha=True, fila_falha=True)
    ev = sa.novo_evento("config.changed", "success", payload={"api_key": "SEGREDO", "v": "x"})
    with pytest.raises(sa.AuditIndisponivel):
        auditor.emitir(ev, "automatico")
    assert "SEGREDO" not in repr(a.chamadas) and "payload" not in repr(a.chamadas)


def test_resultado_vai_ao_principal_quando_saudavel():
    auditor, p, f, a = _auditor()
    r = auditor.emitir_resultado(_ev("EXECUTADA", seq=3))
    assert (r.destino, r.perda_de_rastreabilidade) == ("principal", False)
    assert f.tentativas == 0


def test_resultado_com_principal_falhando_vai_para_a_fila_com_a_mesma_correlacao():  # criterio 13
    auditor, p, f, a = _auditor(principal_falha=True)
    ev = _ev("EXECUTADA", decision_id="d9", seq=3)
    r = auditor.emitir_resultado(ev)
    assert (r.destino, r.perda_de_rastreabilidade) == ("fila", False)
    assert f.eventos[0]["decision_id"] == "d9" and f.eventos[0]["seq"] == 3
    assert a.chamadas == []


def test_resultado_com_os_dois_falhando_nao_levanta_e_sinaliza_perda():  # criterio 13
    auditor, p, f, a = _auditor(principal_falha=True, fila_falha=True)
    ev = _ev("EXECUTADA", seq=3)
    r = auditor.emitir_resultado(ev)  # nao levanta: a acao ja ocorreu
    assert (r.destino, r.perda_de_rastreabilidade) == ("perdido", True)
    assert len(a.chamadas) == 1
    # o evento recebido nao e reclassificado
    assert ev["event_type"] == "EXECUTADA" and ev["outcome"] == "authorized"


def test_resultado_nunca_levanta_nem_com_destinos_quebrados():
    class Quebrado:
        ultimo_erro = "X"
        def gravar(self, ev):
            raise RuntimeError("bug")
        def esta_vazia(self):
            raise RuntimeError("bug")
    auditor = sa.Auditor(Quebrado(), Quebrado(), alertador=AlertadorFalso())
    r = auditor.emitir_resultado(_ev("EXECUTADA", seq=3))
    assert r.perda_de_rastreabilidade is True


def test_alertador_tenta_notify_antes_do_stderr(monkeypatch):
    chamadas = []
    from core import notify
    monkeypatch.setattr(notify, "enviar", lambda msg, dados_extra=None: chamadas.append(msg) or True)
    cap = StderrCapturado()
    monkeypatch.setattr(sys, "stderr", cap)
    assert sa.Alertador().alertar("falha", {"a": 1}) == "webhook"
    assert chamadas == ["falha"] and cap.texto() == ""


def test_alertador_cai_para_stderr_quando_notify_falha_ou_nao_configurado(monkeypatch):
    from core import notify
    cap = StderrCapturado()
    monkeypatch.setattr(sys, "stderr", cap)
    monkeypatch.setattr(notify, "enviar", lambda msg, dados_extra=None: False)
    assert sa.Alertador().alertar("falha", {"a": 1}) == "stderr"
    assert "falha" in cap.texto()

    def explode(msg, dados_extra=None):
        raise RuntimeError("rede")
    monkeypatch.setattr(notify, "enviar", explode)
    cap2 = StderrCapturado()
    monkeypatch.setattr(sys, "stderr", cap2)
    assert sa.Alertador().alertar("falha2") == "stderr"
    assert "falha2" in cap2.texto()


def test_alertador_nao_usa_alerts_log(monkeypatch, tmp_path):
    from core import defense, notify
    monkeypatch.setattr(notify, "enviar", lambda *a, **k: False)
    monkeypatch.setattr(sys, "stderr", StderrCapturado())
    chamadas = []
    monkeypatch.setattr(defense, "registrar_alerta", lambda *a, **k: chamadas.append(a))
    sa.Alertador().alertar("falha")
    assert chamadas == []


def test_alertador_dedup_por_chave(monkeypatch):
    from core import notify
    monkeypatch.setattr(notify, "enviar", lambda *a, **k: False)
    monkeypatch.setattr(sys, "stderr", StderrCapturado())
    al = sa.Alertador()
    assert al.alertar("x", chave_dedup=("ip", "m")) == "stderr"
    assert al.alertar("x", chave_dedup=("ip", "m")) == "suprimido"
    assert al.alertar("x", chave_dedup=("ip2", "m")) == "stderr"
    assert al.alertar("x") == "stderr" and al.alertar("x") == "stderr"
