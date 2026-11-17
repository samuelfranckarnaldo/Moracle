"""Passo 3b - SecurityAction, maquina de estados e Registry (criterios 1, 2, 6)."""
import itertools
import json

import pytest

from core import security_actions as S
from core import security_audit as sa


def _registry():
    contador = itertools.count(1)
    return S.Registry(gerador_id=lambda: "d%d" % next(contador))


def _acao(registry=None, **kw):
    registry = registry or _registry()
    args = dict(action_type="block_ip", alvo=("ip", "203.0.113.5"),
                origem=("humano", "admin"), motivo="manual", origin="http",
                actor={"identity": {"key_id": "k1", "role": "admin"}})
    args.update(kw)
    return registry, registry.propor(**args)


def test_propor_cria_em_proposta_seq_1_com_decision_id_do_registry():
    reg, a = _acao()
    assert (a.estado, a.seq, a.decision_id) == (S.PROPOSTA, 1, "d1")
    assert a.alvo == ("ip", "203.0.113.5") and a.origem == ("humano", "admin")
    assert reg.propor("block_ip", ("ip", "1.1.1.1"), ("humano", "a"), "x", origin="cli-local").decision_id == "d2"


def test_decision_id_padrao_e_unico_uuid_hex():
    reg = S.Registry()
    ids = {reg.propor("block_ip", ("ip", "1.1.1.1"), ("humano", "a"), "x", origin="http").decision_id
           for _ in range(50)}
    assert len(ids) == 50 and all(len(i) == 32 for i in ids)


def test_propor_valida_campos_e_nao_infere_nada():
    reg = _registry()
    base = dict(action_type="block_ip", alvo=("ip", "1.1.1.1"), origem=("humano", "a"), motivo="m", origin="http")
    for kw in ({"action_type": ""}, {"alvo": ("ip",)}, {"alvo": ("ip", "")}, {"alvo": "1.1.1.1"},
               {"origem": ("robo", "x")}, {"origem": ("humano",)}, {"origin": None}, {"origin": "local-shell"},
               {"actor": {"usuario": "x"}}, {"risco": {"x": object()}}):
        args = dict(base)
        args.update(kw)
        with pytest.raises(ValueError):
            reg.propor(**args)
    # actor nao e preenchido: sem actor => actor vazio
    assert reg.propor(**base).actor == {}


def test_acao_automatica_exige_actor_automatic_igual_a_origem():
    reg = _registry()
    base = dict(action_type="block_ip", alvo=("ip", "1.1.1.1"), origem=("automatico", "ingest"),
                motivo="m", origin="http")
    with pytest.raises(ValueError):
        reg.propor(**base)  # sem actor.automatic
    with pytest.raises(ValueError):
        reg.propor(actor={"automatic": "watchdog"}, **base)  # componente diferente
    a = reg.propor(actor={"automatic": "ingest", "identity": {"key_id": "k", "role": "ingest"}}, **base)
    assert a.actor["automatic"] == "ingest" and "os_user" not in a.actor


def test_motivo_e_sanitizado_como_em_bloquear_ip():
    reg, a = _acao(motivo="linha1\nlinha2\x00" + "x" * 500)
    assert "\n" not in a.motivo and "\x00" not in a.motivo and len(a.motivo) == 200


def test_transicoes_validas_do_contrato():
    esperadas = {
        S.PROPOSTA: {S.NEGADA, S.AUTORIZADA, S.AGUARDANDO_CONFIRMACAO},
        S.AUTORIZADA: {S.EXECUTADA, S.FALHA_EXECUCAO},
        S.AGUARDANDO_CONFIRMACAO: {S.CONFIRMADA, S.EXPIRADA},
        S.CONFIRMADA: {S.EXECUTADA, S.FALHA_EXECUCAO},
    }
    assert {k: set(v) for k, v in S.TRANSICOES.items()} == esperadas
    assert S.TERMINAIS == {S.NEGADA, S.EXPIRADA, S.EXECUTADA, S.FALHA_EXECUCAO}
    assert set(S.ESTADOS) == set(S.OUTCOMES)


def _caminhar(reg, a, *destinos):
    for d in destinos:
        reg.aplicar(reg.preparar(a, d))
    return a


def test_todos_os_caminhos_validos_chegam_ao_terminal():
    caminhos = [
        (S.NEGADA,), (S.AUTORIZADA, S.EXECUTADA), (S.AUTORIZADA, S.FALHA_EXECUCAO),
        (S.AGUARDANDO_CONFIRMACAO, S.EXPIRADA),
        (S.AGUARDANDO_CONFIRMACAO, S.CONFIRMADA, S.EXECUTADA),
        (S.AGUARDANDO_CONFIRMACAO, S.CONFIRMADA, S.FALHA_EXECUCAO),
    ]
    for caminho in caminhos:
        reg, a = _acao()
        _caminhar(reg, a, *caminho)
        assert a.terminal and a.estado == caminho[-1] and a.seq == len(caminho) + 1


def test_atalhos_e_transicoes_fora_do_contrato_sao_rejeitados():
    reg, a = _acao()
    for destino in (S.EXECUTADA, S.FALHA_EXECUCAO, S.CONFIRMADA, S.EXPIRADA, S.PROPOSTA, "OUTRA"):
        with pytest.raises(S.TransicaoInvalida):
            reg.preparar(a, destino)
    _caminhar(reg, a, S.AUTORIZADA)
    for destino in (S.NEGADA, S.CONFIRMADA, S.AGUARDANDO_CONFIRMACAO, S.AUTORIZADA):
        with pytest.raises(S.TransicaoInvalida):
            reg.preparar(a, destino)
    _caminhar(reg, a, S.EXECUTADA)
    for destino in S.ESTADOS:  # terminal: nada sai dele
        with pytest.raises(S.TransicaoInvalida):
            reg.preparar(a, destino)


def test_preparar_nao_altera_a_acao_e_aplicar_so_uma_vez():
    reg, a = _acao()
    t = reg.preparar(a, S.AUTORIZADA)
    assert (a.estado, a.seq) == (S.PROPOSTA, 1)  # preparar nao muda nada
    reg.aplicar(t)
    assert (a.estado, a.seq) == (S.AUTORIZADA, 2)
    with pytest.raises(S.TransicaoInvalida):  # reaplicar a mesma transicao
        reg.aplicar(t)
    t_velha = reg.preparar(a, S.EXECUTADA)
    reg.aplicar(reg.preparar(a, S.FALHA_EXECUCAO))
    with pytest.raises(S.TransicaoInvalida):  # transicao preparada antes de outra ser aplicada
        reg.aplicar(t_velha)


def test_cada_transicao_gera_um_evento_com_o_mesmo_decision_id_e_seq_crescente():  # criterio 1
    reg, a = _acao(risco={"score": 80, "nivel": "alto"}, correlation_id="rid-1")
    eventos = [reg.evento_proposta(a)]
    for d in (S.AUTORIZADA, S.EXECUTADA):
        t = reg.preparar(a, d)
        eventos.append(t.evento)
        reg.aplicar(t)
    assert [e["event_type"] for e in eventos] == [S.PROPOSTA, S.AUTORIZADA, S.EXECUTADA]
    assert [e["seq"] for e in eventos] == [1, 2, 3]
    assert {e["decision_id"] for e in eventos} == {a.decision_id}
    assert len({e["event_id"] for e in eventos}) == 3
    assert len({(e["decision_id"], e["seq"]) for e in eventos}) == 3  # chave de deduplicacao
    for e in eventos:
        assert e["correlation_id"] == "rid-1" and e["origin"] == "http"
        assert e["actor"] == {"identity": {"key_id": "k1", "role": "admin"}}  # sem os_user inferido
        p = e["payload"]
        assert p["action_type"] == "block_ip" and p["target"] == {"type": "ip", "id": "203.0.113.5"}
        assert p["source"] == {"type": "humano", "id": "admin"} and p["risk"] == {"score": 80, "nivel": "alto"}
        json.dumps(e)


def test_outcome_de_cada_evento_corresponde_ao_estado_alcancado():  # criterio 2
    reg, a = _acao()
    assert reg.evento_proposta(a)["outcome"] == "proposed"
    assert reg.preparar(a, S.NEGADA).evento["outcome"] == "denied"
    assert reg.preparar(a, S.AUTORIZADA).evento["outcome"] == "authorized"
    assert reg.preparar(a, S.AGUARDANDO_CONFIRMACAO).evento["outcome"] == "awaiting_confirmation"
    _caminhar(reg, a, S.AUTORIZADA)
    assert reg.preparar(a, S.EXECUTADA).evento["outcome"] == "executed"
    falha = reg.preparar(a, S.FALHA_EXECUCAO, {"error_class": "OSError"})
    assert falha.evento["outcome"] == "execution_failed" and falha.evento["event_type"] == "FALHA_EXECUCAO"
    assert falha.evento["payload"]["error_class"] == "OSError"


def test_risk_so_aparece_quando_ha_risco():
    reg, a = _acao()
    assert "risk" not in reg.evento_proposta(a)["payload"]


def test_payload_dos_eventos_passa_pela_redacao():
    reg, a = _acao(risco={"score": 1, "api_key": "SEGREDO"})
    assert "SEGREDO" not in json.dumps(reg.evento_proposta(a))
