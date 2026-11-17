"""Passo 3c - /block e /ingest ligados ao ciclo de SecurityAction.

Chama os handlers diretamente (mesma assinatura do router) com Auditor
de destinos falsos injetado em core.security_runtime; o ultimo bloco usa
destinos reais em disco. Estado de defesa isolado por `estado_isolado`.
"""
import json
import os
import stat

import pytest

from core import defense
from core import moracle_adapter as A
from core import security_audit as sa
from core import security_policy as P
from core import security_runtime as rt
from core.identity import ApiKey
from server.request import Context, Request
from tests.helpers.audit_fakes import AlertadorFalso, DestinoFalso

pytestmark = pytest.mark.usefixtures("estado_isolado")

PAYLOAD_SQLI = {"ip": "198.51.100.77", "method": "GET",
                "path": "/product?id=1 UNION SELECT NULL--",
                "user_agent": "curl/8.0", "status_code": 200}


class DestinoPorTipo(DestinoFalso):
    def __init__(self, nome, falhar=False, falhar_em=()):
        super().__init__(nome, falhar)
        self.falhar_em = set(falhar_em)

    def gravar(self, evento):
        if evento["event_type"] in self.falhar_em:
            self.tentativas += 1
            self.ultimo_erro = "OSError"
            return False
        return super().gravar(evento)


def _req(corpo, caminho="/block"):
    return Request("POST", caminho, {}, {}, json.dumps(corpo).encode(), "HTTP/1.1", ("127.0.0.1", 0))


def _ctx(com_chave=True):
    c = Context("req-abc123")
    if com_chave:
        c["api_key"] = ApiKey(id="k1", key_hash="HASH-SECRETO", name="n",
                              role_name="admin", created_at="2026-01-01T00:00:00+00:00")
    return c


def _corpo(resp):
    return json.loads(resp.body)


@pytest.fixture
def ambiente(monkeypatch):
    principal = DestinoPorTipo("principal")
    fila = DestinoPorTipo("fila")
    alerta = AlertadorFalso()
    monkeypatch.setattr(rt, "fabrica_auditor", lambda: sa.Auditor(principal, fila, alertador=alerta))
    monkeypatch.setattr(rt, "_alertador", alerta)
    return principal, fila, alerta


def _tipos(destino):
    return [e["event_type"] for e in destino.eventos]


# ------------------------------------------------------------------ /block

def test_block_caminho_feliz_registra_tres_eventos_e_bloqueia(ambiente):
    principal, fila, alerta = ambiente
    resp = A.handler_block(_req({"ip": "192.0.2.50", "reason": "manual"}), _ctx())
    assert resp.status == 200
    corpo = _corpo(resp)
    assert corpo["blocked"] == "192.0.2.50" and "info" in corpo
    assert defense.ip_bloqueado("192.0.2.50")
    assert _tipos(principal) == ["PROPOSTA", "AUTORIZADA", "EXECUTADA"]
    assert len({e["decision_id"] for e in principal.eventos}) == 1
    assert [e["seq"] for e in principal.eventos] == [1, 2, 3]
    assert fila.eventos == []


def test_block_actor_origin_e_correlation_vem_do_contexto(ambiente):
    principal, _, _ = ambiente
    A.handler_block(_req({"ip": "192.0.2.51"}), _ctx())
    ev = principal.eventos[0]
    assert ev["actor"]["identity"] == {"key_id": "k1", "role": "admin"}
    assert "automatic" not in ev["actor"]
    assert ev["origin"] == "http"
    assert ev["correlation_id"] == "req-abc123"
    assert ev["payload"]["source"] == {"type": "humano", "id": "admin"}


def test_eventos_nunca_levam_hash_nem_segredo_da_chave(ambiente):
    principal, _, _ = ambiente
    A.handler_block(_req({"ip": "192.0.2.52"}), _ctx())
    assert "HASH-SECRETO" not in json.dumps(principal.eventos)


def test_block_sem_identidade_no_contexto_nao_inventa_identity(ambiente):
    # ator_http nao preenche identity por inferencia
    assert "identity" not in rt.ator_http(_ctx(com_chave=False))
    assert "automatic" not in rt.ator_http(_ctx())


def test_block_audit_principal_falha_devolve_503_e_nao_executa_mesmo_com_fila_saudavel(ambiente):
    principal, fila, alerta = ambiente  # criterio 11
    principal.falhar = True
    resp = A.handler_block(_req({"ip": "192.0.2.53"}), _ctx())
    assert resp.status == 503
    assert _corpo(resp) == {"error": "audit unavailable"}
    assert not defense.ip_bloqueado("192.0.2.53")
    assert fila.eventos == []
    assert alerta.chamadas


def test_block_falha_ao_gravar_autorizada_503_e_nao_executa(ambiente):
    principal, fila, alerta = ambiente
    principal.falhar_em = {"AUTORIZADA"}
    resp = A.handler_block(_req({"ip": "192.0.2.54"}), _ctx())
    assert resp.status == 503
    assert not defense.ip_bloqueado("192.0.2.54")
    assert _tipos(principal) == ["PROPOSTA"]  # decisao orfa documentada (Q4)


def test_block_fabrica_do_auditor_falha_503_fail_closed(monkeypatch):
    alerta = AlertadorFalso()
    monkeypatch.setattr(rt, "_alertador", alerta)

    def quebra():
        raise sa.ErroDeConfiguracaoAudit("caminhos iguais")
    monkeypatch.setattr(rt, "fabrica_auditor", quebra)
    resp = A.handler_block(_req({"ip": "192.0.2.55"}), _ctx())
    assert resp.status == 503 and _corpo(resp) == {"error": "audit unavailable"}
    assert not defense.ip_bloqueado("192.0.2.55")
    assert alerta.chamadas and alerta.chamadas[0][1]["erro_classe"] == "ErroDeConfiguracaoAudit"


def test_block_ip_invalido_400_antes_do_registry_sem_evento(ambiente):
    principal, fila, alerta = ambiente  # Q8
    for ip in ("nao-e-ip", "127.0.0.1", "999.1.1.1"):
        resp = A.handler_block(_req({"ip": ip}), _ctx())
        assert resp.status == 400, ip
    assert principal.eventos == [] and fila.eventos == [] and alerta.chamadas == []


def test_block_corpo_invalido_continua_400_sem_evento(ambiente):
    principal, _, _ = ambiente
    assert A.handler_block(_req({"x": 1}), _ctx()).status == 400
    assert principal.eventos == []


def test_block_expiracao_invalida_400_com_mensagem_e_evento_falha_execucao(ambiente):
    principal, _, _ = ambiente
    resp = A.handler_block(_req({"ip": "192.0.2.56", "expires_hours": -5}), _ctx())
    assert resp.status == 400
    assert "error" in _corpo(resp) and _corpo(resp)["error"]
    assert not defense.ip_bloqueado("192.0.2.56")
    assert _tipos(principal) == ["PROPOSTA", "AUTORIZADA", "FALHA_EXECUCAO"]  # nunca NEGADA


def test_block_expiracao_valida_e_repassada_ao_bloqueio(ambiente):
    resp = A.handler_block(_req({"ip": "192.0.2.57", "expires_hours": 2}), _ctx())
    assert resp.status == 200
    assert _corpo(resp)["info"]  # bloquear_ip devolveu o registro
    assert defense.ip_bloqueado("192.0.2.57")


def test_block_resultado_nao_gravado_no_principal_vai_para_fila_e_resposta_continua_200(ambiente):
    principal, fila, alerta = ambiente  # criterio 13
    principal.falhar_em = {"EXECUTADA"}
    resp = A.handler_block(_req({"ip": "192.0.2.58"}), _ctx())
    assert resp.status == 200
    assert defense.ip_bloqueado("192.0.2.58")
    assert _tipos(fila) == ["EXECUTADA"]
    assert fila.eventos[0]["decision_id"] == principal.eventos[0]["decision_id"]


def test_block_resultado_perdido_nos_dois_destinos_alerta_e_nao_vira_falha(ambiente):
    principal, fila, alerta = ambiente
    principal.falhar_em = {"EXECUTADA"}
    fila.falhar = True
    resp = A.handler_block(_req({"ip": "192.0.2.59"}), _ctx())
    assert resp.status == 200  # a acao ocorreu
    assert defense.ip_bloqueado("192.0.2.59")
    assert alerta.chamadas


def test_block_negada_pela_policy_403_sem_executar(ambiente, monkeypatch):
    principal, _, _ = ambiente

    class Nega:
        def avaliar(self, action):
            return P.Decisao(P.NEGADA, "teste")
    monkeypatch.setattr(rt, "policy", Nega())
    resp = A.handler_block(_req({"ip": "192.0.2.60"}), _ctx())
    assert resp.status == 403
    assert not defense.ip_bloqueado("192.0.2.60")
    assert _tipos(principal) == ["PROPOSTA", "NEGADA"]


def test_block_falha_inesperada_do_executor_500_sem_vazar_detalhes(ambiente, monkeypatch):
    principal, _, _ = ambiente

    class Quebra:
        def executar(self, action, expira_em_horas=None):
            raise RuntimeError("/data/segredo/caminho")
    monkeypatch.setattr(rt, "executor", Quebra())
    resp = A.handler_block(_req({"ip": "192.0.2.61"}), _ctx())
    assert resp.status == 500
    assert "segredo" not in resp.body.decode()
    assert _tipos(principal)[-1] == "FALHA_EXECUCAO"
    assert "segredo" not in json.dumps(principal.eventos)


# ----------------------------------------------------------------- /ingest

def test_ingest_alto_bloqueia_e_corpo_continua_o_mesmo(ambiente):
    principal, fila, alerta = ambiente
    resp = A.handler_ingest(_req(PAYLOAD_SQLI, "/ingest"), _ctx())
    assert resp.status == 200
    corpo = _corpo(resp)
    assert corpo["detected"] is True
    assert set(corpo["finding"]) == {"ip", "attack_type", "attack_name", "content",
                                     "confianca", "risco_score", "risco_nivel"}
    assert defense.ip_bloqueado("198.51.100.77")
    assert _tipos(principal) == ["PROPOSTA", "AUTORIZADA", "EXECUTADA"]


def test_ingest_actor_automatico_origin_risco_e_correlacao(ambiente):
    principal, _, _ = ambiente
    A.handler_ingest(_req(PAYLOAD_SQLI, "/ingest"), _ctx())
    ev = principal.eventos[0]
    assert ev["actor"]["automatic"] == "ingest"
    assert ev["actor"]["identity"] == {"key_id": "k1", "role": "admin"}
    assert ev["origin"] == "automatic:ingest"
    assert ev["correlation_id"] == "req-abc123"
    assert set(ev["payload"]["risk"]) == {"score", "nivel"}
    assert ev["payload"]["source"] == {"type": "automatico", "id": "ingest"}


def test_ingest_audit_principal_falha_fila_ok_executa_e_reconcilia_sem_duplicar(ambiente):
    principal, fila, alerta = ambiente  # criterio 3
    principal.falhar = True
    resp = A.handler_ingest(_req(PAYLOAD_SQLI, "/ingest"), _ctx())
    assert resp.status == 200
    assert defense.ip_bloqueado("198.51.100.77")
    assert _tipos(fila)[:2] == ["PROPOSTA", "AUTORIZADA"]
    ids = [e["event_id"] for e in fila.eventos]
    assert len(ids) == len(set(ids))


def test_ingest_dois_destinos_falham_nao_bloqueia_mantem_200_e_alerta(ambiente):
    principal, fila, alerta = ambiente  # Q2 / criterio 4
    principal.falhar = True
    fila.falhar = True
    resp = A.handler_ingest(_req(PAYLOAD_SQLI, "/ingest"), _ctx())
    assert resp.status == 200
    corpo = _corpo(resp)
    assert corpo["detected"] is True and corpo["finding"]["ip"] == "198.51.100.77"
    assert not defense.ip_bloqueado("198.51.100.77")
    assert alerta.chamadas


def test_ingest_fabrica_do_auditor_falha_nao_bloqueia_mantem_200(monkeypatch):
    alerta = AlertadorFalso()
    monkeypatch.setattr(rt, "_alertador", alerta)

    def quebra():
        raise sa.ErroDeConfiguracaoAudit("x")
    monkeypatch.setattr(rt, "fabrica_auditor", quebra)
    resp = A.handler_ingest(_req(PAYLOAD_SQLI, "/ingest"), _ctx())
    assert resp.status == 200 and _corpo(resp)["detected"] is True
    assert not defense.ip_bloqueado("198.51.100.77")
    assert alerta.chamadas


def test_ingest_excecao_inesperada_no_ciclo_nao_bloqueia_e_nao_derruba_a_resposta(ambiente, monkeypatch):
    class Quebra:
        def avaliar(self, action):
            raise RuntimeError("bug")
    monkeypatch.setattr(rt, "policy", Quebra())
    resp = A.handler_ingest(_req(PAYLOAD_SQLI, "/ingest"), _ctx())
    assert resp.status == 200 and _corpo(resp)["detected"] is True
    assert not defense.ip_bloqueado("198.51.100.77")


def test_ingest_ip_ja_bloqueado_nao_propoe_nova_acao(ambiente):
    principal, _, _ = ambiente
    defense.bloquear_ip("198.51.100.77", motivo="previo")
    resp = A.handler_ingest(_req(PAYLOAD_SQLI, "/ingest"), _ctx())
    assert resp.status == 200
    assert principal.eventos == []


def test_ingest_nao_detectado_nao_gera_evento(ambiente):
    principal, _, _ = ambiente
    limpo = {"ip": "203.0.113.1", "method": "GET", "path": "/index.html",
             "user_agent": "Mozilla", "status_code": 200}
    resp = A.handler_ingest(_req(limpo, "/ingest"), _ctx())
    assert _corpo(resp) == {"detected": False}
    assert principal.eventos == []


def test_ingest_loopback_detecta_mas_nao_propoe(ambiente):
    principal, _, _ = ambiente
    payload = dict(PAYLOAD_SQLI, ip="127.0.0.1")
    resp = A.handler_ingest(_req(payload, "/ingest"), _ctx())
    assert resp.status == 200 and _corpo(resp)["detected"] is True
    assert principal.eventos == []


# ----------------------------------------------------------- partida (Q6)

def test_reconciliar_na_partida_recupera_a_fila_sem_duplicar(tmp_path, monkeypatch):
    from tests.helpers.audit_fakes import isolar_config
    isolar_config(monkeypatch, tmp_path)
    principal = sa.DestinoJsonl(sa.caminho_eventos)
    fila = sa.FilaDuravel(sa.caminho_fila)
    ev = sa.novo_evento("config.changed", "success", payload={"k": 1}, origin="cli-local")
    assert fila.gravar(ev)
    monkeypatch.setattr(rt, "_alertador", AlertadorFalso())
    # 3d-1 (declarado): o retorno passa de texto para ResultadoPartida
    assert rt.reconciliar_na_partida().estado == "reconciliada"
    assert [e["event_id"] for e in principal.ler_eventos()] == [ev["event_id"]]
    assert fila.esta_vazia()
    assert rt.reconciliar_na_partida().estado == "vazia"
    assert len(principal.ler_eventos()) == 1


def test_reconciliar_na_partida_com_config_invalida_nao_levanta_e_avisa(tmp_path, monkeypatch):
    from tests.helpers.audit_fakes import isolar_config
    isolar_config(monkeypatch, tmp_path, auditoria={
        "arquivo_eventos": "a/ev.jsonl", "diretorio_fila": "a"})
    alerta = AlertadorFalso()
    monkeypatch.setattr(rt, "_alertador", alerta)
    estado = rt.reconciliar_na_partida()  # 3d-1 (declarado): ResultadoPartida
    assert estado.estado == "falhou" and estado.detalhe["causa"] == "configuracao_invalida"
    assert alerta.chamadas


# ---------------------------------------------- ponta a ponta, destinos reais

def test_ponta_a_ponta_com_arquivos_reais_0600_e_sem_segredo(tmp_path, monkeypatch):
    from tests.helpers.audit_fakes import isolar_config
    isolar_config(monkeypatch, tmp_path)
    monkeypatch.setattr(rt, "_alertador", AlertadorFalso())
    resp = A.handler_block(_req({"ip": "192.0.2.70", "reason": "e2e"}), _ctx())
    assert resp.status == 200
    caminho = sa.caminho_eventos()
    assert stat.S_IMODE(os.stat(caminho).st_mode) == 0o600
    with open(caminho) as f:
        linhas = [json.loads(x) for x in f if x.strip()]
    assert [x["event_type"] for x in linhas] == ["PROPOSTA", "AUTORIZADA", "EXECUTADA"]
    assert "HASH-SECRETO" not in open(caminho).read()
    assert not os.path.exists(sa.caminho_fila()) or sa.FilaDuravel(sa.caminho_fila).esta_vazia()
