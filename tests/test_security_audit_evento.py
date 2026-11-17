"""Passo 3a - esquema do evento e redacao (criterios 6 e 7)."""
import json

import pytest

from core import security_audit as sa
from tests.helpers.audit_fakes import isolar_config


def test_esquema_comum_e_campos_obrigatorios():
    ev = sa.novo_evento("ioc.imported", "success", payload={"fonte": "x", "importados": 3})
    assert ev["schema_version"] == 1
    assert len(ev["event_id"]) == 32
    assert ev["timestamp"].endswith("+00:00")
    assert ev["event_type"] == "ioc.imported"
    assert ev["outcome"] == "success"
    assert ev["actor"] == {}
    assert "decision_id" not in ev and "seq" not in ev
    json.dumps(ev)


def test_event_id_fornecido_e_conservado():
    ev = sa.novo_evento("x", "ok", event_id="abc", timestamp="2026-01-01T00:00:00+00:00")
    assert ev["event_id"] == "abc"
    assert ev["timestamp"] == "2026-01-01T00:00:00+00:00"


def test_actor_nunca_e_preenchido_por_inferencia():
    # sem actor: vazio, mesmo existindo usuario do SO
    assert sa.novo_evento("x", "ok")["actor"] == {}
    # None explicito nao e gravado
    ev = sa.novo_evento("x", "ok", actor={"os_user": None, "identity": None})
    assert ev["actor"] == {}
    # so os campos informados aparecem, independentes entre si
    ev = sa.novo_evento("x", "ok", actor={"os_user": "u0_a1"})
    assert ev["actor"] == {"os_user": "u0_a1"}
    ev = sa.novo_evento("x", "ok", actor={"automatic": "watchdog"})
    assert ev["actor"] == {"automatic": "watchdog"}
    ev = sa.novo_evento("x", "ok", actor={"identity": {"key_id": "k1", "role": "admin"}, "automatic": "ingest"})
    assert ev["actor"]["identity"] == {"key_id": "k1", "role": "admin"}
    assert "os_user" not in ev["actor"]


def test_actor_com_campo_desconhecido_e_rejeitado():
    with pytest.raises(ValueError):
        sa.novo_evento("x", "ok", actor={"usuario": "x"})
    with pytest.raises(ValueError):
        sa.novo_evento("x", "ok", actor="alguem")


def test_origin_validada():
    for o in ("cli-local", "http", "automatic:watchdog"):
        assert sa.novo_evento("x", "ok", origin=o)["origin"] == o
    for o in ("automatic:", "local-shell", "", 5):
        with pytest.raises(ValueError):
            sa.novo_evento("x", "ok", origin=o)
    assert "origin" not in sa.novo_evento("x", "ok")


def test_decision_id_e_seq_vem_juntos_e_seq_positivo():
    ev = sa.novo_evento("AUTORIZADA", "authorized", decision_id="d1", seq=2)
    assert ev["decision_id"] == "d1" and ev["seq"] == 2
    for kw in ({"decision_id": "d1"}, {"seq": 1}, {"decision_id": "d1", "seq": 0},
               {"decision_id": "d1", "seq": True}, {"decision_id": "", "seq": 1}):
        with pytest.raises(ValueError):
            sa.novo_evento("x", "ok", **kw)


def test_evento_mal_formado_ou_nao_serializavel_levanta_valueerror():
    for kw in ({"event_type": ""}, {"outcome": ""}):
        base = {"event_type": "x", "outcome": "ok"}
        base.update(kw)
        with pytest.raises(ValueError):
            sa.novo_evento(base["event_type"], base["outcome"])
    with pytest.raises(ValueError):
        sa.novo_evento("x", "ok", payload=["nao", "dict"])
    with pytest.raises(ValueError):
        sa.novo_evento("x", "ok", payload={"obj": object()})
    with pytest.raises(ValueError):
        sa.novo_evento("x", "ok", payload={"n": float("nan")})


def test_redacao_do_payload_sem_alterar_o_original():
    original = {"api_key": "SEGREDO", "token": None, "aninhado": {"password": "p"}, "ip": "1.2.3.4"}
    copia = json.loads(json.dumps(original))
    ev = sa.novo_evento("x", "ok", payload=original)
    assert ev["payload"] == {"api_key": "***", "token": None, "aninhado": {"password": "***"}, "ip": "1.2.3.4"}
    assert original == copia  # entrada intacta
    assert "SEGREDO" not in json.dumps(ev)


def test_config_changed_chave_nao_sensivel_guarda_anterior_e_novo():
    ev = sa.evento_config_changed("defesa.limite_alerta_padrao", 3, 999999,
                                  actor={"os_user": "u"}, origin="cli-local")
    assert ev["event_type"] == "config.changed"
    assert ev["outcome"] == "success"
    assert ev["payload"] == {"key": "defesa.limite_alerta_padrao", "previous_value": 3, "new_value": 999999}
    assert "decision_id" not in ev


def test_config_changed_cobre_chaves_de_efeito_de_seguranca():
    for chave in ("defesa.intervalo_padrao", "rate_limit.por_ip_max", "ioc_cache_validade_horas",
                  "diretorio_saida", "auditoria.arquivo_eventos"):
        ev = sa.evento_config_changed(chave, 1, 2)
        assert ev["payload"]["key"] == chave
        assert ev["payload"]["previous_value"] == 1 and ev["payload"]["new_value"] == 2


def test_config_changed_segredo_tem_os_dois_valores_redigidos():
    ev = sa.evento_config_changed("webhook_url", "https://velho/segredo", "https://novo/segredo")
    assert ev["payload"]["previous_value"] == "***"
    assert ev["payload"]["new_value"] == "***"
    texto = json.dumps(ev)
    assert "velho" not in texto and "novo/segredo" not in texto
    # None permanece None (sem segredo anterior)
    ev = sa.evento_config_changed("webhook_url", None, "https://novo/segredo")
    assert ev["payload"]["previous_value"] is None and ev["payload"]["new_value"] == "***"


def test_config_changed_chave_desconhecida_ou_com_nome_de_segredo_redige_valores():
    for chave in ("chave_inventada", "api_token", "x.y"):
        ev = sa.evento_config_changed(chave, "a", "b")
        assert ev["payload"]["previous_value"] == "***" and ev["payload"]["new_value"] == "***"


def test_config_changed_nome_da_chave_com_forma_estranha_e_mascarado():
    ev = sa.evento_config_changed("https://x.y/segredo?t=1", "a", "b")
    assert ev["payload"]["key"] == "***"
    with pytest.raises(ValueError):
        sa.evento_config_changed("", 1, 2)
    with pytest.raises(ValueError):
        sa.evento_config_changed(None, 1, 2)


def test_config_changed_sem_mudanca_efetiva_nao_gera_evento():
    assert sa.evento_config_changed("diretorio_saida", "saida", "saida") is None
    assert sa.evento_config_changed("defesa.intervalo_padrao", 2, 2) is None
    assert sa.evento_config_changed("webhook_url", None, None) is None
    assert sa.evento_config_changed("webhook_url", "u", "u") is None  # igual, mesmo sendo segredo
    # bool nao e o mesmo que numero
    assert sa.evento_config_changed("defesa.intervalo_padrao", True, 1) is not None
    # mudar so o segredo ainda e uma mutacao registrada (redigida)
    assert sa.evento_config_changed("webhook_url", "a", "b") is not None


def test_chaves_novas_de_config_estao_classificadas_e_com_padrao(monkeypatch, tmp_path):
    from core import audit
    for chave in ("auditoria.arquivo_eventos", "auditoria.diretorio_fila"):
        assert chave in audit.CHAVES_CONFIG_NAO_SENSIVEIS
    isolar_config(monkeypatch, tmp_path)
    assert sa.caminho_eventos() == str(tmp_path / ".state" / "security_events.jsonl")
    assert sa.caminho_fila() == str(tmp_path / ".state" / "security_audit_queue" / "fila_eventos.jsonl")
