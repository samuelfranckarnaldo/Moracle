import json
import os
import stat

from core import audit


def _entradas(arquivo):
    return [json.loads(l) for l in open(arquivo, encoding="utf-8")]


def test_registrar_redige_segredos(tmp_path, monkeypatch):
    arquivo = tmp_path / "audit.log"
    monkeypatch.setattr(audit, "AUDIT_FILE", str(arquivo))
    audit.registrar("deploy", "apps", {
        "admin_key": "SEGREDO-A",
        "api_key": "SEGREDO-B",
        "github_webhook_secret": "SEGREDO-C",
        "aninhado": {"password": "SEGREDO-D"},
        "lista": [{"token": "SEGREDO-E"}],
        "ip": "203.0.113.1",
        "reason": "teste",
    })
    texto = arquivo.read_text(encoding="utf-8")
    for segredo in ("SEGREDO-A", "SEGREDO-B", "SEGREDO-C", "SEGREDO-D", "SEGREDO-E"):
        assert segredo not in texto
    args = _entradas(arquivo)[0]["argumentos"]
    assert args["admin_key"] == "***"
    assert args["aninhado"]["password"] == "***"
    assert args["lista"][0]["token"] == "***"
    assert args["ip"] == "203.0.113.1"
    assert args["reason"] == "teste"


def test_registrar_preserva_none_em_campo_secreto(tmp_path, monkeypatch):
    arquivo = tmp_path / "audit.log"
    monkeypatch.setattr(audit, "AUDIT_FILE", str(arquivo))
    audit.registrar("g", "c", {"admin_key": None})
    assert _entradas(arquivo)[0]["argumentos"]["admin_key"] is None


def test_audit_log_fica_com_permissao_0600(tmp_path, monkeypatch):
    arquivo = tmp_path / "audit.log"
    arquivo.write_text("")
    os.chmod(arquivo, 0o644)
    monkeypatch.setattr(audit, "AUDIT_FILE", str(arquivo))
    audit.registrar("g", "c", {})
    assert stat.S_IMODE(os.stat(arquivo).st_mode) == 0o600


def test_ler_recentes_ignora_linha_invalida(tmp_path, monkeypatch):
    arquivo = tmp_path / "audit.log"
    monkeypatch.setattr(audit, "AUDIT_FILE", str(arquivo))
    audit.registrar("g", "c1", {})
    with open(arquivo, "a", encoding="utf-8") as f:
        f.write("linha quebrada\n")
    audit.registrar("g", "c2", {})
    assert [e["comando"] for e in audit.ler_recentes()] == ["c1", "c2"]
