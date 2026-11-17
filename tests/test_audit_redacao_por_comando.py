import argparse
import copy
import json

import pytest

from core import audit, config


def _log(tmp_path, monkeypatch):
    arquivo = tmp_path / "audit.log"
    monkeypatch.setattr(audit, "AUDIT_FILE", str(arquivo))
    return arquivo


def _entradas(arquivo):
    return [json.loads(l) for l in open(arquivo, encoding="utf-8")]


def _args_whois(**extra):
    base = {"group": "forensic", "command": "whois", "target": "203.0.113.5",
            "virustotal": None, "abuseipdb": None, "no_cache": False}
    base.update(extra)
    return base


def _args_config_set(chave, valor):
    return {"group": "config", "command": "set", "key": chave, "value": valor}


# ---------- forensic whois ----------

def test_whois_redige_as_duas_chaves_de_api(tmp_path, monkeypatch):
    arquivo = _log(tmp_path, monkeypatch)
    audit.registrar("forensic", "whois", _args_whois(virustotal="SEGREDO-VT", abuseipdb="SEGREDO-AB"))
    texto = arquivo.read_text(encoding="utf-8")
    assert "SEGREDO-VT" not in texto
    assert "SEGREDO-AB" not in texto
    args = _entradas(arquivo)[0]["argumentos"]
    assert args["virustotal"] == "***"
    assert args["abuseipdb"] == "***"
    assert args["target"] == "203.0.113.5"
    assert args["no_cache"] is False


def test_whois_preserva_none_e_redige_so_o_que_foi_informado(tmp_path, monkeypatch):
    arquivo = _log(tmp_path, monkeypatch)
    audit.registrar("forensic", "whois", _args_whois(virustotal="SEGREDO-VT"))
    args = _entradas(arquivo)[0]["argumentos"]
    assert args["virustotal"] == "***"
    assert args["abuseipdb"] is None


def test_whois_valor_vazio_tambem_e_mascarado(tmp_path, monkeypatch):
    arquivo = _log(tmp_path, monkeypatch)
    audit.registrar("forensic", "whois", _args_whois(virustotal=""))
    assert _entradas(arquivo)[0]["argumentos"]["virustotal"] == "***"


@pytest.mark.parametrize("argv", [
    ["203.0.113.5", "--virustotal", "SEGREDO-VT"],
    ["203.0.113.5", "--virustotal=SEGREDO-VT"],
    ["203.0.113.5", "--virus", "SEGREDO-VT"],
])
def test_whois_sintaxes_do_argparse_dao_o_mesmo_nome_de_destino(argv, tmp_path, monkeypatch):
    """Réplica local das definições de --virustotal/--abuseipdb do cli.py (o
    parser real nao e importavel nos testes). A redacao e por nome de destino,
    nao por sintaxe."""
    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    parser.add_argument("--virustotal")
    parser.add_argument("--abuseipdb")
    ns = parser.parse_args(argv)
    arquivo = _log(tmp_path, monkeypatch)
    audit.registrar("forensic", "whois", {"group": "forensic", "command": "whois", **vars(ns)})
    assert "SEGREDO-VT" not in arquivo.read_text(encoding="utf-8")
    assert _entradas(arquivo)[0]["argumentos"]["virustotal"] == "***"


# ---------- config set ----------

def test_config_set_chave_conhecida_nao_sensivel_grava_chave_e_valor(tmp_path, monkeypatch):
    arquivo = _log(tmp_path, monkeypatch)
    audit.registrar("config", "set", _args_config_set("defesa.limite_alerta_padrao", "999999"))
    args = _entradas(arquivo)[0]["argumentos"]
    assert args["key"] == "defesa.limite_alerta_padrao"
    assert args["value"] == "999999"


def test_config_set_webhook_url_grava_a_chave_e_redige_o_valor(tmp_path, monkeypatch):
    arquivo = _log(tmp_path, monkeypatch)
    audit.registrar("config", "set", _args_config_set("webhook_url", "https://exemplo.invalido/SEGREDO-HOOK"))
    assert "SEGREDO-HOOK" not in arquivo.read_text(encoding="utf-8")
    args = _entradas(arquivo)[0]["argumentos"]
    assert args["key"] == "webhook_url"
    assert args["value"] == "***"


def test_config_set_chave_desconhecida_redige_o_valor(tmp_path, monkeypatch):
    arquivo = _log(tmp_path, monkeypatch)
    audit.registrar("config", "set", _args_config_set("webhook_deploy.meu-repo.domain", "SEGREDO-D"))
    assert "SEGREDO-D" not in arquivo.read_text(encoding="utf-8")
    args = _entradas(arquivo)[0]["argumentos"]
    assert args["key"] == "webhook_deploy.meu-repo.domain"
    assert args["value"] == "***"


def test_config_set_nome_com_cara_de_segredo_mantem_o_nome_e_redige_o_valor(tmp_path, monkeypatch):
    arquivo = _log(tmp_path, monkeypatch)
    audit.registrar("config", "set", _args_config_set("api_token", "SEGREDO-T"))
    assert "SEGREDO-T" not in arquivo.read_text(encoding="utf-8")
    args = _entradas(arquivo)[0]["argumentos"]
    assert args["key"] == "api_token"
    assert args["value"] == "***"


def test_config_set_nome_que_nao_parece_identificador_e_mascarado(tmp_path, monkeypatch):
    arquivo = _log(tmp_path, monkeypatch)
    audit.registrar("config", "set", _args_config_set("https://u:SEGREDO-K@host", "x"))
    assert "SEGREDO-K" not in arquivo.read_text(encoding="utf-8")
    args = _entradas(arquivo)[0]["argumentos"]
    assert args["key"] == "***"
    assert args["value"] == "***"


@pytest.mark.parametrize("chave", [None, 123, ["a"], {"x": 1}, ""])
def test_config_set_chave_de_tipo_inesperado_nao_levanta_e_redige_o_valor(chave, tmp_path, monkeypatch):
    arquivo = _log(tmp_path, monkeypatch)
    audit.registrar("config", "set", _args_config_set(chave, "SEGREDO-V"))
    assert "SEGREDO-V" not in arquivo.read_text(encoding="utf-8")
    assert _entradas(arquivo)[0]["argumentos"]["value"] == "***"


def test_config_set_sem_o_argumento_key_redige_o_valor(tmp_path, monkeypatch):
    arquivo = _log(tmp_path, monkeypatch)
    audit.registrar("config", "set", {"group": "config", "command": "set", "value": "SEGREDO-V"})
    assert "SEGREDO-V" not in arquivo.read_text(encoding="utf-8")
    assert _entradas(arquivo)[0]["argumentos"]["value"] == "***"


def test_config_set_sem_o_argumento_value_nao_levanta(tmp_path, monkeypatch):
    arquivo = _log(tmp_path, monkeypatch)
    audit.registrar("config", "set", {"group": "config", "command": "set", "key": "idioma"})
    assert _entradas(arquivo)[0]["argumentos"]["key"] == "idioma"


# ---------- piso por nome ----------

def test_piso_inclui_termos_em_portugues(tmp_path, monkeypatch):
    arquivo = _log(tmp_path, monkeypatch)
    audit.registrar("g", "c", {"minha_chave": "SEGREDO-A", "segredo_x": "SEGREDO-B", "senha": "SEGREDO-C"})
    texto = arquivo.read_text(encoding="utf-8")
    for segredo in ("SEGREDO-A", "SEGREDO-B", "SEGREDO-C"):
        assert segredo not in texto


def test_piso_continua_valendo_dentro_de_comandos_com_regra_propria(tmp_path, monkeypatch):
    arquivo = _log(tmp_path, monkeypatch)
    audit.registrar("forensic", "whois", _args_whois(admin_key="SEGREDO-A"))
    audit.registrar("config", "set", {**_args_config_set("idioma", "pt"), "admin_key": "SEGREDO-B"})
    texto = arquivo.read_text(encoding="utf-8")
    assert "SEGREDO-A" not in texto
    assert "SEGREDO-B" not in texto


# ---------- originais preservados e robustez ----------

@pytest.mark.parametrize("grupo,comando,argumentos", [
    ("forensic", "whois", _args_whois(virustotal="SEGREDO-VT", abuseipdb="SEGREDO-AB")),
    ("config", "set", _args_config_set("webhook_url", "https://exemplo.invalido/X")),
    ("deploy", None, {"group": "deploy", "admin_key": "SEGREDO-A",
                      "aninhado": {"token": "SEGREDO-T"}, "lista": [{"password": "P"}]}),
])
def test_registrar_nao_altera_os_argumentos_recebidos(grupo, comando, argumentos, tmp_path, monkeypatch):
    _log(tmp_path, monkeypatch)
    original = copy.deepcopy(argumentos)
    audit.registrar(grupo, comando, argumentos)
    assert argumentos == original


@pytest.mark.parametrize("argumentos", [None, [], "texto", 42, {1: "a", None: "b"}, {"key": {"nested": ["x"]}}])
def test_redacao_nunca_levanta_excecao(argumentos, tmp_path, monkeypatch):
    arquivo = _log(tmp_path, monkeypatch)
    audit.registrar("config", "set", argumentos)
    audit.registrar("forensic", "whois", argumentos)
    assert len(_entradas(arquivo)) == 2


def test_grupo_de_tipo_inesperado_nao_levanta_e_nao_vaza(tmp_path, monkeypatch):
    arquivo = _log(tmp_path, monkeypatch)
    audit.registrar(["lista"], {"x": 1}, {"virustotal": "SEGREDO-X"})
    assert "SEGREDO-X" not in arquivo.read_text(encoding="utf-8")
    assert _entradas(arquivo)[0]["argumentos"] == {"_redacao_falhou": True}


# ---------- consistencia com a config real ----------

def _achatar(dicionario, prefixo=""):
    for k, v in dicionario.items():
        if isinstance(v, dict):
            yield from _achatar(v, prefixo + k + ".")
        else:
            yield prefixo + k


def test_toda_chave_do_padrao_esta_classificada_para_o_config_set():
    conhecidas = set(_achatar(config.PADRAO))
    classificadas = audit.CHAVES_CONFIG_NAO_SENSIVEIS | audit.CHAVES_CONFIG_SENSIVEIS
    assert not (audit.CHAVES_CONFIG_NAO_SENSIVEIS & audit.CHAVES_CONFIG_SENSIVEIS)
    assert conhecidas == classificadas, (
        "sem classificacao: %s; classificadas mas fora de PADRAO: %s"
        % (sorted(conhecidas - classificadas), sorted(classificadas - conhecidas))
    )


def test_nenhuma_chave_nao_sensivel_casa_com_o_piso():
    for chave in audit.CHAVES_CONFIG_NAO_SENSIVEIS:
        assert not audit._CAMPO_SECRETO.search(chave), chave
