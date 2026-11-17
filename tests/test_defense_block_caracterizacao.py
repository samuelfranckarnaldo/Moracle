"""
Passo 4a-0 (atualizado no 4a-1) - caracterizacao do `mc defense block`.

Escritos no 4a-0 contra o comportamento SEM autorizacao. No 4a-1 o
comando passa a exigir credencial explicita (MORACLE_API_KEY) e a passar
pelo ciclo de SecurityAction; por isso:
  - a fixture `amb` agora cria role `defender` (so defense.block) e uma
    chave no estado temporario e define MORACLE_API_KEY (MUDANCA DE SETUP
    DECLARADA: as asserções de efeito - blocklist, saida, audit legado,
    argumentos do efeito - ficam IGUAIS, e e isso que prova ausencia de
    regressao);
  - 3 testes mudam de SEMANTICA (marcados "ATUALIZADO NO 4a-1"):
    bloqueio sem credencial, erro inesperado do efeito e criacao de
    chaves/api_key.txt.
O comportamento novo (autorizacao, eventos, falhas de audit) esta em
test_defense_block_autorizacao.py.

Isolamento: estado, config, audit e raiz do projeto apontam para tmp_path;
nada toca o .state nem o config.json reais. Suposicoes minimas sobre o
codigo existente: a saida e verificada por presenca (IP, "[WARN]", "[ERR]"),
nunca pelo texto i18n exato.
"""
import json
import sys
from datetime import datetime
from types import SimpleNamespace

import pytest

import cli
from core import api_key, audit, config, defense
from core import security_runtime as rt
from core.identity import KeyStore, RoleStore, ServiceRole, create_api_key


@pytest.fixture
def amb(tmp_path, monkeypatch):
    estado = tmp_path / ".state"
    estado.mkdir()
    monkeypatch.setattr(config, "RAIZ_PROJETO", str(tmp_path))
    monkeypatch.setattr(config, "CONFIG_PATH", str(tmp_path / "config.json"))
    monkeypatch.setattr(config, "_cache", None)
    monkeypatch.setattr(defense, "STATE_DIR", str(estado))
    monkeypatch.setattr(defense, "STATE_FILE", str(estado / "defesa_state.json"))
    monkeypatch.setattr(defense, "BLOCKLIST_FILE", str(estado / "blocklist.json"))
    monkeypatch.setattr(defense, "ALERTS_FILE", str(estado / "alerts.log"))
    monkeypatch.setattr(audit, "AUDIT_FILE", str(estado / "audit.log"))
    # Constante de modulo que NAO segue RAIZ_PROJETO: isolada de proposito,
    # para o 4a-1 nunca tocar o api_key.txt real a partir destes testes.
    monkeypatch.setattr(api_key, "KEY_PATH", str(estado / "api_key.txt"))
    # 4a-1: estado do runtime de seguranca isolado (alertador/fabricas).
    monkeypatch.setattr(rt, "_alertador", None)
    monkeypatch.setattr(rt, "fabrica_auditor", None)
    monkeypatch.setattr(rt, "policy", None)
    monkeypatch.setattr(rt, "executor", None)
    # 4a-1: role minima (so defense.block) + chave no estado TEMPORARIO.
    RoleStore(estado).add(ServiceRole(name="defender", permissions=frozenset({"defense.block"})))
    _, token = create_api_key(KeyStore(estado), name="cli-defender", role_name="defender")
    monkeypatch.setenv("MORACLE_API_KEY", token)
    return SimpleNamespace(
        raiz=tmp_path,
        estado=estado,
        token=token,
        blocklist=estado / "blocklist.json",
        audit_log=estado / "audit.log",
        alertas=estado / "alerts.log",
    )


def rodar(monkeypatch, *args):
    monkeypatch.setattr(sys, "argv", ["mc", "defense", "block", *args])
    return cli.main()


def ler_blocklist(amb):
    if not amb.blocklist.exists():
        return {}
    return json.loads(amb.blocklist.read_text())


# ------------------------------------------------------------ caminho feliz

def test_bloqueia_com_credencial_defense_block(amb, monkeypatch, capsys):
    # ATUALIZADO NO 4a-1: antes bloqueava sem qualquer credencial; agora
    # exige MORACLE_API_KEY com defense.block (efeito e saida iguais).
    rc = rodar(monkeypatch, "203.0.113.5")
    out = capsys.readouterr().out
    assert rc == 0
    assert "203.0.113.5" in out
    assert "[WARN]" in out
    assert "203.0.113.5" in ler_blocklist(amb)


def test_entrada_basica_na_blocklist(amb, monkeypatch):
    rodar(monkeypatch, "203.0.113.5")
    entrada = ler_blocklist(amb)["203.0.113.5"]
    assert entrada["motivo"] == "manual block"
    assert "expira_em_horas" not in entrada
    datetime.fromisoformat(entrada["bloqueado_em"])  # ISO 8601 valido


def test_motivo_e_expiracao_sao_gravados(amb, monkeypatch):
    rc = rodar(monkeypatch, "203.0.113.6", "--reason", "teste de motivo",
               "--expires-hours", "2")
    assert rc == 0
    entrada = ler_blocklist(amb)["203.0.113.6"]
    assert entrada["motivo"] == "teste de motivo"
    assert entrada["expira_em_horas"] == pytest.approx(2)


def test_reblock_sobrescreve_a_entrada(amb, monkeypatch):
    rodar(monkeypatch, "203.0.113.7", "--reason", "primeiro")
    primeira = ler_blocklist(amb)["203.0.113.7"]
    rodar(monkeypatch, "203.0.113.7", "--reason", "segundo")
    blocklist = ler_blocklist(amb)
    assert list(blocklist) == ["203.0.113.7"]  # uma entrada so
    assert blocklist["203.0.113.7"]["motivo"] == "segundo"
    assert (datetime.fromisoformat(blocklist["203.0.113.7"]["bloqueado_em"])
            >= datetime.fromisoformat(primeira["bloqueado_em"]))


def test_ip_privado_rfc1918_e_bloqueavel(amb, monkeypatch):
    # Decisao vigente (Pacote 2): sem allowlist de IPs privados.
    rc = rodar(monkeypatch, "10.0.0.1")
    assert rc == 0
    assert "10.0.0.1" in ler_blocklist(amb)


# ------------------------------------------------------------------- erros

def test_ip_invalido_sai_com_1_e_sem_efeito(amb, monkeypatch, capsys):
    rc = rodar(monkeypatch, "not-an-ip")
    out = capsys.readouterr().out
    assert rc == 1
    assert "[ERR]" in out
    assert ler_blocklist(amb) == {}


def test_valueerror_do_efeito_vira_erro_com_saida_1(amb, monkeypatch, capsys):
    # Cobre o ramo `except ValueError` da CLI sem depender das regras de
    # validar_expiracao/normalizar_ip.
    def falha(ip, motivo=None, expira_em_horas=None):
        raise ValueError("expiracao invalida (simulada)")

    monkeypatch.setattr(defense, "bloquear_ip", falha)
    rc = rodar(monkeypatch, "203.0.113.8", "--expires-hours", "1")
    out = capsys.readouterr().out
    assert rc == 1
    assert "[ERR]" in out
    assert "expiracao invalida (simulada)" in out


def test_erro_inesperado_do_efeito_vira_falha_de_execucao(amb, monkeypatch, capsys):
    # ATUALIZADO NO 4a-1 (mudanca declarada): antes so ValueError era
    # tratado e qualquer outro erro derrubava o comando; agora o
    # Executor (3b) converte em FALHA_EXECUCAO e o comando sai com 1, sem
    # propagar e sem vazar o texto da excecao.
    def falha(ip, motivo=None, expira_em_horas=None):
        raise OSError("disco (simulado)")

    monkeypatch.setattr(defense, "bloquear_ip", falha)
    rc = rodar(monkeypatch, "203.0.113.9")
    saida = capsys.readouterr()
    assert rc == 1
    assert "[ERR]" in saida.out
    assert "disco (simulado)" not in saida.out + saida.err
    assert ler_blocklist(amb) == {}


def test_sem_argumento_ip_sai_com_2(amb, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["mc", "defense", "block"])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 2


# ----------------------------------------------- contrato com o efeito

def test_chama_bloquear_ip_uma_vez_com_os_argumentos_brutos(amb, monkeypatch, capsys):
    chamadas = []

    def espiao(ip, motivo=None, expira_em_horas=None):
        chamadas.append((ip, motivo, expira_em_horas))
        return {"bloqueado_em": "2026-01-01T00:00:00+00:00", "motivo": motivo}

    monkeypatch.setattr(defense, "bloquear_ip", espiao)
    rc = rodar(monkeypatch, "203.0.113.10", "--reason", "via espiao",
               "--expires-hours", "1.5")
    out = capsys.readouterr().out
    assert rc == 0
    assert chamadas == [("203.0.113.10", "via espiao", 1.5)]
    assert "203.0.113.10" in out
    assert "[WARN]" in out


def test_motivo_padrao_e_expiracao_ausente(amb, monkeypatch):
    chamadas = []

    def espiao(ip, motivo=None, expira_em_horas=None):
        chamadas.append((ip, motivo, expira_em_horas))
        return {"bloqueado_em": "2026-01-01T00:00:00+00:00", "motivo": motivo}

    monkeypatch.setattr(defense, "bloquear_ip", espiao)
    rodar(monkeypatch, "203.0.113.11")
    assert chamadas == [("203.0.113.11", "manual block", None)]


# ------------------------------------------- o que hoje NAO acontece

def test_nao_cria_nem_usa_a_chave_legada(amb, monkeypatch):
    # ATUALIZADO NO 4a-1: a CLI agora autentica contra keys.json (criado
    # pela fixture), mas continua a NAO criar nem escolher a chave
    # legada: nunca cria .state/api_key.txt nem migra a legacy-admin.
    rodar(monkeypatch, "203.0.113.12")
    assert (amb.estado / "keys.json").exists()
    assert not (amb.estado / "api_key.txt").exists()
    assert KeyStore.LEGACY_MIGRATION_ID not in KeyStore(amb.estado).load_all()


def test_nao_regista_alerta(amb, monkeypatch):
    rodar(monkeypatch, "203.0.113.14")
    assert not amb.alertas.exists()


# --------------------------------------------------------- audit legado

def test_audit_legado_regista_a_invocacao(amb, monkeypatch):
    # Permanece igual no 4a-1.
    rodar(monkeypatch, "203.0.113.15", "--reason", "auditado")
    linhas = [json.loads(l) for l in amb.audit_log.read_text().splitlines() if l.strip()]
    assert len(linhas) == 1
    entrada = linhas[0]
    assert entrada["grupo"] == "defense"
    assert entrada["comando"] == "block"
    assert entrada["usuario"]
    assert entrada["argumentos"]["ip"] == "203.0.113.15"
    assert entrada["argumentos"]["reason"] == "auditado"
    datetime.fromisoformat(entrada["timestamp"])


def test_audit_legado_regista_antes_do_efeito(amb, monkeypatch):
    # O registro da invocacao existe mesmo que o efeito falhe.
    def falha(ip, motivo=None, expira_em_horas=None):
        raise ValueError("falha simulada")

    monkeypatch.setattr(defense, "bloquear_ip", falha)
    rodar(monkeypatch, "203.0.113.16")
    linhas = [l for l in amb.audit_log.read_text().splitlines() if l.strip()]
    assert len(linhas) == 1
