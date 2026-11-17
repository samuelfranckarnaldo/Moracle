"""
Passo 4a-1 - `mc defense block` com autorizacao local e ciclo de
SecurityAction. Cobre os criterios de aceitacao 1-20 do contrato 4a.

Mapa criterio -> teste (nomes `test_cNN_...`). Isolamento (criterio 17 e
20): config, estado, audit, KEY_PATH e fila apontam para tmp_path; a
fixture cria role e chave temporarias; nada toca o .state real.
"""
import json
import os
import stat
import sys
from types import SimpleNamespace

import pytest

import cli
from core import api_key as api_key_mod
from core import audit, auth, authorization, cli_authz, config, defense
from core import security_audit as sa
from core import security_runtime as rt
from core.identity import KeyStore, RoleStore, ServiceRole, create_api_key
from core.security_policy import Decisao, NEGADA


# ---------------------------------------------------------------- apoio

class Coletor:
    """Alertador de teste: guarda os alertas em vez de escrever em stderr."""

    def __init__(self):
        self.alertas = []

    def alertar(self, mensagem, dados=None, chave_dedup=None):
        self.alertas.append((mensagem, dict(dados or {})))
        return "stderr"

    def esquecer(self, chave):
        pass


class DestinoQueFalha:
    ultimo_erro = "OSError"

    def gravar(self, evento):
        return False

    def ids_existentes(self):
        return set()


class DestinoFalhaApos(sa.DestinoJsonl):
    """Grava os primeiros `n` eventos e falha nos seguintes."""

    def __init__(self, caminho, n):
        super().__init__(caminho)
        self.restantes = n

    def gravar(self, evento):
        if self.restantes <= 0:
            self.ultimo_erro = "OSError"
            return False
        self.restantes -= 1
        return super().gravar(evento)


class PolicyQueNega:
    def avaliar(self, action):
        return Decisao(NEGADA, "negada no teste")


class PolicyQueExplode:
    def avaliar(self, action):
        raise RuntimeError("detalhe interno da policy")


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
    monkeypatch.setattr(api_key_mod, "KEY_PATH", str(estado / "api_key.txt"))
    coletor = Coletor()
    monkeypatch.setattr(rt, "_alertador", coletor)
    monkeypatch.setattr(rt, "fabrica_auditor", None)
    monkeypatch.setattr(rt, "policy", None)
    monkeypatch.setattr(rt, "executor", None)
    monkeypatch.delenv("MORACLE_API_KEY", raising=False)
    return SimpleNamespace(
        raiz=tmp_path, estado=estado, alertas_coletados=coletor,
        blocklist=estado / "blocklist.json",
        eventos=estado / "security_events.jsonl",
        fila=estado / "security_audit_queue" / "fila_eventos.jsonl",
        audit_log=estado / "audit.log",
        alerts_log=estado / "alerts.log",
    )


def criar_chave(amb, monkeypatch, permissoes=("defense.block",), role="defender",
                nome="cli-defender", usar=True, scoped=None, expires_at=None):
    RoleStore(amb.estado).upsert(ServiceRole(name=role, permissions=frozenset(permissoes)))
    chave, token = create_api_key(KeyStore(amb.estado), name=nome, role_name=role,
                                  scoped_app_names=scoped, expires_at=expires_at)
    if usar:
        monkeypatch.setenv("MORACLE_API_KEY", token)
    return chave, token


def rodar(monkeypatch, *args):
    monkeypatch.setattr(sys, "argv", ["mc", "defense", "block", *args])
    return cli.main()


def blocklist(amb):
    return json.loads(amb.blocklist.read_text()) if amb.blocklist.exists() else {}


def eventos(amb):
    if not amb.eventos.exists():
        return []
    return [json.loads(l) for l in amb.eventos.read_text().splitlines() if l.strip()]


def tipos(amb):
    return [e["event_type"] for e in eventos(amb)]


def varrer_segredo(amb, token, *textos):
    """O token nao aparece em nenhuma saida nem em nenhum ficheiro do estado."""
    for t in textos:
        assert token not in t
    for raiz, _, nomes in os.walk(str(amb.raiz)):
        for n in nomes:
            with open(os.path.join(raiz, n), "rb") as f:
                assert token.encode() not in f.read(), n


# ------------------------------------------- 1-2: credencial / autenticacao

def test_c01_sem_credencial_nada_executa(amb, monkeypatch, capsys):
    criar_chave(amb, monkeypatch, usar=False)
    rc = rodar(monkeypatch, "203.0.113.5")
    out = capsys.readouterr().out
    assert rc == 1
    assert "MORACLE_API_KEY" in out
    assert blocklist(amb) == {}
    assert eventos(amb) == []
    assert not amb.fila.exists()


def test_c01_credencial_vazia_ou_so_espacos_conta_como_ausente(amb, monkeypatch, capsys):
    criar_chave(amb, monkeypatch, usar=False)
    for valor in ("", "   "):
        monkeypatch.setenv("MORACLE_API_KEY", valor)
        assert rodar(monkeypatch, "203.0.113.5") == 1
    assert blocklist(amb) == {}
    assert eventos(amb) == []


def test_c02_chave_desconhecida_revogada_e_expirada_dao_a_mesma_mensagem(amb, monkeypatch, capsys):
    mensagens = []

    monkeypatch.setenv("MORACLE_API_KEY", "mk_desconhecida")
    criar_chave(amb, monkeypatch, usar=False)
    assert rodar(monkeypatch, "203.0.113.5") == 1
    mensagens.append(capsys.readouterr().out)

    chave, token = criar_chave(amb, monkeypatch, nome="revogada", usar=False)
    KeyStore(amb.estado).revoke(chave.id)
    monkeypatch.setenv("MORACLE_API_KEY", token)
    assert rodar(monkeypatch, "203.0.113.5") == 1
    mensagens.append(capsys.readouterr().out)

    _, token = criar_chave(amb, monkeypatch, nome="expirada", usar=False,
                           expires_at="2000-01-01T00:00:00+00:00")
    monkeypatch.setenv("MORACLE_API_KEY", token)
    assert rodar(monkeypatch, "203.0.113.5") == 1
    mensagens.append(capsys.readouterr().out)

    assert mensagens[0] == mensagens[1] == mensagens[2]
    assert "invalida" in mensagens[0]
    assert blocklist(amb) == {}
    assert eventos(amb) == []


# ----------------------------------------------------- 3-4: autorizacao

def test_c03_chave_sem_defense_block_e_negada_sem_evento(amb, monkeypatch, capsys):
    criar_chave(amb, monkeypatch, permissoes=("defense.read", "ingest.write"), role="leitor")
    rc = rodar(monkeypatch, "203.0.113.5")
    assert rc == 1
    assert "defense.block" in capsys.readouterr().out
    assert blocklist(amb) == {}
    assert eventos(amb) == []


def test_c04_role_removido_do_rolestore_e_negado(amb, monkeypatch, capsys):
    criar_chave(amb, monkeypatch)
    (amb.estado / "roles.json").write_text("[]")  # a chave referencia um role que nao existe mais
    assert rodar(monkeypatch, "203.0.113.5") == 1
    assert blocklist(amb) == {}
    assert eventos(amb) == []


# ------------------------------------- 5: estado de identidade indisponivel

def test_c05_keys_json_corrompido_falha_fechada_sem_traceback(amb, monkeypatch, capsys):
    criar_chave(amb, monkeypatch)
    (amb.estado / "keys.json").write_text("{isto nao e json")
    rc = rodar(monkeypatch, "203.0.113.5")  # nao pode levantar
    out = capsys.readouterr().out
    assert rc == 1
    assert "indisponivel" in out
    assert "Traceback" not in out
    assert blocklist(amb) == {}
    assert eventos(amb) == []


def test_c05_estado_nao_gravavel_falha_fechada(amb, monkeypatch, capsys):
    criar_chave(amb, monkeypatch)

    def sem_permissao(self, key_id):
        raise PermissionError("somente leitura (simulado)")

    monkeypatch.setattr(KeyStore, "touch_last_used", sem_permissao)
    rc = rodar(monkeypatch, "203.0.113.5")
    out = capsys.readouterr().out
    assert rc == 1
    assert "indisponivel" in out
    assert "somente leitura" not in out
    assert blocklist(amb) == {}
    assert eventos(amb) == []


def test_c05_sem_chaves_diz_nenhuma_chave_e_nao_cria_nem_migra(amb, monkeypatch, capsys):
    monkeypatch.setenv("MORACLE_API_KEY", "mk_qualquer")
    rc = rodar(monkeypatch, "203.0.113.5")
    out = capsys.readouterr().out
    assert rc == 1
    assert "nenhuma chave configurada" in out
    assert not (amb.estado / "api_key.txt").exists()
    assert KeyStore.LEGACY_MIGRATION_ID not in KeyStore(amb.estado).load_all()
    assert KeyStore(amb.estado).load_all() == {}
    assert blocklist(amb) == {}
    assert eventos(amb) == []


# --------------------------------------------- 6-7: caminho feliz e admin

def test_c06_caminho_feliz_gera_tres_eventos_com_o_mesmo_decision_id(amb, monkeypatch, capsys):
    chave, token = criar_chave(amb, monkeypatch)
    rc = rodar(monkeypatch, "203.0.113.5", "--reason", "teste 4a")
    out = capsys.readouterr().out
    assert rc == 0
    assert "203.0.113.5" in out and "[WARN]" in out
    assert "203.0.113.5" in blocklist(amb)

    evs = eventos(amb)
    assert [e["event_type"] for e in evs] == ["PROPOSTA", "AUTORIZADA", "EXECUTADA"]
    assert [e["seq"] for e in evs] == [1, 2, 3]
    assert len({e["decision_id"] for e in evs}) == 1
    assert len({e["event_id"] for e in evs}) == 3
    for e in evs:
        assert e["origin"] == "cli-local"
        assert e["actor"]["identity"] == {"key_id": chave.id, "role": "defender"}
        assert e["actor"]["os_user"]
        assert "automatic" not in e["actor"]          # actor nunca inferido
        assert "correlation_id" not in e              # a CLI nao tem request_id
        assert e["payload"]["source"] == {"type": "humano", "id": "defender"}
        assert e["payload"]["target"] == {"type": "ip", "id": "203.0.113.5"}
        assert e["payload"]["reason"] == "teste 4a"
    assert evs[2]["outcome"] == "executed"
    assert stat.S_IMODE(os.stat(str(amb.eventos)).st_mode) == 0o600
    assert not amb.fila.exists()                      # acao humana nunca usa a fila (P1)
    varrer_segredo(amb, token, out)


def test_c07_chave_server_admin_explicita_tambem_autoriza(amb, monkeypatch, capsys):
    RoleStore(amb.estado).ensure_admin_role_exists()
    chave, _ = criar_chave(amb, monkeypatch, permissoes=("server.admin",), role="admin-teste",
                           nome="admin-explicita")
    rc = rodar(monkeypatch, "203.0.113.5")
    assert rc == 0
    evs = eventos(amb)
    assert evs[0]["actor"]["identity"]["role"] == "admin-teste"
    assert evs[0]["payload"]["source"] == {"type": "humano", "id": "admin-teste"}
    assert "203.0.113.5" in blocklist(amb)


# --------------------------------------------- 8-9: audit indisponivel

def test_c08_audit_principal_falha_nao_executa_e_nao_usa_a_fila(amb, monkeypatch, capsys):
    criar_chave(amb, monkeypatch)
    fila = sa.FilaDuravel(str(amb.fila))
    monkeypatch.setattr(rt, "fabrica_auditor",
                        lambda: sa.Auditor(DestinoQueFalha(), fila, alertador=rt.obter_alertador()))
    rc = rodar(monkeypatch, "203.0.113.5")
    out = capsys.readouterr().out
    assert rc == 1
    assert "auditoria indisponivel" in out
    assert blocklist(amb) == {}
    assert not amb.fila.exists()                     # D7/P1: sem fila para acao humana
    assert len(amb.alertas_coletados.alertas) == 1   # o Auditor alertou; a CLI nao duplica
    assert amb.alertas_coletados.alertas[0][1]["destinos_falhos"] == ["principal"]


def test_c09_auditor_nao_criavel_falha_fechada_com_alerta_de_infraestrutura(amb, monkeypatch, capsys):
    criar_chave(amb, monkeypatch)

    def fabrica():
        raise sa.ErroDeConfiguracaoAudit("caminho secreto /dados/privados")

    monkeypatch.setattr(rt, "fabrica_auditor", fabrica)
    rc = rodar(monkeypatch, "203.0.113.5")
    saida = capsys.readouterr()
    assert rc == 1
    assert "auditoria indisponivel" in saida.out
    assert "secreto" not in saida.out + saida.err
    assert blocklist(amb) == {}
    assert eventos(amb) == []
    assert amb.alertas_coletados.alertas == [
        ("falha de auditoria de seguranca", {"onde": "cli-block", "erro_classe": "ErroDeConfiguracaoAudit"})]


def test_c09_configuracao_de_audit_invalida_real_falha_fechada(amb, monkeypatch, capsys):
    criar_chave(amb, monkeypatch)
    # principal e fila no mesmo diretorio: validar_caminhos() levanta.
    (amb.raiz / "config.json").write_text(json.dumps({"auditoria": {
        "arquivo_eventos": ".state/a.jsonl", "diretorio_fila": ".state"}}))
    monkeypatch.setattr(config, "_cache", None)
    rc = rodar(monkeypatch, "203.0.113.5")
    assert rc == 1
    assert "auditoria indisponivel" in capsys.readouterr().out
    assert blocklist(amb) == {}
    assert len(amb.alertas_coletados.alertas) == 1


# ------------------------------------------ 10-11: validacao de entrada

def test_c10_ip_invalido_sem_evento_e_sem_bloqueio(amb, monkeypatch, capsys):
    criar_chave(amb, monkeypatch)
    for ip in ("999.1.1.1", "not-an-ip", "127.0.0.1", "0.0.0.0"):
        assert rodar(monkeypatch, ip) == 1
    assert blocklist(amb) == {}
    assert eventos(amb) == []


def test_c11_expiracao_invalida_gera_proposta_autorizada_e_falha_execucao(amb, monkeypatch, capsys):
    criar_chave(amb, monkeypatch)
    rc = rodar(monkeypatch, "203.0.113.5", "--expires-hours", "-5")
    out = capsys.readouterr().out
    assert rc == 1
    assert "expires_hours" in out
    assert tipos(amb) == ["PROPOSTA", "AUTORIZADA", "FALHA_EXECUCAO"]
    assert eventos(amb)[2]["payload"]["error_class"] == "ValueError"
    assert blocklist(amb) == {}


def test_c11_valueerror_de_propor_e_generico_e_sem_evento(amb, monkeypatch, capsys):
    criar_chave(amb, monkeypatch)
    from core.security_actions import Registry

    def explode(self, *a, **k):
        raise ValueError("segredo interno do registry")

    monkeypatch.setattr(Registry, "propor", explode)
    rc = rodar(monkeypatch, "203.0.113.5")
    saida = capsys.readouterr()
    assert rc == 1
    assert "pedido de bloqueio invalido" in saida.out
    assert "segredo interno" not in saida.out + saida.err
    assert eventos(amb) == []
    assert blocklist(amb) == {}


# --------------- 12: resultado nao gravado (rastreabilidade) e falha do efeito

def test_c12_falha_ao_gravar_executada_sai_0_com_aviso_e_nao_vira_falha_execucao(amb, monkeypatch, capsys):
    _, token = criar_chave(amb, monkeypatch)
    principal = DestinoFalhaApos(str(amb.eventos), 2)       # PROPOSTA e AUTORIZADA gravam
    monkeypatch.setattr(rt, "fabrica_auditor", lambda: sa.Auditor(
        principal, DestinoQueFalha(), alertador=rt.obter_alertador()))
    rc = rodar(monkeypatch, "203.0.113.5")
    saida = capsys.readouterr()
    assert rc == 0                                          # P-3: o bloqueio foi aplicado
    assert "203.0.113.5" in blocklist(amb)
    assert "foi aplicado" in saida.err and "auditoria final nao foi confirmada" in saida.err
    assert "203.0.113.5" in saida.err
    assert tipos(amb) == ["PROPOSTA", "AUTORIZADA"]         # sem FALHA_EXECUCAO por falha de audit
    assert len(amb.alertas_coletados.alertas) == 1          # alerta de perda de rastreabilidade
    varrer_segredo(amb, token, saida.out, saida.err)


def test_c12_resultado_na_fila_nao_e_perda_de_rastreabilidade(amb, monkeypatch, capsys):
    criar_chave(amb, monkeypatch)
    principal = DestinoFalhaApos(str(amb.eventos), 2)
    fila = sa.FilaDuravel(str(amb.fila))
    monkeypatch.setattr(rt, "fabrica_auditor", lambda: sa.Auditor(
        principal, fila, alertador=rt.obter_alertador()))
    rc = rodar(monkeypatch, "203.0.113.5")
    saida = capsys.readouterr()
    assert rc == 0
    assert saida.err == ""                                  # sem aviso: o resultado esta na fila
    na_fila = fila.ler_eventos()
    assert [e["event_type"] for e in na_fila] == ["EXECUTADA"]
    assert na_fila[0]["decision_id"] == eventos(amb)[0]["decision_id"]


def test_falha_inesperada_do_efeito_gera_falha_execucao(amb, monkeypatch, capsys):
    criar_chave(amb, monkeypatch)

    def falha(ip, motivo=None, expira_em_horas=None):
        raise OSError("disco (simulado)")

    monkeypatch.setattr(defense, "bloquear_ip", falha)
    rc = rodar(monkeypatch, "203.0.113.5")
    assert rc == 1
    assert tipos(amb) == ["PROPOSTA", "AUTORIZADA", "FALHA_EXECUCAO"]
    assert eventos(amb)[2]["payload"]["error_class"] == "OSError"
    assert "disco (simulado)" not in json.dumps(eventos(amb))


# ------------------------------------------------------- 13: Policy

def test_c13_policy_que_nega_gera_negada_e_nao_executa(amb, monkeypatch, capsys):
    criar_chave(amb, monkeypatch)
    monkeypatch.setattr(rt, "policy", PolicyQueNega())
    rc = rodar(monkeypatch, "203.0.113.5")
    assert rc == 1
    assert "Policy" in capsys.readouterr().out
    assert tipos(amb) == ["PROPOSTA", "NEGADA"]
    assert blocklist(amb) == {}


def test_excecao_da_policy_nao_autoriza_e_nao_vaza_detalhe(amb, monkeypatch, capsys):
    criar_chave(amb, monkeypatch)
    monkeypatch.setattr(rt, "policy", PolicyQueExplode())
    rc = rodar(monkeypatch, "203.0.113.5")
    saida = capsys.readouterr()
    assert rc == 1
    assert "falha interna" in saida.out
    assert "detalhe interno" not in saida.out + saida.err
    assert tipos(amb) == ["PROPOSTA"]                      # decisao orfa documentada
    assert blocklist(amb) == {}
    assert amb.alertas_coletados.alertas[0][1]["erro_classe"] == "RuntimeError"


# ------------------------------------------------ 14: segredo nunca vaza

def test_c14_token_nunca_aparece_em_saidas_nem_ficheiros(amb, monkeypatch, capsys):
    _, token = criar_chave(amb, monkeypatch)
    saidas = []
    # sucesso, expiracao invalida, audit a falhar e chave revogada
    rodar(monkeypatch, "203.0.113.5", "--reason", "ok")
    rodar(monkeypatch, "203.0.113.6", "--expires-hours", "-1")
    monkeypatch.setattr(rt, "fabrica_auditor", lambda: sa.Auditor(
        DestinoQueFalha(), sa.FilaDuravel(str(amb.fila)), alertador=rt.obter_alertador()))
    rodar(monkeypatch, "203.0.113.7")
    monkeypatch.setattr(rt, "fabrica_auditor", None)
    for chave in KeyStore(amb.estado).load_all().values():
        KeyStore(amb.estado).revoke(chave.id)
    rodar(monkeypatch, "203.0.113.8")
    saida = capsys.readouterr()
    alertas = json.dumps(amb.alertas_coletados.alertas)
    varrer_segredo(amb, token, saida.out, saida.err, alertas)
    # o audit legado regista a invocacao, sem o token (nunca esteve em argv)
    assert token not in amb.audit_log.read_text()


# ---------------------------------- 15: reutiliza auth/authorization existentes

def test_c15_usa_core_auth_e_exigir_permissao_sem_logica_propria(amb, monkeypatch, capsys):
    criar_chave(amb, monkeypatch)
    chamadas = []
    original_auth = auth.autenticar
    original_exigir = authorization.exigir_permissao

    def espiao_auth(token, key_store, now=None):
        chamadas.append(("autenticar", type(key_store).__name__))
        return original_auth(token, key_store, now=now)

    def espiao_exigir(api_key, role_store, permission, app_name=None):
        chamadas.append(("exigir_permissao", permission, app_name))
        return original_exigir(api_key, role_store, permission, app_name=app_name)

    monkeypatch.setattr(auth, "autenticar", espiao_auth)
    monkeypatch.setattr(authorization, "exigir_permissao", espiao_exigir)
    assert rodar(monkeypatch, "203.0.113.5") == 0
    assert chamadas == [("autenticar", "KeyStore"), ("exigir_permissao", "defense.block", None)]


# ------------------------------------ 16: audit legado e flag fora do 4a

def test_c16_audit_legado_inalterado_uma_linha_por_invocacao(amb, monkeypatch, capsys):
    criar_chave(amb, monkeypatch)
    rodar(monkeypatch, "203.0.113.5", "--reason", "legado")
    linhas = [json.loads(l) for l in amb.audit_log.read_text().splitlines() if l.strip()]
    assert len(linhas) == 1
    assert linhas[0]["grupo"] == "defense" and linhas[0]["comando"] == "block"
    assert linhas[0]["argumentos"]["ip"] == "203.0.113.5"
    assert set(linhas[0]) >= {"timestamp", "usuario", "grupo", "comando", "argumentos"}


def test_p1_flag_api_key_nao_existe_no_4a(amb, monkeypatch):
    criar_chave(amb, monkeypatch)
    monkeypatch.setattr(sys, "argv", ["mc", "defense", "block", "203.0.113.5", "--api-key", "x"])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 2
    assert blocklist(amb) == {}


# --------------------------------------------- 17 e 20: isolamento do estado

def test_c17_c20_estado_isolado_e_chave_temporaria(amb, monkeypatch):
    chave, _ = criar_chave(amb, monkeypatch)
    raiz = str(amb.raiz)
    assert config.RAIZ_PROJETO == raiz
    assert str(cli_authz._diretorio_estado()).startswith(raiz)
    for caminho in (defense.BLOCKLIST_FILE, defense.ALERTS_FILE, audit.AUDIT_FILE, api_key_mod.KEY_PATH):
        assert caminho.startswith(raiz)
    assert sa.caminho_eventos().startswith(raiz)
    assert sa.caminho_fila().startswith(raiz)
    assert chave.id in KeyStore(amb.estado).load_all()
    assert (amb.estado / "keys.json").exists() and (amb.estado / "roles.json").exists()


# --------------------------------------------- 18-19: escopo e role sem permissao

def test_c18_chave_com_scoped_app_names_e_defense_block_continua_autorizada(amb, monkeypatch, capsys):
    criar_chave(amb, monkeypatch, scoped=["app-a"])       # app-a: so restringe rotas de aplicacao
    rc = rodar(monkeypatch, "203.0.113.5")
    assert rc == 0
    assert tipos(amb) == ["PROPOSTA", "AUTORIZADA", "EXECUTADA"]
    assert "203.0.113.5" in blocklist(amb)


def test_c19_role_so_com_defense_read_e_negada(amb, monkeypatch, capsys):
    criar_chave(amb, monkeypatch, permissoes=("defense.read",), role="so-leitura")
    rc = rodar(monkeypatch, "203.0.113.5")
    assert rc == 1
    assert "defense.block" in capsys.readouterr().out
    assert eventos(amb) == []
    assert blocklist(amb) == {}


# ----------------------------------------- unidades de core.cli_authz

def test_credencial_do_ambiente_unidades():
    assert cli_authz.credencial_do_ambiente({}) is None
    assert cli_authz.credencial_do_ambiente({"MORACLE_API_KEY": ""}) is None
    assert cli_authz.credencial_do_ambiente({"MORACLE_API_KEY": "  \t "}) is None
    assert cli_authz.credencial_do_ambiente({"MORACLE_API_KEY": "  mk_x \n"}) == "mk_x"
    assert cli_authz.credencial_do_ambiente({"OUTRA": "mk_x"}) is None


def test_autorizar_operacao_cli_estados(amb, monkeypatch):
    assert cli_authz.autorizar_operacao_cli("defense.block", ambiente={}).estado == cli_authz.CREDENCIAL_AUSENTE
    # sem tocar o estado de identidade quando nao ha credencial
    assert not (amb.estado / "keys.json").exists()

    assert cli_authz.autorizar_operacao_cli(
        "defense.block", ambiente={"MORACLE_API_KEY": "mk_x"}).estado == cli_authz.NENHUMA_CHAVE

    chave, token = criar_chave(amb, monkeypatch, usar=False)
    res = cli_authz.autorizar_operacao_cli("defense.block", ambiente={"MORACLE_API_KEY": token})
    assert res.autorizado and res.api_key.id == chave.id and res.estado == cli_authz.AUTORIZADO

    assert cli_authz.autorizar_operacao_cli(
        "defense.read", ambiente={"MORACLE_API_KEY": token}).estado == cli_authz.SEM_PERMISSAO
    assert cli_authz.autorizar_operacao_cli(
        "defense.block", ambiente={"MORACLE_API_KEY": "mk_errada"}).estado == cli_authz.CREDENCIAL_INVALIDA


def test_autorizar_cli_permissao_fora_do_contrato_e_indisponivel_nao_autoriza(amb, monkeypatch):
    chave, token = criar_chave(amb, monkeypatch, usar=False)
    estado, erro = cli_authz.autorizar_cli(chave, "permissao.inexistente")
    assert estado == cli_authz.INDISPONIVEL and erro == "UnknownPermissionError"
