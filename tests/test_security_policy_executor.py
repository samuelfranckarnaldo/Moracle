"""Passo 3b - Policy de passagem e Executor (criterios 2 e 9, invariantes 2/3/5/6/7)."""
import pytest

from core import security_actions as S
from core import security_executor as X
from core import security_policy as P


def _acao(origem=("humano", "admin"), actor=None, alvo=("ip", "203.0.113.5"), tipo="block_ip", motivo="m"):
    actor = actor if actor is not None else (
        {"automatic": origem[1]} if origem[0] == "automatico" else {})
    return S.Registry().propor(tipo, alvo, origem, motivo, origin="http", actor=actor)


def test_policy_de_passagem_autoriza_os_tres_caminhos_sem_regra_nova():
    pol = P.PolicyDePassagem()
    for origem in (("humano", "admin"), ("automatico", "ingest"), ("automatico", "watchdog")):
        d = pol.avaliar(_acao(origem))
        assert d.resultado == P.AUTORIZADA


def test_policy_de_passagem_nao_nega_nem_pede_confirmacao_nem_diferencia_risco():
    pol = P.PolicyDePassagem()
    reg = S.Registry()
    for nivel in ("alto", "critico"):
        a = reg.propor("block_ip", ("ip", "1.1.1.1"), ("automatico", "ingest"), "m", {"score": 70, "nivel": nivel},
                       origin="http", actor={"automatic": "ingest"})
        assert pol.avaliar(a).resultado == P.AUTORIZADA
    # tipo de acao desconhecido tambem NAO e negado (falharia no Executor)
    assert pol.avaliar(_acao(tipo="outra_acao")).resultado == P.AUTORIZADA


def test_decisao_valida_o_resultado():
    for r in P.RESULTADOS_VALIDOS:
        assert P.Decisao(r).resultado == r
    for r in ("EXECUTADA", "", None, "autorizada"):
        with pytest.raises(ValueError):
            P.Decisao(r)


def test_executor_chama_bloquear_ip_com_motivo_e_expiracao():
    chamadas = []

    def bloquear(ip, motivo=None, expira_em_horas=None):
        chamadas.append((ip, motivo, expira_em_horas))
        return {"bloqueado_em": "t", "motivo": motivo}

    res = X.Executor(bloquear=bloquear).executar(_acao(motivo="por teste"), expira_em_horas=2)
    assert res.sucesso is True and res.info["motivo"] == "por teste"
    assert chamadas == [("203.0.113.5", "por teste", 2)]


def test_executor_valueerror_e_falha_de_validacao_com_mensagem():
    def bloquear(ip, motivo=None, expira_em_horas=None):
        raise ValueError("expires_hours deve ser positivo e finito")
    res = X.Executor(bloquear=bloquear).executar(_acao(), expira_em_horas=-1)
    assert (res.sucesso, res.validacao, res.erro_classe) == (False, True, "ValueError")
    assert "expires_hours" in res.erro_mensagem


def test_executor_outro_erro_guarda_so_a_classe_sem_vazar_detalhes():
    def bloquear(ip, motivo=None, expira_em_horas=None):
        raise OSError("/data/data/com.termux/files/home/moracle/.state/blocklist.json: sem espaco")
    res = X.Executor(bloquear=bloquear).executar(_acao())
    assert (res.sucesso, res.validacao, res.erro_classe) == (False, False, "OSError")
    assert res.erro_mensagem is None


def test_executor_acao_ou_alvo_nao_suportado_e_falha_nao_negacao():
    chamadas = []
    ex = X.Executor(bloquear=lambda *a, **k: chamadas.append(a))
    r1 = ex.executar(_acao(tipo="unblock_ip"))
    r2 = ex.executar(_acao(alvo=("dominio", "x.com")))
    assert (r1.sucesso, r1.erro_classe) == (False, "AcaoNaoSuportada")
    assert (r2.sucesso, r2.erro_classe) == (False, "AlvoNaoSuportado")
    assert chamadas == []


def test_executor_com_defense_real_grava_na_blocklist_isolada(estado_isolado):
    from core import defense
    res = X.Executor().executar(_acao(motivo="teste real"), expira_em_horas=1)
    assert res.sucesso is True
    entrada = defense.carregar_blocklist()["203.0.113.5"]
    assert entrada["motivo"] == "teste real" and entrada["expira_em_horas"] == 1


def test_executor_com_defense_real_validacao_de_ip_e_expiracao_continua_em_bloquear_ip(estado_isolado):
    from core import defense
    res = X.Executor().executar(_acao(alvo=("ip", "127.0.0.1")))  # loopback nao e bloqueavel
    assert (res.sucesso, res.validacao) == (False, True)
    res = X.Executor().executar(_acao(), expira_em_horas="x")
    assert (res.sucesso, res.validacao) == (False, True)
    assert defense.carregar_blocklist() == {}


def test_executor_nunca_levanta_para_excecoes_comuns():
    def bloquear(*a, **k):
        raise RuntimeError("bug")
    assert X.Executor(bloquear=bloquear).executar(_acao()).erro_classe == "RuntimeError"
