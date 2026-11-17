"""Passo 3b - ciclo de vida orquestrado (criterios 1-4, 9, 11-13 no nivel do ciclo)."""
import itertools

import pytest

from core import security_actions as S
from core import security_audit as sa
from core import security_executor as X
from core import security_policy as P
from tests.helpers.audit_fakes import AlertadorFalso, DestinoFalso


class Registro:
    """Log compartilhado de chamadas, para provar a ORDEM das operacoes."""

    def __init__(self):
        self.log = []


class DestinoOrdenado(DestinoFalso):
    def __init__(self, registro, nome, falhar=False, falhar_em=()):
        super().__init__(nome, falhar)
        self.registro = registro
        self.falhar_em = set(falhar_em)  # event_types que falham

    def gravar(self, evento):
        if evento["event_type"] in self.falhar_em:
            self.tentativas += 1
            self.ultimo_erro = "OSError"
            return False
        ok = super().gravar(evento)
        if ok:
            self.registro.log.append(("grava:" + self.nome, evento["event_type"]))
        return ok


class ExecutorFalso:
    def __init__(self, registro, resultado=None, levanta=None):
        self.registro = registro
        self.resultado = resultado or X.ResultadoExecucao(True, info={"motivo": "m"})
        self.levanta = levanta
        self.chamadas = []

    def executar(self, action, expira_em_horas=None):
        self.registro.log.append(("executa", action.estado))
        self.chamadas.append((action.alvo, expira_em_horas))
        if self.levanta:
            raise self.levanta
        return self.resultado


class PolicyFixa:
    def __init__(self, resultado, motivo="regra de teste"):
        self.d = P.Decisao(resultado, motivo)

    def avaliar(self, action):
        return self.d


def _montar(modo="humano", principal_falha=False, fila_falha=False, falhar_principal_em=(),
            resultado=None, levanta=None, policy=None):
    reg = Registro()
    principal = DestinoOrdenado(reg, "principal", principal_falha, falhar_principal_em)
    fila = DestinoOrdenado(reg, "fila", fila_falha)
    alerta = AlertadorFalso()
    auditor = sa.Auditor(principal, fila, alertador=alerta)
    ex = ExecutorFalso(reg, resultado, levanta)
    contador = itertools.count(1)
    registry = S.Registry(gerador_id=lambda: "d%d" % next(contador))
    if modo == "humano":
        action = registry.propor("block_ip", ("ip", "203.0.113.5"), ("humano", "admin"), "manual",
                                 origin="http", actor={"identity": {"key_id": "k1", "role": "admin"}})
    else:
        action = registry.propor("block_ip", ("ip", "203.0.113.5"), ("automatico", "ingest"), "score 80",
                                 {"score": 80, "nivel": "alto"}, origin="http",
                                 actor={"automatic": "ingest"})
    kw = dict(registry=registry, auditor=auditor, policy=policy or P.PolicyDePassagem(), executor=ex)
    return action, kw, principal, fila, alerta, ex, reg


def _tipos(destino):
    return [e["event_type"] for e in destino.eventos]


def test_caminho_feliz_humano_gera_tres_eventos_na_ordem_certa():  # criterio 1
    action, kw, principal, fila, alerta, ex, reg = _montar("humano")
    r = S.processar(action, expira_em_horas=3, **kw)
    assert _tipos(principal) == ["PROPOSTA", "AUTORIZADA", "EXECUTADA"]
    assert [e["seq"] for e in principal.eventos] == [1, 2, 3]
    assert {e["decision_id"] for e in principal.eventos} == {"d1"}
    assert (r.estado, r.executado, r.audit_indisponivel, r.perda_de_rastreabilidade) == (
        S.EXECUTADA, True, False, False)
    assert r.info == {"motivo": "m"} and ex.chamadas == [(("ip", "203.0.113.5"), 3)]
    assert fila.tentativas == 0 and alerta.chamadas == []


def test_executor_so_roda_depois_de_proposta_e_autorizada_duraveis():  # criterio 2/12
    action, kw, principal, fila, alerta, ex, reg = _montar("automatico")
    S.processar(action, **kw)
    ordem = reg.log
    assert ordem == [("grava:principal", "PROPOSTA"), ("grava:principal", "AUTORIZADA"),
                     ("executa", "AUTORIZADA"), ("grava:principal", "EXECUTADA")]


def test_executada_so_depois_do_sucesso_do_executor_e_falha_nao_e_negada():  # criterio 2
    falha = X.ResultadoExecucao(False, erro_classe="OSError")
    action, kw, principal, fila, alerta, ex, reg = _montar("humano", resultado=falha)
    r = S.processar(action, **kw)
    assert _tipos(principal) == ["PROPOSTA", "AUTORIZADA", "FALHA_EXECUCAO"]
    assert "EXECUTADA" not in _tipos(principal) and "NEGADA" not in _tipos(principal)
    assert (r.estado, r.executado, r.negada, r.validacao_falhou) == (S.FALHA_EXECUCAO, False, False, False)
    ev = principal.eventos[-1]
    assert ev["outcome"] == "execution_failed" and ev["payload"]["error_class"] == "OSError"
    assert "error" not in ev["payload"]  # sem mensagem para erros que nao sao de validacao


def test_falha_de_validacao_expoe_mensagem_e_marca_validacao():
    falha = X.ResultadoExecucao(False, erro_classe="ValueError", erro_mensagem="expires_hours invalido",
                                validacao=True)
    action, kw, principal, *_ = _montar("humano", resultado=falha)
    r = S.processar(action, **kw)
    assert r.estado == S.FALHA_EXECUCAO and r.validacao_falhou is True
    assert r.erro_mensagem == "expires_hours invalido"
    assert principal.eventos[-1]["payload"]["error"] == "expires_hours invalido"


def test_executor_com_defeito_vira_falha_execucao_sem_levantar():
    action, kw, principal, *_ = _montar("humano", levanta=RuntimeError("bug"))
    r = S.processar(action, **kw)
    assert (r.estado, r.executado, r.erro_classe) == (S.FALHA_EXECUCAO, False, "RuntimeError")
    assert _tipos(principal)[-1] == "FALHA_EXECUCAO"


def test_humano_com_principal_falhando_nao_executa_mesmo_com_fila_saudavel():  # criterio 11
    action, kw, principal, fila, alerta, ex, reg = _montar("humano", principal_falha=True)
    r = S.processar(action, **kw)
    assert ex.chamadas == [] and r.audit_indisponivel is True and r.executado is None
    assert r.proposta_registada is False and r.estado == S.PROPOSTA
    assert fila.eventos == [] and fila.tentativas == 0  # a fila NAO substitui o principal
    assert len(alerta.chamadas) == 1


def test_automatico_com_principal_falhando_so_executa_depois_da_fila_confirmar():  # criterio 12
    action, kw, principal, fila, alerta, ex, reg = _montar("automatico", principal_falha=True)
    r = S.processar(action, **kw)
    assert _tipos(fila) == ["PROPOSTA", "AUTORIZADA", "EXECUTADA"]
    assert principal.eventos == [] and r.executado is True and r.estado == S.EXECUTADA
    assert r.audit_indisponivel is False and r.perda_de_rastreabilidade is False
    # a execucao veio depois dos dois eventos pre-execucao estarem na fila
    assert reg.log == [("grava:fila", "PROPOSTA"), ("grava:fila", "AUTORIZADA"),
                       ("executa", "AUTORIZADA"), ("grava:fila", "EXECUTADA")]
    assert [e["seq"] for e in fila.eventos] == [1, 2, 3]


def test_automatico_com_os_dois_destinos_falhando_nao_inicia_a_acao():  # criterio 4/12
    action, kw, principal, fila, alerta, ex, reg = _montar("automatico", principal_falha=True, fila_falha=True)
    r = S.processar(action, **kw)
    assert ex.chamadas == [] and r.audit_indisponivel is True and r.executado is None
    assert len(alerta.chamadas) == 1 and alerta.chamadas[0][1]["destinos_falhos"] == ["principal", "fila"]


def test_falha_ao_gravar_autorizada_nao_executa_e_deixa_decisao_orfa_em_proposta():  # Q4
    action, kw, principal, fila, alerta, ex, reg = _montar("humano", falhar_principal_em=("AUTORIZADA",))
    r = S.processar(action, **kw)
    assert ex.chamadas == [] and r.audit_indisponivel is True and r.proposta_registada is True
    assert _tipos(principal) == ["PROPOSTA"]
    assert (r.estado, action.seq) == (S.PROPOSTA, 1)  # o estado so avanca com evento duravel
    assert r.executado is None and not r.action.terminal  # orfa: sem estado terminal inventado


def test_resultado_nao_gravavel_em_nenhum_destino_preserva_o_resultado_real():  # criterio 13
    action, kw, principal, fila, alerta, ex, reg = _montar("humano", falhar_principal_em=("EXECUTADA",))
    fila.falhar_em = {"EXECUTADA"}
    r = S.processar(action, **kw)
    assert r.executado is True and r.estado == S.EXECUTADA  # a acao ocorreu; nao vira FALHA
    assert r.perda_de_rastreabilidade is True and r.audit_indisponivel is False
    assert len(alerta.chamadas) == 1
    assert _tipos(principal) == ["PROPOSTA", "AUTORIZADA"]
    assert r.eventos[-1] == ("EXECUTADA", "perdido")


def test_resultado_com_principal_falhando_depois_da_execucao_vai_para_a_fila():  # criterio 13
    action, kw, principal, fila, alerta, ex, reg = _montar("humano", falhar_principal_em=("EXECUTADA",))
    r = S.processar(action, **kw)
    assert r.executado is True and r.perda_de_rastreabilidade is False
    assert _tipos(fila) == ["EXECUTADA"]
    assert fila.eventos[0]["decision_id"] == "d1" and fila.eventos[0]["seq"] == 3  # mesma correlacao
    assert alerta.chamadas == []


def test_policy_que_nega_gera_negada_e_nao_executa():  # NEGADA != FALHA_EXECUCAO
    action, kw, principal, fila, alerta, ex, reg = _montar("humano", policy=PolicyFixa(P.NEGADA, "regra X"))
    r = S.processar(action, **kw)
    assert _tipos(principal) == ["PROPOSTA", "NEGADA"] and ex.chamadas == []
    assert (r.negada, r.estado, r.executado) == (True, S.NEGADA, None)
    assert principal.eventos[-1]["payload"]["policy_reason"] == "regra X"
    assert principal.eventos[-1]["outcome"] == "denied"


def test_policy_que_pede_confirmacao_nao_executa():
    action, kw, principal, fila, alerta, ex, reg = _montar("humano", policy=PolicyFixa(P.AGUARDANDO_CONFIRMACAO))
    r = S.processar(action, **kw)
    assert _tipos(principal) == ["PROPOSTA", "AGUARDANDO_CONFIRMACAO"] and ex.chamadas == []
    assert (r.aguardando_confirmacao, r.estado) == (True, S.AGUARDANDO_CONFIRMACAO)


def test_negada_com_audit_indisponivel_nao_levanta_e_nao_executa():
    action, kw, principal, fila, alerta, ex, reg = _montar(
        "humano", policy=PolicyFixa(P.NEGADA), falhar_principal_em=("NEGADA",))
    r = S.processar(action, **kw)
    assert r.negada is True and r.audit_indisponivel is True and ex.chamadas == []
    assert r.estado == S.PROPOSTA  # a negacao nao ficou duravel


def test_erro_da_policy_propaga_e_nada_executa():
    class PolicyQuebrada:
        def avaliar(self, action):
            raise RuntimeError("bug na policy")
    action, kw, principal, fila, alerta, ex, reg = _montar("humano", policy=PolicyQuebrada())
    with pytest.raises(RuntimeError):
        S.processar(action, **kw)
    assert ex.chamadas == [] and _tipos(principal) == ["PROPOSTA"]


def test_actor_dos_eventos_nao_e_inferido_em_nenhum_caminho():  # criterio 6
    for modo, esperado in (("humano", {"identity": {"key_id": "k1", "role": "admin"}}),
                           ("automatico", {"automatic": "ingest"})):
        action, kw, principal, *_ = _montar(modo)
        S.processar(action, **kw)
        for e in principal.eventos:
            assert e["actor"] == esperado
            assert "os_user" not in e["actor"]


def test_acoes_distintas_tem_decision_ids_distintos_e_eventos_nao_se_misturam():
    a1, kw, principal, fila, alerta, ex, reg = _montar("humano")
    S.processar(a1, **kw)
    a2 = kw["registry"].propor("block_ip", ("ip", "198.51.100.7"), ("humano", "admin"), "outra", origin="http")
    S.processar(a2, **kw)
    ids = {e["decision_id"] for e in principal.eventos}
    assert len(ids) == 2 and len(principal.eventos) == 6


def test_ciclo_real_ponta_a_ponta_com_destinos_em_disco_e_defense_isolado(estado_isolado, tmp_path):
    """Audit real (JSONL), fila real, Executor real e blocklist real isolada."""
    from core import defense
    principal = sa.DestinoJsonl(str(tmp_path / "audit" / "eventos.jsonl"))
    fila = sa.FilaDuravel(str(tmp_path / "fila" / "fila_eventos.jsonl"))
    auditor = sa.Auditor(principal, fila, alertador=AlertadorFalso())
    registry = S.Registry()
    action = registry.propor("block_ip", ("ip", "203.0.113.9"), ("automatico", "ingest"), "score 80",
                             {"score": 80, "nivel": "alto"}, origin="http", actor={"automatic": "ingest"})
    r = S.processar(action, registry=registry, auditor=auditor, policy=P.PolicyDePassagem(),
                    executor=X.Executor(), expira_em_horas=2)
    assert r.estado == S.EXECUTADA and r.executado is True
    assert defense.carregar_blocklist()["203.0.113.9"]["expira_em_horas"] == 2
    eventos = principal.ler_eventos()
    assert [e["event_type"] for e in eventos] == ["PROPOSTA", "AUTORIZADA", "EXECUTADA"]
    assert [e["seq"] for e in eventos] == [1, 2, 3] and len({e["decision_id"] for e in eventos}) == 1

    # ip invalido na execucao: FALHA_EXECUCAO com validacao, blocklist intocada
    a2 = registry.propor("block_ip", ("ip", "127.0.0.1"), ("humano", "admin"), "x", origin="http")
    r2 = S.processar(a2, registry=registry, auditor=auditor, policy=P.PolicyDePassagem(), executor=X.Executor())
    assert (r2.estado, r2.validacao_falhou) == (S.FALHA_EXECUCAO, True)
    assert "127.0.0.1" not in defense.carregar_blocklist()
