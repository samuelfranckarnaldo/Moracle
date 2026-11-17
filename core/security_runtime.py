"""
Ligacao de runtime do ciclo de SecurityAction (Gate #6 / Passo 3c).

Fica entre os handlers HTTP e os modulos do ciclo (security_actions,
security_audit, security_policy, security_executor). Nao decide nada:
monta o Auditor/Policy/Executor padrao, constroi o `actor` a partir do
contexto autenticado (sem inferencia) e reconcilia a fila na partida.

Pontos de injecao para teste: `fabrica_auditor`, `policy`, `executor`
(None = padrao). Nada aqui e constante derivada de RAIZ_PROJETO: os
caminhos do audit sao resolvidos a cada criacao do Auditor.
"""
import getpass
import logging

from core import security_audit as sa
from core.security_executor import Executor
from core.security_policy import PolicyDePassagem
from core.security_actions import Registry

_log = logging.getLogger(__name__)

fabrica_auditor = None   # callable() -> Auditor; None = sa.criar_auditor_padrao
policy = None            # None = PolicyDePassagem()
executor = None          # None = Executor()
_alertador = None        # compartilhado: dedup de alertas de infraestrutura


def obter_alertador():
    global _alertador
    if _alertador is None:
        _alertador = sa.Alertador()
    return _alertador


def obter_auditor():
    """Levanta se a configuracao do audit for invalida (o chamador trata
    como audit indisponivel: fail-closed)."""
    if fabrica_auditor is not None:
        return fabrica_auditor()
    return sa.criar_auditor_padrao(alertador=obter_alertador())


def obter_policy():
    return policy if policy is not None else PolicyDePassagem()


def obter_executor():
    return executor if executor is not None else Executor()


def novo_registry():
    return Registry()


def alertar_infraestrutura(exc, onde):
    """Alerta quando nem o Auditor pode ser criado (config invalida).
    So classe do erro e local; nunca a mensagem."""
    try:
        obter_alertador().alertar(
            "falha de auditoria de seguranca",
            {"onde": onde, "erro_classe": type(exc).__name__},
            chave_dedup=("infra", onde, type(exc).__name__))
    except Exception:
        pass


def _os_user():
    try:
        return getpass.getuser()
    except Exception:
        return None


def ator_http(context, automatic=None):
    """actor a partir do contexto autenticado. identity so existe se o
    middleware autenticou (context['api_key']); os_user e so contexto
    do processo; automatic so em acao automatica. Nada e preenchido
    por inferencia."""
    ator = {}
    usuario = _os_user()
    if usuario:
        ator["os_user"] = usuario
    api_key = context.get("api_key") if context is not None else None
    if api_key is not None:
        ator["identity"] = {"key_id": api_key.id, "role": api_key.role_name}
    if automatic:
        ator["automatic"] = automatic
    return ator


def request_id_de(context):
    valor = getattr(context, "request_id", None)
    return valor if isinstance(valor, str) and valor else None


class ResultadoPartida:
    """Estado da reconciliacao na partida (Q6/3d-1). `estado` e um de
    vazia | reconciliada | parcial | falhou; so `vazia` significa fila
    verificavelmente vazia. `detalhe` guarda classes de erro e
    contagens, nunca conteudo de eventos."""

    def __init__(self, estado, detalhe=None):
        self.estado = estado
        self.detalhe = detalhe or {}

    @property
    def degradado(self):
        return self.estado in (sa.ESTADO_PARCIAL, sa.ESTADO_FALHOU)

    @property
    def texto(self):
        if not self.detalhe:
            return self.estado
        return "%s (%s)" % (self.estado, ", ".join(
            "%s=%s" % (k, v) for k, v in sorted(self.detalhe.items())))

    def __repr__(self):
        return "ResultadoPartida(%r, %r)" % (self.estado, self.detalhe)


def _detalhe_de(resultado):
    d = {}
    if resultado.erro is not None:
        d["erro"] = resultado.erro
    if resultado.principal_indisponivel:
        d["principal_indisponivel"] = True
    if resultado.ilegiveis:
        d["ilegiveis"] = resultado.ilegiveis
    if resultado.restantes:
        d["restantes"] = resultado.restantes
    return d


def reconciliar_na_partida():
    """Reconcilia a fila na partida de um processo (servidor ou
    monitorar). Idempotente; nunca levanta. Falha de reconciliacao NAO
    e fila vazia: devolve `parcial` ou `falhou` e alerta (canal
    notify -> stderr, com dedup por estado). Isto NAO bloqueia acoes: a
    execucao continua condicionada a cada evento ser gravado de forma
    duravel no principal ou na fila (Gate #6, P-D)."""
    chave = lambda estado: ("partida", "reconciliacao", estado)

    def degradado(estado, detalhe):
        try:
            obter_alertador().alertar(
                "reconciliacao da fila de auditoria de seguranca incompleta",
                dict(detalhe, estado=estado), chave_dedup=chave(estado))
        except Exception:
            pass
        return ResultadoPartida(estado, detalhe)

    try:
        sa.validar_caminhos()
    except Exception as exc:
        return degradado(sa.ESTADO_FALHOU, {"erro": type(exc).__name__, "causa": "configuracao_invalida"})
    try:
        auditor = obter_auditor()
        res = auditor.reconciliar_se_necessario()
    except Exception as exc:
        return degradado(sa.ESTADO_FALHOU, {"erro": type(exc).__name__})
    estado = sa.estado_reconciliacao(res)
    if estado in (sa.ESTADO_PARCIAL, sa.ESTADO_FALHOU):
        return degradado(estado, _detalhe_de(res))
    for e in (sa.ESTADO_PARCIAL, sa.ESTADO_FALHOU):  # recuperacao confirmada
        _esquecer(obter_alertador(), chave(e))
    return ResultadoPartida(estado)


def _esquecer(alertador, chave):
    esquecer = getattr(alertador, "esquecer", None)
    if esquecer is not None:
        try:
            esquecer(chave)
        except Exception:
            pass
