"""
Ciclo de auditoria para mutacoes humanas (Passos 4b-2..4b-4).

Mesma semantica do Gate #6 usada pelo SecurityAction, para mutacoes que nao
sao acoes de Policy (identidade, IOC, config):

  1. evento `outcome="requested"` gravado de forma duravel ANTES da mutacao
     (falha fechada: se o auditor nao aceita, nada acontece);
  2. a mutacao (`gravar`);
  3. evento de resultado (`success`/`failure`, correlacionado pelo event_id
     do pedido), em melhor esforco: nunca reverte nem altera a mutacao e
     sinaliza `perda_de_rastreabilidade` se nao puder ser gravado.

Os payloads sao montados por quem chama e NUNCA devem conter segredos
(tokens, hashes de chave, valores de configuracao sensiveis, caminhos
absolutos). Este modulo nao os inspeciona.
"""
from core import security_audit as sa
from core import security_runtime as rt

OK = "ok"
AUDIT_INDISPONIVEL = "audit_indisponivel"
FALHA = "falha"


class ResultadoCiclo:
    def __init__(self, estado, dados=None, perda=False, erro=None):
        self.estado = estado
        self.dados = dados or {}
        self.perda_de_rastreabilidade = perda
        self.erro = erro            # so a CLASSE da excecao

    @property
    def sucesso(self):
        return self.estado == OK

    def __repr__(self):
        return "ResultadoCiclo(%r)" % (self.estado,)


def ciclo_auditado(event_type, pedido, gravar, ator, origin, correlation_id=None,
                   repropagar=()):
    """Executa o ciclo. `gravar()` devolve um dict (campos do resultado).
    Excecoes de `gravar`: as do tipo `repropagar` sao registadas como
    failure e levantadas de novo (erros de dominio que o chamador traduz);
    as restantes viram ResultadoCiclo(FALHA, erro=classe). Nunca levanta
    por falha de auditoria."""
    try:
        requested = sa.novo_evento(event_type, "requested", payload=pedido, actor=ator,
                                   origin=origin, correlation_id=correlation_id)
        auditor = rt.obter_auditor()
    except Exception as exc:
        rt.alertar_infraestrutura(exc, "audit-ciclo")
        return ResultadoCiclo(AUDIT_INDISPONIVEL)
    try:
        auditor.emitir(requested, "humano")
    except sa.AuditIndisponivel:
        return ResultadoCiclo(AUDIT_INDISPONIVEL)

    dados, outcome, erro, excecao = None, "success", None, None
    try:
        dados = gravar()
    except Exception as exc:
        outcome, erro, excecao = "failure", type(exc).__name__, exc
    perda = False
    try:
        payload = dict(pedido, **(dados or {})) if outcome == "success" else dict(pedido, error=erro)
        evento = sa.novo_evento(event_type, outcome, payload=payload, actor=ator, origin=origin,
                                correlation_id=requested["event_id"])
        perda = auditor.emitir_resultado(evento).perda_de_rastreabilidade
    except Exception:
        perda = True
    if excecao is not None and repropagar and isinstance(excecao, tuple(repropagar)):
        raise excecao
    if outcome == "failure":
        return ResultadoCiclo(FALHA, perda=perda, erro=erro)
    return ResultadoCiclo(OK, dados=dados, perda=perda)


def registar_fato(event_type, payload, ator, origin):
    """Evento de um fato JA OCORRIDO (ex.: migracao da chave legada), em
    melhor esforco. Devolve True se ficou gravado (principal ou fila)."""
    try:
        evento = sa.novo_evento(event_type, "success", payload=payload, actor=ator, origin=origin)
        auditor = rt.obter_auditor()
        res = auditor.emitir_resultado(evento)
        return not res.perda_de_rastreabilidade
    except Exception as exc:
        rt.alertar_infraestrutura(exc, "audit-fato")
        return False
