"""
SecurityAction e Registry (Gate #6 / Passo 3b).

Contrato fechado (secoes "SecurityAction" e Gate #6):
  Campos : decision_id, action_type, alvo=(tipo, identificador),
           origem=(tipo, identificador), motivo, risco (opcional).
  Estados: PROPOSTA -> {NEGADA | AUTORIZADA | AGUARDANDO_CONFIRMACAO}
           AUTORIZADA -> {EXECUTADA | FALHA_EXECUCAO}
           AGUARDANDO_CONFIRMACAO -> {CONFIRMADA | EXPIRADA}
           CONFIRMADA -> {EXECUTADA | FALHA_EXECUCAO}
           terminais: NEGADA, EXPIRADA, EXECUTADA, FALHA_EXECUCAO.
           Sem atalhos, sem SIMULADA (#3-A pendente).

O Registry gera o decision_id (uuid4 hex) e aplica as transicoes; o
audit (core.security_audit) so recebe e persiste. Este modulo nao
decide Policy, nao executa e nao grava: `processar` apenas orquestra
Audit, Policy e Executor injetados, na ordem do contrato:

  1. PROPOSTA emitida                       -> falha: nada executa
  2. Policy avalia; transicao emitida       -> falha: nada executa
     (a acao fica no ULTIMO ESTADO DURAVEL; decisao orfa documentada, Q4)
  3. Executor executa
  4. resultado (EXECUTADA | FALHA_EXECUCAO) -> nunca levanta e nunca
     reclassifica a acao: principal -> fila -> alerta + sinalizacao de
     perda de rastreabilidade (P2)

O estado em memoria de uma acao SO avanca depois de o evento da
transicao estar duravel (ou, no resultado, depois de a acao ter de fato
ocorrido). O Registry nao persiste estado entre chamadas: o ciclo do
Passo 3 e sincrono e o estado duravel vive nos eventos. (AGUARDANDO_
CONFIRMACAO existe na maquina de estados mas nenhum produtor o usa,
invariante 6; continuar uma confirmacao exigiria um Registry persistente,
fora do escopo.)
"""
import json
import uuid

from core import security_audit as sa
from core.validacao_defesa import sanitizar_motivo

PROPOSTA = "PROPOSTA"
NEGADA = "NEGADA"
AUTORIZADA = "AUTORIZADA"
AGUARDANDO_CONFIRMACAO = "AGUARDANDO_CONFIRMACAO"
CONFIRMADA = "CONFIRMADA"
EXPIRADA = "EXPIRADA"
EXECUTADA = "EXECUTADA"
FALHA_EXECUCAO = "FALHA_EXECUCAO"

ESTADOS = (PROPOSTA, NEGADA, AUTORIZADA, AGUARDANDO_CONFIRMACAO,
           CONFIRMADA, EXPIRADA, EXECUTADA, FALHA_EXECUCAO)

TRANSICOES = {
    PROPOSTA: frozenset({NEGADA, AUTORIZADA, AGUARDANDO_CONFIRMACAO}),
    AUTORIZADA: frozenset({EXECUTADA, FALHA_EXECUCAO}),
    AGUARDANDO_CONFIRMACAO: frozenset({CONFIRMADA, EXPIRADA}),
    CONFIRMADA: frozenset({EXECUTADA, FALHA_EXECUCAO}),
}
TERMINAIS = frozenset({NEGADA, EXPIRADA, EXECUTADA, FALHA_EXECUCAO})

# outcome = resultado efetivamente alcancado naquele evento.
OUTCOMES = {
    PROPOSTA: "proposed",
    NEGADA: "denied",
    AUTORIZADA: "authorized",
    AGUARDANDO_CONFIRMACAO: "awaiting_confirmation",
    CONFIRMADA: "confirmed",
    EXPIRADA: "expired",
    EXECUTADA: "executed",
    FALHA_EXECUCAO: "execution_failed",
}

ORIGEM_HUMANO = "humano"
ORIGEM_AUTOMATICO = "automatico"
TIPOS_DE_ORIGEM = (ORIGEM_HUMANO, ORIGEM_AUTOMATICO)


class TransicaoInvalida(Exception):
    """Transicao fora da maquina de estados do contrato (erro de programacao)."""


def _par_de_texto(valor, nome):
    if (not isinstance(valor, (tuple, list)) or len(valor) != 2
            or not all(isinstance(x, str) and x for x in valor)):
        raise ValueError("%s deve ser (tipo, identificador) com textos nao vazios" % nome)
    return (valor[0], valor[1])


class SecurityAction:
    """Registro de uma acao de seguranca. Criar via Registry.propor; o
    estado so muda por Registry.aplicar."""

    def __init__(self, decision_id, action_type, alvo, origem, motivo, risco,
                 actor, origin, correlation_id):
        self.decision_id = decision_id
        self.action_type = action_type
        self.alvo = alvo
        self.origem = origem
        self.motivo = motivo
        self.risco = risco
        self.actor = actor
        self.origin = origin
        self.correlation_id = correlation_id
        self.estado = PROPOSTA
        self.seq = 1  # PROPOSTA e a transicao 1

    @property
    def terminal(self):
        return self.estado in TERMINAIS

    def __repr__(self):
        return "SecurityAction(%s, %s, %s:%s, estado=%s, seq=%d)" % (
            self.decision_id, self.action_type, self.alvo[0], self.alvo[1], self.estado, self.seq)


class Transicao:
    """Transicao preparada, ainda NAO aplicada: carrega o evento a emitir."""

    def __init__(self, action, origem_estado, destino, seq, evento):
        self.action = action
        self.origem_estado = origem_estado
        self.destino = destino
        self.seq = seq
        self.evento = evento


class Registry:
    def __init__(self, gerador_id=None):
        self._gerador_id = gerador_id or (lambda: uuid.uuid4().hex)

    # ------------------------------------------------------------ criar
    def propor(self, action_type, alvo, origem, motivo, risco=None, *,
               actor=None, origin=None, correlation_id=None):
        """Cria a SecurityAction em PROPOSTA (seq 1), com decision_id novo.
        Nada e inferido: origem, actor e origin sao declarados por quem
        chama. Valida tudo aqui, para falhar antes de qualquer efeito."""
        if not isinstance(action_type, str) or not action_type:
            raise ValueError("action_type obrigatorio")
        alvo = _par_de_texto(alvo, "alvo")
        origem = _par_de_texto(origem, "origem")
        if origem[0] not in TIPOS_DE_ORIGEM:
            raise ValueError("tipo de origem deve ser um de %s" % (TIPOS_DE_ORIGEM,))
        if origin is None:
            raise ValueError("origin obrigatoria numa SecurityAction")
        origin = sa._validar_origin(origin)
        actor = sa._validar_actor(actor)
        if origem[0] == ORIGEM_AUTOMATICO and actor.get("automatic") != origem[1]:
            raise ValueError("acao automatica exige actor.automatic igual ao identificador da origem")
        if risco is not None:
            try:
                json.dumps(risco, allow_nan=False)
            except (TypeError, ValueError):
                raise ValueError("risco deve ser serializavel em JSON") from None
        return SecurityAction(
            decision_id=self._gerador_id(), action_type=action_type, alvo=alvo,
            origem=origem, motivo=sanitizar_motivo(motivo), risco=risco,
            actor=actor, origin=origin, correlation_id=correlation_id)

    # ----------------------------------------------------------- eventos
    def _evento(self, action, estado, seq, detalhes=None):
        payload = {
            "action_type": action.action_type,
            "target": {"type": action.alvo[0], "id": action.alvo[1]},
            "source": {"type": action.origem[0], "id": action.origem[1]},
            "reason": action.motivo,
            "state": estado,
        }
        if action.risco is not None:
            payload["risk"] = action.risco
        if detalhes:
            payload.update(detalhes)
        return sa.novo_evento(
            estado, OUTCOMES[estado], payload=payload, actor=action.actor,
            origin=action.origin, correlation_id=action.correlation_id,
            decision_id=action.decision_id, seq=seq)

    def evento_proposta(self, action):
        """Evento da transicao 1 (PROPOSTA). Nao muda o estado."""
        return self._evento(action, PROPOSTA, 1)

    def preparar(self, action, destino, detalhes=None):
        """Valida a transicao e constroi o evento, SEM alterar a acao."""
        permitidos = TRANSICOES.get(action.estado, frozenset())
        if destino not in permitidos:
            raise TransicaoInvalida("%s -> %s nao e uma transicao valida" % (action.estado, destino))
        seq = action.seq + 1
        return Transicao(action, action.estado, destino, seq,
                         self._evento(action, destino, seq, detalhes))

    def aplicar(self, transicao):
        """Aplica uma transicao preparada. Reverifica contra o estado atual
        (uma transicao velha, ja aplicada ou fora de ordem, e rejeitada)."""
        action = transicao.action
        if (action.estado != transicao.origem_estado or action.seq + 1 != transicao.seq
                or transicao.destino not in TRANSICOES.get(action.estado, frozenset())):
            raise TransicaoInvalida("transicao desatualizada ou invalida: %s -> %s (seq %d)" % (
                transicao.origem_estado, transicao.destino, transicao.seq))
        action.estado = transicao.destino
        action.seq = transicao.seq


# ------------------------------------------------------------------ ciclo

def modo_de(action):
    """Modo de emissao do audit, derivado da origem declarada."""
    return "humano" if action.origem[0] == ORIGEM_HUMANO else "automatico"


class ResultadoDoCiclo:
    """O que aconteceu, para o chamador (3c/3d) mapear em resposta."""

    def __init__(self, action):
        self.action = action
        self.decision_id = action.decision_id
        self.proposta_registada = False
        self.negada = False
        self.aguardando_confirmacao = False
        self.executado = None            # True | False | None (nao chegou a executar)
        self.info = None                 # retorno de bloquear_ip quando executou
        self.validacao_falhou = False    # ValueError de validacao de execucao
        self.erro_mensagem = None        # so para ValueError
        self.erro_classe = None
        self.audit_indisponivel = False  # a acao NAO prosseguiu por falta de audit
        self.perda_de_rastreabilidade = False  # resultado nao pode ser registado em nenhum destino
        self.eventos = []                # [(event_type, destino)]

    @property
    def estado(self):
        return self.action.estado


def processar(action, *, registry, auditor, policy, executor, expira_em_horas=None):
    """Executa o ciclo de vida de UMA acao proposta (ver docstring do
    modulo). Nao levanta por indisponibilidade de audit, falha do
    Executor ou falha ao registar o resultado; erros de programacao
    (TransicaoInvalida, ValueError de evento mal formado, excecao da
    Policy) propagam."""
    modo = modo_de(action)
    r = ResultadoDoCiclo(action)

    def emitir_e_aplicar(transicao):
        try:
            destino = auditor.emitir(transicao.evento, modo)
        except sa.AuditIndisponivel:
            r.audit_indisponivel = True
            return False
        r.eventos.append((transicao.evento["event_type"], destino))
        registry.aplicar(transicao)  # o estado so avanca com o evento duravel
        return True

    # 1. PROPOSTA
    evento = registry.evento_proposta(action)
    try:
        destino = auditor.emitir(evento, modo)
    except sa.AuditIndisponivel:
        r.audit_indisponivel = True
        return r
    r.eventos.append((PROPOSTA, destino))
    r.proposta_registada = True

    # 2. Policy
    decisao = policy.avaliar(action)
    if decisao.resultado == NEGADA:
        r.negada = True
        emitir_e_aplicar(registry.preparar(action, NEGADA, {"policy_reason": decisao.motivo}))
        return r
    if decisao.resultado == AGUARDANDO_CONFIRMACAO:
        r.aguardando_confirmacao = True
        emitir_e_aplicar(registry.preparar(action, AGUARDANDO_CONFIRMACAO,
                                           {"policy_reason": decisao.motivo}))
        return r
    if not emitir_e_aplicar(registry.preparar(action, AUTORIZADA, {"policy_reason": decisao.motivo})):
        return r  # decisao orfa em PROPOSTA; nada executa

    # 3. Execucao
    try:
        res = executor.executar(action, expira_em_horas=expira_em_horas)
    except Exception as exc:  # executor com defeito: a acao nao ocorreu
        from core.security_executor import ResultadoExecucao
        res = ResultadoExecucao(False, erro_classe=type(exc).__name__)

    # 4. Resultado: reflete a acao real, independente do audit
    r.executado = bool(res.sucesso)
    r.info = res.info
    r.erro_classe = res.erro_classe
    if res.sucesso:
        transicao = registry.preparar(action, EXECUTADA)
    else:
        r.validacao_falhou = bool(res.validacao)
        r.erro_mensagem = res.erro_mensagem if res.validacao else None
        detalhes = {"error_class": res.erro_classe}
        if res.validacao and res.erro_mensagem:
            detalhes["error"] = res.erro_mensagem
        transicao = registry.preparar(action, FALHA_EXECUCAO, detalhes)
    registry.aplicar(transicao)
    emissao = auditor.emitir_resultado(transicao.evento)
    r.perda_de_rastreabilidade = emissao.perda_de_rastreabilidade
    r.eventos.append((transicao.evento["event_type"], emissao.destino))
    return r
