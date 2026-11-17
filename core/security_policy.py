"""
Policy de seguranca (Gate #6 / Passo 3b) - SO a Policy de passagem.

Eixos independentes: Authorization decide "pode SOLICITAR a capacidade?"
(fora daqui, ja existente), a Policy decide "alguma condicao do sistema
impede?", o Executor executa e reporta, o Audit regista.

No Passo 3 a Policy NAO cria regra nova: reproduz o comportamento atual,
em que toda acao proposta pelos tres caminhos (humano via /block,
automatico via /ingest e watchdog) e autorizada diretamente
(invariantes 2, 3 e 5). Em particular:
  - nao nega nada (NEGADA fica alcancavel so por Policies de teste);
  - nao pede confirmacao (invariante 6: ninguem usa AGUARDANDO_CONFIRMACAO);
  - nao diferencia alto de critico (decisao futura e nova);
  - nao restringe tipo de acao nem componente de origem: uma acao
    nao suportada pelo Executor falha la como FALHA_EXECUCAO, nunca
    como negacao. Negar tipos desconhecidos seria regra nova (passo 4).
A validacao de IP/expiracao continua em bloquear_ip e nao e Policy
(invariante 7). "Nenhuma acao proposta" (ingest baixo/medio) e decidido
por quem produz o achado e nunca chega aqui (invariante 1).
"""

AUTORIZADA = "AUTORIZADA"
NEGADA = "NEGADA"
AGUARDANDO_CONFIRMACAO = "AGUARDANDO_CONFIRMACAO"

RESULTADOS_VALIDOS = (AUTORIZADA, NEGADA, AGUARDANDO_CONFIRMACAO)


class Decisao:
    """Resultado da avaliacao: um dos estados que a Policy pode escolher
    a partir de PROPOSTA, mais o motivo (texto curto, sem dados sensiveis)."""

    def __init__(self, resultado, motivo=None):
        if resultado not in RESULTADOS_VALIDOS:
            raise ValueError("resultado de Policy invalido: %r" % (resultado,))
        self.resultado = resultado
        self.motivo = motivo

    def __repr__(self):
        return "Decisao(%r, %r)" % (self.resultado, self.motivo)


class PolicyDePassagem:
    """Policy do Passo 3: autoriza sempre (ver docstring do modulo)."""

    def avaliar(self, action):
        return Decisao(AUTORIZADA, "passo 3: policy de passagem")
