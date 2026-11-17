"""
Executor de acoes de seguranca (Gate #6 / Passo 3b).

Unico ponto que chama `defense.bloquear_ip` a partir do ciclo de vida de
SecurityAction. Executa e reporta; nao autoriza, nao decide Policy e nao
regista audit. `bloquear_ip` continua sendo so o efeito (a assinatura e
o comportamento nao mudam).

Resultado:
  sucesso=True              -> EXECUTADA
  sucesso=False             -> FALHA_EXECUCAO (nunca NEGADA)
    validacao=True          -> ValueError de validacao de execucao
                               (IP/expiracao invalidos): o chamador HTTP
                               continua devolvendo 400 como hoje
    validacao=False         -> acao nao suportada ou erro inesperado
A mensagem de erro so e exposta para ValueError (validacao); para os
demais erros guarda-se apenas a classe, para nao vazar caminhos nem
detalhes internos ao audit ou ao cliente.
"""

ACAO_BLOCK_IP = "block_ip"
ALVO_IP = "ip"
LIMITE_MENSAGEM = 200


class ResultadoExecucao:
    def __init__(self, sucesso, info=None, erro_classe=None, erro_mensagem=None, validacao=False):
        self.sucesso = sucesso
        self.info = info
        self.erro_classe = erro_classe
        self.erro_mensagem = erro_mensagem
        self.validacao = validacao

    def __repr__(self):
        return "ResultadoExecucao(sucesso=%r, erro_classe=%r, validacao=%r)" % (
            self.sucesso, self.erro_classe, self.validacao)


class Executor:
    """`bloquear` e injetavel (testes); por padrao resolve
    core.defense.bloquear_ip no momento da chamada (import tardio, para
    nao criar ciclo com core.defense, que usara este modulo no 3d)."""

    def __init__(self, bloquear=None):
        self._bloquear = bloquear

    def _resolver_bloquear(self):
        if self._bloquear is not None:
            return self._bloquear
        from core import defense
        return defense.bloquear_ip

    def executar(self, action, expira_em_horas=None):
        """Nunca levanta (exceto KeyboardInterrupt/SystemExit)."""
        try:
            if action.action_type != ACAO_BLOCK_IP:
                return ResultadoExecucao(False, erro_classe="AcaoNaoSuportada")
            tipo, identificador = action.alvo
            if tipo != ALVO_IP:
                return ResultadoExecucao(False, erro_classe="AlvoNaoSuportado")
            bloquear = self._resolver_bloquear()
            info = bloquear(identificador, motivo=action.motivo, expira_em_horas=expira_em_horas)
            return ResultadoExecucao(True, info=info)
        except ValueError as exc:
            return ResultadoExecucao(False, erro_classe="ValueError",
                                     erro_mensagem=str(exc)[:LIMITE_MENSAGEM], validacao=True)
        except Exception as exc:
            return ResultadoExecucao(False, erro_classe=type(exc).__name__)
