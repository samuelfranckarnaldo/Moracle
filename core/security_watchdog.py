"""
Bloqueio automatico do watchdog pelo ciclo de SecurityAction
(Gate #6 / Passo 3d-1). Substitui a chamada direta a `bloquear_ip` em
`defense.monitorar()`; o loop, a contagem, os prints e o `notify.enviar`
do bloqueio continuam em `defense.py`.

DIVIDA DE AUTORIZACAO (C1/G4) - PENDENCIA EXPLICITA DO PASSO 4
  O watchdog corre como processo local da CLI, sem identidade
  autenticada. O evento regista `actor.automatic = "watchdog"`, SEM
  `identity`, com `origin = "automatic:watchdog"` e `os_user` so como
  contexto. Isto NAO constitui conformidade com o Authorization Boundary
  do #4-A: a autorizacao formal da CLI local fica para o Passo 4. Aqui a
  execucao fica condicionada a (1) evento duravel no principal ou na
  fila e (2) avaliacao da Policy; nada alem disso e afirmado.

Ordem por achado (ver Gate #6, spec 3d):
  1. validar IP e expiracao ANTES do Registry (invalido -> `ignorado`,
     sem evento, o chamador imprime `[IGNORADO]`);
  2. espera por (ip, categoria): dentro dela nao ha decisao, evento nem
     alerta;
  3. propor -> processar (PROPOSTA, Policy, AUTORIZADA, Executor,
     EXECUTADA|FALHA_EXECUCAO) com um Auditor novo por tentativa.

Causas de nao-bloqueio, mantidas distintas (nunca reclassificadas):
  audit_indisponivel  nenhum destino durável aceitou o evento (ou o
                      Auditor nao pode ser criado); inclui decisao orfa
  falha_execucao      o Executor falhou (FALHA_EXECUCAO)
  ciclo               excecao inesperada (ex.: da Policy). A Policy NUNCA
                      autoriza por excecao: a acao nao executa, o erro e
                      sinalizado e a decisao PROPOSTA fica sem terminal
                      (decisao orfa documentada, sem estado novo)
  perda de rastreabilidade (acao EXECUTADA, resultado nao gravado) NAO e
  falha de execucao: o IP foi bloqueado e `bloqueado` e True.

ESPERA_SEGUNDOS e uma protecao OPERACIONAL provisoria contra tempestade
de decisoes/alertas num loop que repete a cada linha de log. Nao e regra
de seguranca nem Policy; nunca reutiliza uma decisao aberta (cada tentativa
tem o seu proprio decision_id) e pode ser revista.
Deduplicacao de alertas: um alerta inicial por (ip, categoria, causa);
a chave e apagada na recuperacao confirmada (bloqueio com audit duravel).
"""
import logging
import time

from core import security_runtime as rt
from core.security_actions import processar
from core.validacao_defesa import normalizar_ip, validar_expiracao

_log = logging.getLogger(__name__)

COMPONENTE = "watchdog"
ORIGIN = "automatic:watchdog"
ESPERA_SEGUNDOS = 60
CATEGORIA_IOC = "ioc_conhecido"
CATEGORIA_CONTAGEM = "contagem"

CAUSA_VALIDACAO = "validacao"
CAUSA_ESPERA = "espera"
CAUSA_AUDIT = "audit_indisponivel"
CAUSA_EXECUCAO = "falha_execucao"
CAUSA_CICLO = "ciclo"
CAUSA_POLICY = "nao_autorizada"
TIPO_PERDA = "perda_de_rastreabilidade"

_EVENTOS_DE_RESULTADO = ("EXECUTADA", "FALHA_EXECUCAO")
_TIPOS_DE_CHAVE = (CAUSA_AUDIT, TIPO_PERDA, CAUSA_EXECUCAO, CAUSA_CICLO)
_LIMITE_ENTRADAS = 1024

_relogio = time.monotonic  # injetavel em teste


class GuardaDeEspera:
    """Espera por chave, em nivel de processo (sobrevive aos reinicios
    do `watch` no mesmo processo). Relogio monotonico."""

    def __init__(self):
        self._ate = {}

    def em_espera(self, chave, agora):
        ate = self._ate.get(chave)
        if ate is None:
            return False
        if agora >= ate:
            del self._ate[chave]
            return False
        return True

    def iniciar(self, chave, agora, segundos=ESPERA_SEGUNDOS):
        if len(self._ate) >= _LIMITE_ENTRADAS:
            self._ate = {k: v for k, v in self._ate.items() if v > agora}
        self._ate[chave] = agora + segundos

    def limpar(self, chave):
        self._ate.pop(chave, None)


_guarda = GuardaDeEspera()


def reiniciar_estado():
    """Zera a espera de processo (isolamento de testes)."""
    global _guarda
    _guarda = GuardaDeEspera()


class ResultadoWatchdog:
    def __init__(self):
        self.bloqueado = False
        self.ignorado = False            # alvo/expiracao invalidos: [IGNORADO]
        self.mensagem = None             # texto do ValueError quando ignorado
        self.causa = None                # uma das CAUSA_* quando nao bloqueou
        self.perda_de_rastreabilidade = False
        self.decision_id = None
        self.erro_classe = None

    def __repr__(self):
        return "ResultadoWatchdog(bloqueado=%r, ignorado=%r, causa=%r, perda=%r)" % (
            self.bloqueado, self.ignorado, self.causa, self.perda_de_rastreabilidade)


class _AlertadorComChave:
    """Envolve o alertador do Auditor: junta o contexto do watchdog e a
    chave de dedup (ip, categoria, tipo), sem alterar o Auditor. Preserva a
    causa: alerta de resultado perdido e alerta de audit indisponivel tem
    tipos e mensagens distintos e nao se suprimem entre si."""

    def __init__(self, base, ip, categoria):
        self.base = base
        self.ip = ip
        self.categoria = categoria

    def chave(self, tipo):
        return ("watchdog", self.ip, self.categoria, tipo)

    def alertar(self, mensagem, dados=None, chave_dedup=None):
        dados = dict(dados or {})
        perda = dados.get("event_type") in _EVENTOS_DE_RESULTADO
        tipo = TIPO_PERDA if perda else CAUSA_AUDIT
        if perda:
            mensagem = "perda de rastreabilidade do resultado do bloqueio (watchdog)"
        else:
            mensagem = "falha de auditoria de seguranca (watchdog)"
        dados.update({"componente": COMPONENTE, "ip": self.ip, "categoria": self.categoria})
        resultado = self.base.alertar(mensagem, dados, chave_dedup=self.chave(tipo))
        _registar_supressao(resultado, tipo, self.ip, self.categoria)
        return resultado

    def esquecer_tudo(self):
        for alertador in {id(a): a for a in (self.base, rt.obter_alertador())}.values():
            esquecer = getattr(alertador, "esquecer", None)
            if esquecer is None:
                continue
            for tipo in _TIPOS_DE_CHAVE:
                try:
                    esquecer(self.chave(tipo))
                except Exception:
                    pass


def _registar_supressao(resultado, tipo, ip, categoria):
    if resultado == "suprimido":
        _log.warning("alerta repetido suprimido (watchdog): ip=%s categoria=%s tipo=%s",
                     ip, categoria, tipo)


def _alertar_proprio(causa, ip, categoria, mensagem, extra=None):
    """Alerta gerado pelo proprio watchdog (nao pelo Auditor): falha de
    execucao, excecao do ciclo ou Auditor que nao pode ser criado."""
    try:
        dados = {"componente": COMPONENTE, "ip": ip, "categoria": categoria}
        dados.update(extra or {})
        resultado = rt.obter_alertador().alertar(
            mensagem, dados, chave_dedup=("watchdog", ip, categoria, causa))
        _registar_supressao(resultado, causa, ip, categoria)
    except Exception:
        pass


def _nao_bloqueou(r, causa, chave, agora, linha):
    r.causa = causa
    _guarda.iniciar(chave, agora)
    print(linha + "; nova tentativa apos %ds" % ESPERA_SEGUNDOS)
    return r


def tentar_bloqueio(ip, categoria, motivo, expira_em_horas=None):
    """Tenta bloquear `ip` pelo ciclo. Nunca levanta (exceto
    KeyboardInterrupt/SystemExit). Os prints de [IGNORADO], [BLOQUEIO] e a
    notificacao de bloqueio ficam com o chamador (defense.monitorar)."""
    r = ResultadoWatchdog()

    # 1. validacao ANTES do Registry: sem evento para alvos invalidos
    try:
        ip_norm = normalizar_ip(ip)
        expira = validar_expiracao(expira_em_horas)
    except ValueError as exc:
        r.ignorado = True
        r.mensagem = str(exc)
        r.causa = CAUSA_VALIDACAO
        return r

    # 2. espera por (ip, categoria)
    chave = (ip_norm, categoria)
    agora = _relogio()
    if _guarda.em_espera(chave, agora):
        r.causa = CAUSA_ESPERA
        return r

    # 3. propor + auditor
    try:
        action = rt.novo_registry().propor(
            "block_ip", ("ip", ip_norm), ("automatico", COMPONENTE), motivo,
            actor=rt.ator_http(None, automatic=COMPONENTE), origin=ORIGIN)
    except Exception as exc:
        r.erro_classe = type(exc).__name__
        _alertar_proprio(CAUSA_CICLO, ip_norm, categoria,
                         "falha no ciclo de seguranca (watchdog)", {"erro_classe": r.erro_classe})
        return _nao_bloqueou(r, CAUSA_CICLO, chave, agora,
                             "[FALHA-CICLO] %s nao foi bloqueado: %s" % (ip, r.erro_classe))
    try:
        auditor = rt.obter_auditor()
    except Exception as exc:
        r.erro_classe = type(exc).__name__
        _alertar_proprio(CAUSA_AUDIT, ip_norm, categoria,
                         "falha de auditoria de seguranca (watchdog)",
                         {"erro_classe": r.erro_classe, "causa": "auditor_indisponivel"})
        return _nao_bloqueou(r, CAUSA_AUDIT, chave, agora,
                             "[AUDIT-INDISPONIVEL] %s nao foi bloqueado: auditoria duravel indisponivel" % ip)

    alertador = _AlertadorComChave(auditor.alertador, ip_norm, categoria)
    auditor.alertador = alertador

    # 4. ciclo
    try:
        res = processar(action, registry=rt.novo_registry(), auditor=auditor,
                        policy=rt.obter_policy(), executor=rt.obter_executor(),
                        expira_em_horas=expira)
    except Exception as exc:
        # Ex.: excecao da Policy. NAO autoriza: a acao nao executa; a decisao
        # PROPOSTA fica orfa (sem estado novo) e o erro e sinalizado.
        r.erro_classe = type(exc).__name__
        r.decision_id = action.decision_id
        _alertar_proprio(CAUSA_CICLO, ip_norm, categoria,
                         "falha no ciclo de seguranca (watchdog)",
                         {"erro_classe": r.erro_classe, "decision_id": action.decision_id})
        return _nao_bloqueou(r, CAUSA_CICLO, chave, agora,
                             "[FALHA-CICLO] %s nao foi bloqueado: %s" % (ip, r.erro_classe))

    r.decision_id = action.decision_id
    if res.audit_indisponivel:  # o Auditor ja alertou (tipo audit_indisponivel)
        return _nao_bloqueou(r, CAUSA_AUDIT, chave, agora,
                             "[AUDIT-INDISPONIVEL] %s nao foi bloqueado: auditoria duravel indisponivel" % ip)
    if res.negada or res.aguardando_confirmacao:
        return _nao_bloqueou(r, CAUSA_POLICY, chave, agora,
                             "[NAO-AUTORIZADO] %s nao foi bloqueado: Policy" % ip)
    if res.executado:
        r.bloqueado = True
        r.perda_de_rastreabilidade = bool(res.perda_de_rastreabilidade)
        _guarda.limpar(chave)
        if r.perda_de_rastreabilidade:
            print("[RASTREABILIDADE] %s foi bloqueado, mas o resultado nao pode ser registado" % ip)
        else:
            alertador.esquecer_tudo()  # recuperacao confirmada (K1)
        return r
    if res.validacao_falhou:  # nao deveria ocorrer (validado acima)
        r.ignorado = True
        r.mensagem = res.erro_mensagem
        r.causa = CAUSA_VALIDACAO
        _guarda.iniciar(chave, agora)
        return r
    r.erro_classe = res.erro_classe
    _alertar_proprio(CAUSA_EXECUCAO, ip_norm, categoria,
                     "falha de execucao do bloqueio (watchdog)",
                     {"erro_classe": res.erro_classe, "decision_id": action.decision_id})
    return _nao_bloqueou(r, CAUSA_EXECUCAO, chave, agora,
                         "[FALHA-EXECUCAO] %s nao foi bloqueado: %s" % (ip, res.erro_classe))
