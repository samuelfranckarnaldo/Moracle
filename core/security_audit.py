"""
Auditoria de eventos de seguranca (Gate #6 / Passo 3a).

Este modulo SO registra. Nao decide autorizacao, Policy nem execucao, e
nao conhece SecurityAction, Registry ou Executor (partes 3b em diante):
quem produz o evento fornece decision_id/seq; aqui eles apenas sao
validados e persistidos.

Pecas:
  - novo_evento / evento_config_changed: constroem o evento (esquema
    comum, redacao aplicada so a copia que vai para o log).
  - DestinoJsonl: destino com a interface `gravar(evento) -> bool`
    (True = gravacao CONFIRMADA com flush+fsync; False = falha). Nunca
    levanta excecao. O audit principal e a fila usam a mesma interface.
  - FilaDuravel (DestinoJsonl + leitura): fila de recuperacao em disco.
  - reconciliar: move eventos da fila para o principal de forma
    idempotente (event_id e (decision_id, seq)).
  - Auditor: aplica a semantica de falha do contrato.
      humano       : principal -> falha => AuditIndisponivel (a fila NAO
                     substitui o principal para acao humana; P1).
      automatico   : principal -> fila -> falha => AuditIndisponivel.
      resultado    : (acao ja ocorreu) principal -> fila -> alerta +
                     sinalizacao de perda de rastreabilidade; nunca
                     levanta e nunca altera o resultado da acao (P2).
  - alertar: notify.enviar (melhor esforco) e, se falhar, stderr.
    alerts.log NAO e canal de emergencia (fica em .state/).

Caminhos sao resolvidos no momento do uso (nunca como constante de
modulo), contra config.RAIZ_PROJETO, para que o isolamento de estado
dos testes os cubra automaticamente.
"""
import fcntl
import json
import logging
import os
import sys
import tempfile
import uuid
from datetime import datetime, timezone

from core import config
from core.atomic_state import FileLock
# Redacao: reutiliza a politica ja aprovada (piso por nome + regra de
# config). Sao helpers privados de core.audit, usados aqui de proposito
# para existir UMA politica de redacao so.
from core.audit import _nome_de_config, _redigir, _valor_de_config_visivel

SCHEMA_VERSION = 1

MODOS = ("humano", "automatico")
CAMPOS_ACTOR = ("os_user", "identity", "automatic")
ORIGENS_FIXAS = ("cli-local", "http")
NOME_ARQUIVO_FILA = "fila_eventos.jsonl"
LIMITE_RECONCILIACAO_PADRAO = 1000

_log = logging.getLogger("moracle.application")


# ---------------------------------------------------------------- erros

class AuditIndisponivel(Exception):
    """Nenhum destino exigido aceitou o evento. NAO e negacao de Policy
    nem falha de execucao: e uma categoria propria."""

    def __init__(self, destinos_falhos, evento=None):
        self.destinos_falhos = tuple(destinos_falhos)
        self.event_id = (evento or {}).get("event_id")
        self.decision_id = (evento or {}).get("decision_id")
        super().__init__(
            "audit indisponivel (destinos: %s)" % ", ".join(self.destinos_falhos)
        )


class ErroDeConfiguracaoAudit(Exception):
    """Configuracao de auditoria invalida (ex.: principal e fila iguais)."""


# --------------------------------------------------------------- evento

def _agora_utc():
    return datetime.now(timezone.utc).isoformat()


def _validar_actor(actor):
    if actor is None:
        return {}
    if not isinstance(actor, dict):
        raise ValueError("actor deve ser um dict")
    extras = set(actor) - set(CAMPOS_ACTOR)
    if extras:
        raise ValueError("campos de actor desconhecidos: %s" % sorted(extras))
    # Campo ausente fica ausente; None explicito tambem nao e gravado.
    # Nada aqui preenche os_user/identity/automatic por inferencia.
    return {k: v for k, v in actor.items() if v is not None}


def _validar_origin(origin):
    if origin is None:
        return None
    if not isinstance(origin, str) or not origin:
        raise ValueError("origin deve ser texto nao vazio")
    if origin in ORIGENS_FIXAS or (
        origin.startswith("automatic:") and len(origin) > len("automatic:")
    ):
        return origin
    raise ValueError("origin invalida: %r" % (origin,))


def novo_evento(event_type, outcome, *, payload=None, actor=None, origin=None,
                correlation_id=None, decision_id=None, seq=None,
                event_id=None, timestamp=None, redigir_payload=True):
    """Constroi um evento do esquema comum (dict pronto para JSONL).

    - event_id: gerado aqui na primeira emissao (uuid4 hex) e conservado
      em todas as tentativas e na reconciliacao (P3). Quem reemite um
      evento existente passa o mesmo event_id.
    - decision_id/seq: fornecidos pelo Registry (3b); aqui so se valida
      que vem juntos e que seq >= 1. Eventos de mutacao nao os tem.
    - outcome: resultado EFETIVAMENTE alcançado, informado por quem
      produz o evento; este modulo nunca o infere.
    - payload: passa pela redacao aprovada (piso por nome de campo); o
      original nao e alterado. `redigir_payload=False` so e usado por
      construtores que ja aplicam regra propria de redacao (config.changed).
    - actor: tres campos independentes e opcionais; nada e inferido.
    Levanta ValueError para evento mal formado ou nao serializavel
    (erro de programacao, distinto de indisponibilidade do audit)."""
    if not isinstance(event_type, str) or not event_type:
        raise ValueError("event_type obrigatorio")
    if not isinstance(outcome, str) or not outcome:
        raise ValueError("outcome obrigatorio")
    if (decision_id is None) != (seq is None):
        raise ValueError("decision_id e seq devem ser informados juntos")
    if decision_id is not None:
        if not isinstance(decision_id, str) or not decision_id:
            raise ValueError("decision_id invalido")
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
            raise ValueError("seq deve ser inteiro >= 1")
    if payload is not None and not isinstance(payload, dict):
        raise ValueError("payload deve ser dict")

    evento = {
        "schema_version": SCHEMA_VERSION,
        "event_id": event_id or uuid.uuid4().hex,
        "timestamp": timestamp or _agora_utc(),
        "event_type": event_type,
        "outcome": outcome,
        "actor": _validar_actor(actor),
        "payload": (_redigir(dict(payload)) if redigir_payload else dict(payload)) if payload else {},
    }
    origem = _validar_origin(origin)
    if origem is not None:
        evento["origin"] = origem
    if correlation_id is not None:
        evento["correlation_id"] = correlation_id
    if decision_id is not None:
        evento["decision_id"] = decision_id
        evento["seq"] = seq
    try:
        json.dumps(evento, ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValueError("evento nao serializavel em JSON: %s" % exc) from None
    return evento


def _equivalentes(a, b):
    """Igualdade de valores de config sem confundir bool com numero
    (True == 1 em Python, mas True -> 1 e uma mudanca real)."""
    if isinstance(a, bool) != isinstance(b, bool):
        return False
    return a == b


def evento_config_changed(chave, valor_anterior, valor_novo, *, outcome="success",
                          actor=None, origin=None, correlation_id=None):
    """Evento de mutacao de configuracao (sem decision_id).

    Devolve None quando o valor efetivo NAO mudou (criterio 15): nao ha
    mutacao a registrar. A comparacao usa os valores reais, ANTES da
    redacao. Os dois valores so ficam em claro para chaves
    classificadas como nao sensiveis; qualquer outra chave
    (sensivel, desconhecida ou de tipo inesperado) tem anterior e novo
    redigidos, mas a mudanca continua registrada.

    Observacao: a config nao tem funcao de normalizacao propria alem de
    _validar; o chamador deve passar valores ja normalizados."""
    if _equivalentes(valor_anterior, valor_novo):
        return None
    if not isinstance(chave, str) or not chave:
        raise ValueError("chave de config obrigatoria")
    visivel = _valor_de_config_visivel(chave)

    def _v(valor):
        if visivel:
            return _redigir(valor)
        return None if valor is None else "***"

    return novo_evento(
        "config.changed", outcome,
        payload={"key": _nome_de_config(chave), "previous_value": _v(valor_anterior),
                 "new_value": _v(valor_novo)},
        actor=actor, origin=origin, correlation_id=correlation_id,
        redigir_payload=False,
    )


# -------------------------------------------------------------- destinos

def _fsync_diretorio(diretorio):
    try:
        fd = os.open(diretorio, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _escrever_tudo(fd, dados):
    visao = memoryview(dados)
    while visao:
        n = os.write(fd, visao)
        visao = visao[n:]


class DestinoJsonl:
    """Destino JSONL com a interface `gravar(evento) -> bool`.

    `caminho` e um texto ou um callable sem argumentos (resolvido a cada
    uso). Escrita: lock de arquivo entre threads e processos, modo 0600,
    uma linha por chamada, flush+fsync antes de devolver True. Se o
    arquivo terminar sem '\\n' (escrita anterior interrompida), uma
    quebra de linha e inserida primeiro para isolar a linha truncada."""

    def __init__(self, caminho):
        self._caminho = caminho
        self.ultimo_erro = None

    def caminho(self):
        return self._caminho() if callable(self._caminho) else self._caminho

    def gravar(self, evento):
        try:
            linha = json.dumps(evento, ensure_ascii=False, allow_nan=False)
            dados = (linha + "\n").encode("utf-8")
            caminho = self.caminho()
            diretorio = os.path.dirname(os.path.abspath(caminho))
            os.makedirs(diretorio, mode=0o700, exist_ok=True)
            novo = not os.path.exists(caminho)
            with FileLock(caminho):
                fd = os.open(caminho, os.O_RDWR | os.O_APPEND | os.O_CREAT, 0o600)
                try:
                    try:
                        os.fchmod(fd, 0o600)
                    except OSError:
                        pass
                    tamanho = os.fstat(fd).st_size
                    if tamanho > 0:
                        ultimo = os.pread(fd, 1, tamanho - 1)
                        if ultimo != b"\n":
                            dados = b"\n" + dados
                    _escrever_tudo(fd, dados)
                    os.fsync(fd)
                finally:
                    os.close(fd)
            if novo:
                _fsync_diretorio(diretorio)
            self.ultimo_erro = None
            return True
        except Exception as exc:  # a interface nunca levanta
            self.ultimo_erro = type(exc).__name__
            return False

    def _linhas(self):
        caminho = self.caminho()
        if not os.path.exists(caminho):
            return []
        with open(caminho, "r", encoding="utf-8", errors="replace") as f:
            return f.read().split("\n")

    def ids_existentes(self):
        """Chaves de deduplicacao dos eventos ja aceitos: ("id", event_id) e
        ("ds", decision_id, seq). Linhas ilegiveis sao ignoradas. Levanta
        OSError se o arquivo nao puder ser lido."""
        chaves = set()
        for linha in self._linhas():
            if not linha.strip():
                continue
            try:
                ev = json.loads(linha)
            except ValueError:
                continue
            chaves.update(_chaves_de_dedup(ev))
        return chaves

    def ler_eventos(self):
        eventos = []
        for linha in self._linhas():
            if not linha.strip():
                continue
            try:
                ev = json.loads(linha)
            except ValueError:
                continue
            if isinstance(ev, dict):
                eventos.append(ev)
        return eventos


class FilaDuravel(DestinoJsonl):
    """Fila de recuperacao persistente (mesma interface do principal)."""

    def esta_vazia(self):
        """True SO se a fila verificavelmente nao existe ou tem tamanho 0.
        Qualquer outro erro de I/O (permissao, caminho ilegivel...) PROPAGA:
        uma fila que nao se consegue ler nao pode passar por vazia (3d-1)."""
        try:
            return os.stat(self.caminho()).st_size == 0
        except FileNotFoundError:
            return True


def _chaves_de_dedup(ev):
    chaves = []
    if isinstance(ev, dict):
        if ev.get("event_id"):
            chaves.append(("id", ev["event_id"]))
        if ev.get("decision_id") is not None and ev.get("seq") is not None:
            chaves.append(("ds", ev["decision_id"], ev["seq"]))
    return chaves


# ---------------------------------------------------------- reconciliacao

class ResultadoReconciliacao:
    def __init__(self):
        self.movidos = 0
        self.descartados_duplicados = 0
        self.ilegiveis = 0
        self.restantes = 0
        self.principal_indisponivel = False
        self.erro = None  # classe da excecao de I/O inesperada (ex.: falha ao reescrever a fila)

    def __repr__(self):
        return ("ResultadoReconciliacao(movidos=%d, descartados_duplicados=%d, "
                "ilegiveis=%d, restantes=%r, principal_indisponivel=%s, erro=%r)" % (
                    self.movidos, self.descartados_duplicados, self.ilegiveis,
                    self.restantes, self.principal_indisponivel, self.erro))


ESTADO_VAZIA = "vazia"
ESTADO_RECONCILIADA = "reconciliada"
ESTADO_PARCIAL = "parcial"
ESTADO_FALHOU = "falhou"


def estado_reconciliacao(resultado):
    """Classifica o resultado de uma reconciliacao (3d-1). So `vazia`
    significa fila verificavelmente vazia; falha nunca vira `vazia`.
      None                         -> vazia
      erro de I/O inesperado       -> falhou
      principal indisponivel, linhas restantes ou ilegiveis -> parcial
      caso contrario               -> reconciliada"""
    if resultado is None:
        return ESTADO_VAZIA
    if resultado.erro is not None:
        return ESTADO_FALHOU
    if resultado.principal_indisponivel or resultado.ilegiveis or (resultado.restantes or 0) > 0:
        return ESTADO_PARCIAL
    return ESTADO_RECONCILIADA


def _reescrever_fila(caminho, linhas):
    """Reescreve a fila de forma atomica (temp + fsync + replace), 0600."""
    diretorio = os.path.dirname(os.path.abspath(caminho))
    fd, temporario = tempfile.mkstemp(dir=diretorio, prefix=".tmp_fila_")
    try:
        try:
            os.fchmod(fd, 0o600)
        except OSError:
            pass
        conteudo = "".join(l + "\n" for l in linhas).encode("utf-8")
        _escrever_tudo(fd, conteudo)
        os.fsync(fd)
        os.close(fd)
        fd = None
        os.replace(temporario, caminho)
        _fsync_diretorio(diretorio)
    except BaseException:
        if fd is not None:
            os.close(fd)
        if os.path.exists(temporario):
            os.remove(temporario)
        raise


def reconciliar(fila, principal, *, maximo=LIMITE_RECONCILIACAO_PADRAO):
    """Move eventos da fila para o principal, de forma idempotente.

    Garantias:
      - um evento so sai da fila DEPOIS de o principal confirmar a
        gravacao (ou de ja existir la, por event_id ou (decision_id,
        seq));
      - uma interrupcao entre gravar no principal e reescrever a fila
        deixa o evento nos dois lados, e a proxima reconciliacao o
        descarta como duplicado (nao reinsere);
      - event_id, decision_id, seq e timestamp originais sao
        preservados; acrescenta-se `reconciled_at`;
      - linhas ilegiveis permanecem na fila (nada e perdido em silencio);
      - principal indisponivel => a fila fica intacta.
    Nunca levanta: principal ilegivel/falhando vira `principal_indisponivel`;
    qualquer outro erro de I/O vira `erro` e deixa a fila como estava. `maximo` limita o trabalho por chamada, para nao
    segurar o lock da fila por muito tempo."""
    resultado = ResultadoReconciliacao()
    try:
        caminho_fila = fila.caminho()
        if not os.path.exists(caminho_fila):
            return resultado
        with FileLock(caminho_fila):
            linhas = [l for l in fila._linhas() if l.strip()]
            if not linhas:
                return resultado
            try:
                conhecidos = principal.ids_existentes()
            except Exception:
                resultado.principal_indisponivel = True
                resultado.restantes = len(linhas)
                return resultado

            restantes = []
            processados = 0
            parar = False
            for linha in linhas:
                if parar or processados >= maximo:
                    restantes.append(linha)
                    continue
                try:
                    ev = json.loads(linha)
                    if not isinstance(ev, dict):
                        raise ValueError("evento nao e objeto")
                except ValueError:
                    resultado.ilegiveis += 1
                    restantes.append(linha)
                    continue
                processados += 1
                chaves = _chaves_de_dedup(ev)
                if any(c in conhecidos for c in chaves):
                    resultado.descartados_duplicados += 1
                    continue
                ev_final = dict(ev)
                ev_final["reconciled_at"] = _agora_utc()
                if principal.gravar(ev_final):
                    conhecidos.update(chaves)
                    resultado.movidos += 1
                else:
                    resultado.principal_indisponivel = True
                    restantes.append(linha)
                    parar = True

            if len(restantes) != len(linhas):
                _reescrever_fila(caminho_fila, restantes)
            resultado.restantes = len(restantes)
    except Exception as exc:
        # Ex.: falha ao reescrever a fila depois de gravar no principal. Os
        # eventos ja gravados ficam nos DOIS lados e a proxima reconciliacao
        # os descarta como duplicados. `movidos` conta gravacoes confirmadas
        # no principal; `restantes` fica indeterminado (None).
        resultado.erro = type(exc).__name__
        resultado.restantes = None
    return resultado


# ---------------------------------------------------------------- alerta

class Alertador:
    """Canal de alerta de falha de audit: notify.enviar (melhor esforco,
    so se webhook configurado) e, se nao enviar, stderr. alerts.log nao
    e usado. A mensagem so leva event_type, ids, destinos e classe do
    erro — nunca payload nem valores redigiveis."""

    def __init__(self):
        self._ja_alertados = set()

    def esquecer(self, chave_dedup):
        """Apaga uma chave de dedup (recuperacao confirmada): uma falha
        posterior com a mesma chave volta a alertar (K1, 3d-1)."""
        self._ja_alertados.discard(chave_dedup)

    def alertar(self, mensagem, dados=None, chave_dedup=None):
        """Devolve "webhook", "stderr", "nenhum" ou "suprimido" (dedup)."""
        if chave_dedup is not None:
            if chave_dedup in self._ja_alertados:
                return "suprimido"
            self._ja_alertados.add(chave_dedup)
        try:
            from core import notify  # import tardio: requests e opcional aqui
            if notify.enviar(mensagem, dados_extra=dados):
                return "webhook"
        except Exception:
            pass
        try:
            sys.stderr.write("[MORACLE AUDIT] %s %s\n" % (
                mensagem, json.dumps(dados, ensure_ascii=False, default=str)
                if dados else ""))
            sys.stderr.flush()
            return "stderr"
        except Exception:
            return "nenhum"


# ---------------------------------------------------------------- Auditor

class ResultadoEmissaoResultado:
    """Retorno de emitir_resultado: onde o evento ficou e se a
    rastreabilidade do resultado foi perdida."""

    def __init__(self, destino, perda_de_rastreabilidade, canal_alerta=None):
        self.destino = destino              # "principal" | "fila" | "perdido"
        self.perda_de_rastreabilidade = perda_de_rastreabilidade
        self.canal_alerta = canal_alerta

    def __repr__(self):
        return "ResultadoEmissaoResultado(%r, perda=%r)" % (
            self.destino, self.perda_de_rastreabilidade)


class Auditor:
    def __init__(self, principal, fila, alertador=None, maximo_reconciliacao=LIMITE_RECONCILIACAO_PADRAO):
        self.principal = principal
        self.fila = fila
        self.alertador = alertador or Alertador()
        self.maximo_reconciliacao = maximo_reconciliacao
        self.degradacoes = 0  # eventos que foram para a fila por falha do principal

    # -- reconciliacao oportunista (Q6): antes de novas emissoes ------
    def reconciliar_se_necessario(self):
        """None SO quando a fila esta verificavelmente vazia. Qualquer
        falha (inclusive ao verificar se esta vazia) devolve um
        ResultadoReconciliacao com `erro` preenchido: falha nunca e
        reportada como fila vazia (3d-1). Nunca levanta."""
        try:
            if self.fila.esta_vazia():
                return None
            return reconciliar(self.fila, self.principal, maximo=self.maximo_reconciliacao)
        except Exception as exc:
            resultado = ResultadoReconciliacao()
            resultado.erro = type(exc).__name__
            resultado.restantes = None
            return resultado

    def _alertar_falha(self, evento, destinos, destino_erro):
        dados = {
            "event_type": evento.get("event_type"),
            "event_id": evento.get("event_id"),
            "decision_id": evento.get("decision_id"),
            "destinos_falhos": list(destinos),
            "erro": destino_erro,
        }
        return self.alertador.alertar("falha de auditoria de seguranca", dados)

    def emitir(self, evento, modo):
        """Emissao ANTES da execucao. Devolve "principal" ou "fila";
        levanta AuditIndisponivel se a acao NAO pode prosseguir."""
        if modo not in MODOS:
            raise ValueError("modo deve ser um de %s" % (MODOS,))
        self.reconciliar_se_necessario()

        if self.principal.gravar(evento):
            return "principal"

        if modo == "humano":
            self._alertar_falha(evento, ["principal"], self.principal.ultimo_erro)
            raise AuditIndisponivel(["principal"], evento)

        if self.fila.gravar(evento):
            self.degradacoes += 1
            _log.warning("audit principal indisponivel; evento %s na fila de recuperacao",
                         evento.get("event_id"))
            return "fila"

        self._alertar_falha(
            evento, ["principal", "fila"],
            "principal=%s fila=%s" % (self.principal.ultimo_erro, self.fila.ultimo_erro))
        raise AuditIndisponivel(["principal", "fila"], evento)

    def emitir_resultado(self, evento):
        """Emissao do evento de RESULTADO, depois de a acao ocorrer.
        Nunca levanta e nunca reclassifica a acao: principal -> fila ->
        alerta + perda_de_rastreabilidade. (Vale para humano e automatico.)"""
        try:
            self.reconciliar_se_necessario()
            if self.principal.gravar(evento):
                return ResultadoEmissaoResultado("principal", False)
            if self.fila.gravar(evento):
                self.degradacoes += 1
                return ResultadoEmissaoResultado("fila", False)
            canal = self._alertar_falha(
                evento, ["principal", "fila"],
                "principal=%s fila=%s" % (self.principal.ultimo_erro, self.fila.ultimo_erro))
            return ResultadoEmissaoResultado("perdido", True, canal)
        except Exception:
            return ResultadoEmissaoResultado("perdido", True, "nenhum")


# ------------------------------------------------------ caminhos e fabrica

def _resolver(caminho):
    return caminho if os.path.isabs(caminho) else os.path.join(config.RAIZ_PROJETO, caminho)


def _config_auditoria():
    cfg = (config.carregar().get("auditoria") or {})
    padrao = config.PADRAO["auditoria"]
    saida = {}
    for chave in ("arquivo_eventos", "diretorio_fila"):
        valor = cfg.get(chave, padrao[chave])
        if not isinstance(valor, str) or not valor.strip():
            raise ErroDeConfiguracaoAudit("auditoria.%s invalido: %r" % (chave, valor))
        saida[chave] = valor
    return saida


def caminho_eventos():
    return _resolver(_config_auditoria()["arquivo_eventos"])


def caminho_fila():
    return os.path.join(_resolver(_config_auditoria()["diretorio_fila"]), NOME_ARQUIVO_FILA)


def validar_caminhos():
    """Principal e fila precisam ser distintos: arquivos diferentes E
    diretorios diferentes. Mesmo dispositivo e permitido (risco
    correlacionado residual, documentado), mas nunca o mesmo caminho."""
    principal = os.path.realpath(caminho_eventos())
    fila = os.path.realpath(caminho_fila())
    if principal == fila:
        raise ErroDeConfiguracaoAudit("audit principal e fila apontam para o mesmo arquivo")
    if os.path.dirname(principal) == os.path.dirname(fila):
        raise ErroDeConfiguracaoAudit(
            "audit principal e fila nao podem ficar no mesmo diretorio: %s" % os.path.dirname(principal))
    return principal, fila


def criar_auditor_padrao(alertador=None):
    """Auditor com os destinos da configuracao. Valida os caminhos na
    criacao (falha cedo, antes de qualquer acao protegida)."""
    validar_caminhos()
    return Auditor(DestinoJsonl(caminho_eventos), FilaDuravel(caminho_fila), alertador=alertador)
