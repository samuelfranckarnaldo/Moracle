"""
`config set` com classificacao por efeito (Passo 4b-2).

Decisoes aplicadas (Samuel): D3=B (permissao `config.security_write`), D4=B
(classificacao central por EFEITO REAL com allowlist explicita, sem esquema
declarativo completo). Este modulo decide tres coisas, nesta ordem:

  1. CLASSE da chave:
       LIVRE        efeito nulo para seguranca/decisoes de bloqueio/auditoria/
                    integridade de registos (apenas `idioma` e
                    `limite_suspeitos_padrao`, que so afeta relatorios
                    forenses). Nao exige credencial.
       PROTEGIDA    chave conhecida cujo efeito toca seguranca, bloqueio,
                    auditoria, retencao ou canal de alerta. Exige
                    `config.security_write`.
       DESCONHECIDA chave fora da allowlist. POLITICA EXPLICITA: nao e segura
                    por omissao; trata-se como PROTEGIDA (exige
                    `config.security_write`) e so aceita valor texto/inteiro
                    simples. Nunca se cria um objeto estruturado por esta via.
  2. VALIDACAO do valor (tipo e limites) da chave, antes de qualquer escrita.
     O valor persistido e SEMPRE o que foi validado: nada e "corrigido" em
     silencio (o `_validar` de core.config continua a existir so como rede
     de seguranca na leitura).
  3. CICLO DE AUDITORIA (Gate #6): evento `config.changed` com
     outcome="requested" gravado de forma duravel ANTES da escrita (falha
     fechada para chaves PROTEGIDAS/DESCONHECIDAS), e evento de resultado
     (`success`/`failure`) DEPOIS (melhor esforco: nunca reverte a escrita).
     Chaves LIVRES emitem os mesmos eventos, mas a falta de auditoria nao
     impede a alteracao (efeito nulo para seguranca).

A escrita e atomica e feita sob lock (core.config.definir). Este modulo nao
imprime nada: devolve um ResultadoConfigSet para a CLI mostrar.
"""
import math
import os
import re

from core import config

LIVRE = "livre"
PROTEGIDA = "protegida"
DESCONHECIDA = "desconhecida"

PERMISSAO = "config.security_write"

OK = "ok"
SEM_ALTERACAO = "sem_alteracao"
NEGADO = "negado"
INVALIDO = "invalido"
AUDIT_INDISPONIVEL = "audit_indisponivel"
FALHA = "falha"

_NULOS = ("", "null", "none")
_INT_ASCII = re.compile(r"[0-9]+")
_FLOAT_ASCII = re.compile(r"[0-9]+(\.[0-9]+)?")
_HTTP = re.compile(r"https?://[^\s/]+\S*", re.IGNORECASE)

MAX_HORAS = 24 * 365
MAX_CONTAGEM = 10_000_000
MAX_JANELA_S = 86_400


class ValorInvalido(ValueError):
    """Valor fora do tipo/limites da chave. A mensagem nunca inclui o valor."""


# ------------------------------------------------------------ validadores

def _inteiro(bruto, minimo, maximo, nome):
    if not isinstance(bruto, str) or not _INT_ASCII.fullmatch(bruto):
        raise ValorInvalido("%s: esperado inteiro entre %d e %d" % (nome, minimo, maximo))
    valor = int(bruto)
    if not minimo <= valor <= maximo:
        raise ValorInvalido("%s: esperado inteiro entre %d e %d" % (nome, minimo, maximo))
    return valor


def _inteiro_ou_nulo(minimo, maximo):
    def _v(bruto, nome):
        if isinstance(bruto, str) and bruto.strip().lower() in _NULOS:
            return None
        return _inteiro(bruto, minimo, maximo, nome)
    return _v


def _numero_positivo(maximo):
    def _v(bruto, nome):
        if not isinstance(bruto, str) or not _FLOAT_ASCII.fullmatch(bruto):
            raise ValorInvalido("%s: esperado numero positivo ate %s" % (nome, maximo))
        valor = float(bruto)
        if not (0 < valor <= maximo) or math.isnan(valor):
            raise ValorInvalido("%s: esperado numero positivo ate %s" % (nome, maximo))
        return int(valor) if valor.is_integer() else valor
    return _v


def _faixa(minimo, maximo):
    return lambda bruto, nome: _inteiro(bruto, minimo, maximo, nome)


def _idioma(bruto, nome):
    if bruto not in config.IDIOMAS_VALIDOS:
        raise ValorInvalido("%s: use um de %s" % (nome, sorted(config.IDIOMAS_VALIDOS)))
    return bruto


def _webhook(bruto, nome):
    if isinstance(bruto, str) and bruto.strip().lower() in _NULOS:
        return None
    if not isinstance(bruto, str) or not _HTTP.fullmatch(bruto.strip()) or "\x00" in bruto:
        raise ValorInvalido("%s: esperado URL http(s) ou null" % nome)
    return bruto.strip()


def _texto_simples(bruto, nome):
    if not isinstance(bruto, str) or not bruto.strip() or "\x00" in bruto:
        raise ValorInvalido("%s: texto nao vazio esperado" % nome)
    return bruto


def _diretorio_dentro_da_raiz(bruto, nome):
    """diretorio_saida: relativo, sem '..', resolvido dentro da raiz do
    projeto (cleanup apaga ficheiros dentro dele; fora da raiz seria
    apagar dados alheios)."""
    _texto_simples(bruto, nome)
    if os.path.isabs(bruto):
        raise ValorInvalido("%s: caminho relativo a raiz do projeto esperado" % nome)
    partes = os.path.normpath(bruto).split(os.sep)
    if ".." in partes or os.path.normpath(bruto) in (".", ""):
        raise ValorInvalido("%s: deve ficar dentro da raiz do projeto (sem '..' nem '.')" % nome)
    raiz = os.path.realpath(config.RAIZ_PROJETO)
    destino = os.path.realpath(os.path.join(raiz, bruto))
    if os.path.commonpath([raiz, destino]) != raiz or destino == raiz:
        raise ValorInvalido("%s: deve ficar dentro da raiz do projeto" % nome)
    return bruto


_PREFIXOS_PROIBIDOS = ("/dev/", "/proc/", "/sys/")


def _caminho_de_auditoria(bruto, nome):
    """Caminhos do audit: relativos (a raiz) ou absolutos (producao pode usar
    outro volume), mas nunca dispositivos/pseudo-ficheiros (ex.: /dev/null
    descartaria os eventos) nem '..'."""
    _texto_simples(bruto, nome)
    normal = os.path.normpath(bruto)
    if ".." in normal.split(os.sep):
        raise ValorInvalido("%s: '..' nao e permitido" % nome)
    absoluto = normal if os.path.isabs(normal) else os.path.join(config.RAIZ_PROJETO, normal)
    real = os.path.realpath(absoluto)
    if any((real + "/").startswith(p) or (normal + "/").startswith(p) for p in _PREFIXOS_PROIBIDOS):
        raise ValorInvalido("%s: dispositivos e pseudo-ficheiros nao sao permitidos" % nome)
    return bruto


# Allowlist: chave -> validador. LIVRES nao tocam seguranca; PROTEGIDAS sim.
CHAVES_LIVRES = {
    "idioma": _idioma,
    "limite_suspeitos_padrao": _faixa(1, 100_000),
}

CHAVES_PROTEGIDAS = {
    "diretorio_saida": _diretorio_dentro_da_raiz,
    "ioc_cache_validade_horas": _numero_positivo(MAX_HORAS),
    "bloqueio_expira_horas_padrao": _inteiro_ou_nulo(1, MAX_HORAS),
    "webhook_url": _webhook,
    "defesa.intervalo_padrao": _faixa(1, 3600),
    "defesa.limite_alerta_padrao": _faixa(1, 100_000),
    "rate_limit.global_max": _faixa(1, MAX_CONTAGEM),
    "rate_limit.global_janela_segundos": _faixa(1, MAX_JANELA_S),
    "rate_limit.por_ip_max": _faixa(1, MAX_CONTAGEM),
    "rate_limit.por_ip_janela_segundos": _faixa(1, MAX_JANELA_S),
    "rate_limit.por_rota_max": _faixa(1, MAX_CONTAGEM),
    "rate_limit.por_rota_janela_segundos": _faixa(1, MAX_JANELA_S),
    "auditoria.arquivo_eventos": _caminho_de_auditoria,
    "auditoria.diretorio_fila": _caminho_de_auditoria,
}

_NOME_VALIDO = re.compile(r"[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)?")


def classificar(chave):
    if chave in CHAVES_LIVRES:
        return LIVRE
    if chave in CHAVES_PROTEGIDAS:
        return PROTEGIDA
    return DESCONHECIDA


def _valor_desconhecido(bruto, nome):
    """Chave desconhecida: so texto simples ou inteiro ASCII (nunca
    estruturas). Inteiros so com digitos ASCII (corrige o int('²'))."""
    _texto_simples(bruto, nome)
    return int(bruto) if bruto.isascii() and bruto.isdigit() else bruto


def validar_valor(chave, bruto):
    """Devolve o valor tipado, ou levanta ValorInvalido."""
    validador = (CHAVES_LIVRES.get(chave) or CHAVES_PROTEGIDAS.get(chave)
                 or _valor_desconhecido)
    return validador(bruto, chave)


def validar_estrutura(chave, config_atual):
    """Recusa substituir um objeto por um escalar (`config set defesa x`) e
    escrever uma subchave sob um escalar (`idioma.x`). Levanta ValorInvalido."""
    if not isinstance(chave, str) or not _NOME_VALIDO.fullmatch(chave):
        raise ValorInvalido("nome de chave invalido (use nome ou raiz.sub)")
    if "." in chave:
        raiz, _ = chave.split(".", 1)
        existente = config_atual.get(raiz)
        if existente is not None and not isinstance(existente, dict):
            raise ValorInvalido("a chave '%s' nao e um objeto; nao aceita subchaves" % raiz)
        if existente is None and classificar(chave) == DESCONHECIDA:
            raise ValorInvalido("nao e possivel criar objetos novos por esta via")
    elif isinstance(config_atual.get(chave), dict):
        raise ValorInvalido("a chave '%s' e um objeto; defina uma subchave (%s.sub)" % (chave, chave))


def _valor_atual(config_atual, chave):
    if "." in chave:
        raiz, sub = chave.split(".", 1)
        no = config_atual.get(raiz)
        return no.get(sub) if isinstance(no, dict) else None
    return config_atual.get(chave)


def _auditoria_ficaria_valida(chave, valor):
    """auditoria.*: principal e fila nao podem coincidir (mesmo ficheiro ou
    mesmo diretorio), senao o proprio audit ficaria inutilizavel."""
    if not chave.startswith("auditoria."):
        return
    atual = dict(config.carregar().get("auditoria") or {})
    atual[chave.split(".", 1)[1]] = valor
    padrao = config.PADRAO["auditoria"]

    def _res(texto):
        return texto if os.path.isabs(texto) else os.path.join(config.RAIZ_PROJETO, texto)

    principal = os.path.realpath(_res(atual.get("arquivo_eventos", padrao["arquivo_eventos"])))
    fila = os.path.realpath(os.path.join(
        _res(atual.get("diretorio_fila", padrao["diretorio_fila"])), "fila_eventos.jsonl"))
    if principal == fila or os.path.dirname(principal) == os.path.dirname(fila):
        raise ValorInvalido("auditoria: principal e fila nao podem partilhar ficheiro nem diretorio")


# ------------------------------------------------------------- resultado

class ResultadoConfigSet:
    def __init__(self, estado, chave=None, valor=None, classe=None,
                 mensagem=None, perda_de_rastreabilidade=False, visivel=False):
        self.estado = estado
        self.chave = chave
        self.valor = valor
        self.classe = classe
        self.mensagem = mensagem
        self.perda_de_rastreabilidade = perda_de_rastreabilidade
        self.visivel = visivel   # True: o valor pode ser mostrado em claro

    @property
    def sucesso(self):
        return self.estado in (OK, SEM_ALTERACAO)

    def __repr__(self):
        return "ResultadoConfigSet(%r, %r)" % (self.estado, self.chave)


def executar_config_set(chave, bruto, ambiente=None):
    """Fluxo completo de `config set`. Nunca imprime; levanta so em erro de
    programacao. Ordem: classificar -> autorizar (se nao LIVRE) -> validar
    valor/estrutura -> evento 'requested' (duravel, falha fechada se nao
    LIVRE) -> escrita atomica -> evento de resultado."""
    from core import cli_authz, security_audit as sa, security_runtime as rt
    from core.audit import _valor_de_config_visivel

    classe = classificar(chave)
    api_key = None
    if classe != LIVRE:
        autorizacao = cli_authz.autorizar_operacao_cli(PERMISSAO, ambiente)
        if not autorizacao.autorizado:
            return ResultadoConfigSet(NEGADO, chave, classe=classe, mensagem=autorizacao.estado)
        api_key = autorizacao.api_key

    try:
        atual = config.carregar()
        validar_estrutura(chave, atual)
        valor = validar_valor(chave, bruto)
        _auditoria_ficaria_valida(chave, valor)
    except ValorInvalido as exc:
        return ResultadoConfigSet(INVALIDO, chave, classe=classe, mensagem=str(exc))
    except (TypeError, ValueError) as exc:  # config atual ilegivel/estranha
        return ResultadoConfigSet(INVALIDO, chave, classe=classe,
                                  mensagem="configuracao atual invalida (%s)" % type(exc).__name__)

    anterior = _valor_atual(atual, chave)
    ator = rt.ator_http({"api_key": api_key} if api_key is not None else {})
    visivel = _valor_de_config_visivel(chave)

    try:
        requested = sa.evento_config_changed(
            chave, anterior, valor, outcome="requested", actor=ator, origin="cli-local")
    except ValueError:
        return ResultadoConfigSet(INVALIDO, chave, classe=classe, mensagem="valor nao serializavel")
    if requested is None:
        return ResultadoConfigSet(SEM_ALTERACAO, chave, valor, classe, visivel=visivel)

    try:
        auditor = rt.obter_auditor()
    except Exception as exc:
        rt.alertar_infraestrutura(exc, "cli-config-set")
        auditor = None
    if auditor is not None:
        try:
            auditor.emitir(requested, "humano")
        except sa.AuditIndisponivel:
            if classe != LIVRE:
                return ResultadoConfigSet(AUDIT_INDISPONIVEL, chave, classe=classe)
    elif classe != LIVRE:
        return ResultadoConfigSet(AUDIT_INDISPONIVEL, chave, classe=classe)

    outcome = "success"
    try:
        config.definir(chave, valor)
    except Exception as exc:
        outcome = "failure"
        erro = type(exc).__name__
    perda = False
    if auditor is not None:
        try:
            resultado = sa.evento_config_changed(
                chave, anterior, valor, outcome=outcome, actor=ator, origin="cli-local",
                correlation_id=requested["event_id"])
            perda = auditor.emitir_resultado(resultado).perda_de_rastreabilidade
        except Exception:
            perda = True
    if outcome == "failure":
        return ResultadoConfigSet(FALHA, chave, classe=classe, mensagem=erro,
                                  perda_de_rastreabilidade=perda)
    return ResultadoConfigSet(OK, chave, valor, classe, perda_de_rastreabilidade=perda,
                              visivel=visivel)
