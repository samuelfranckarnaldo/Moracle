"""
Autorizacao local da CLI (Gate #4-A / Passo 4a).

Resolve a credencial EXPLICITA do operador e decide se ela pode executar
uma capacidade protegida, SEM duplicar nada: a autenticacao e a de
`core.auth.autenticar` (a mesma do middleware HTTP) e a autorizacao e a
de `core.authorization.exigir_permissao`. Este modulo so liga as duas
ao ambiente da CLI e traduz o resultado em estados que a CLI sabe
mostrar. Nao executa acoes, nao decide Policy e nao regista audit.

Decisoes aplicadas (Samuel, 2026-10-25):
  - D1 = B: autorizacao local no processo (sem passar por HTTP).
  - D2 = B: credencial explicita; a variavel de ambiente MORACLE_API_KEY
    e o unico mecanismo no 4a (sem flag em argv). A chave
    `legacy-admin-migration` / `.state/api_key.txt` NUNCA e escolhida
    silenciosamente, e esta CLI nao migra, nao cria nem escolhe
    credenciais: se nao ha chaves em keys.json, a operacao falha.
  - Falha fechada: qualquer erro ao ler o estado de identidade vira
    INDISPONIVEL (nunca autoriza); a mensagem nunca inclui o token nem
    o texto de excecoes.

`os_user` e `origin=cli-local` continuam sendo so contexto: nao sao
autorizacao. O caminho do estado e resolvido a cada uso contra
config.RAIZ_PROJETO (nunca como constante de modulo).
"""
import os

from core import auth, authorization, config
from core.identity import KeyStore, RoleStore

VARIAVEL_CREDENCIAL = "MORACLE_API_KEY"

AUTORIZADO = "autorizado"
CREDENCIAL_AUSENTE = "credencial_ausente"
NENHUMA_CHAVE = "nenhuma_chave"
CREDENCIAL_INVALIDA = "credencial_invalida"
SEM_PERMISSAO = "sem_permissao"
INDISPONIVEL = "indisponivel"

ESTADOS = (AUTORIZADO, CREDENCIAL_AUSENTE, NENHUMA_CHAVE,
           CREDENCIAL_INVALIDA, SEM_PERMISSAO, INDISPONIVEL)


class ResultadoAutorizacaoCli:
    """`api_key` so existe quando `estado == AUTORIZADO`. `erro_classe` so
    guarda a classe de uma excecao (INDISPONIVEL), nunca a mensagem."""

    def __init__(self, estado, api_key=None, erro_classe=None):
        self.estado = estado
        self.api_key = api_key
        self.erro_classe = erro_classe

    @property
    def autorizado(self):
        return self.estado == AUTORIZADO

    def __repr__(self):
        return "ResultadoAutorizacaoCli(%r)" % (self.estado,)


def _diretorio_estado():
    return os.path.join(config.RAIZ_PROJETO, ".state")


def credencial_do_ambiente(ambiente=None):
    """Token da variavel MORACLE_API_KEY, sem espacos nas pontas; ausente
    ou vazio/so espacos -> None. `ambiente` e injetavel para teste."""
    fonte = os.environ if ambiente is None else ambiente
    valor = fonte.get(VARIAVEL_CREDENCIAL)
    if not isinstance(valor, str):
        return None
    valor = valor.strip()
    return valor or None


def autenticar_cli(token):
    """Devolve (estado, api_key, erro_classe). Nunca levanta.

    NENHUMA_CHAVE so quando keys.json e legivel e esta vazio: a CLI nao
    migra a chave legada (isso e do `server start`) nem cria credencial.
    Qualquer falha ao ler/atualizar o estado (keys.json corrompido,
    .state sem permissao de escrita para o last_used_at...) e INDISPONIVEL.
    Chave desconhecida, revogada ou expirada partilham o mesmo estado
    (autenticar devolve None sem distincao)."""
    try:
        key_store = KeyStore(_diretorio_estado())
        if not key_store.load_all():
            return NENHUMA_CHAVE, None, None
        api_key = auth.autenticar(token, key_store)
    except Exception as exc:
        return INDISPONIVEL, None, type(exc).__name__
    if api_key is None:
        return CREDENCIAL_INVALIDA, None, None
    return AUTORIZADO, api_key, None


def autorizar_cli(api_key, permissao):
    """Devolve (estado, erro_classe) para uma api_key ja autenticada.
    Nunca levanta; role removido do RoleStore -> negado (fail-closed,
    no proprio exigir_permissao)."""
    try:
        permitido = authorization.exigir_permissao(
            api_key, RoleStore(_diretorio_estado()), permissao)
    except Exception as exc:
        return INDISPONIVEL, type(exc).__name__
    return (AUTORIZADO if permitido else SEM_PERMISSAO), None


def autorizar_operacao_cli(permissao, ambiente=None):
    """Fluxo completo: credencial do ambiente -> autenticacao ->
    autorizacao. Sem credencial nao toca o estado de identidade."""
    token = credencial_do_ambiente(ambiente)
    if token is None:
        return ResultadoAutorizacaoCli(CREDENCIAL_AUSENTE)

    estado, api_key, erro = autenticar_cli(token)
    if estado != AUTORIZADO:
        return ResultadoAutorizacaoCli(estado, erro_classe=erro)

    estado, erro = autorizar_cli(api_key, permissao)
    if estado != AUTORIZADO:
        return ResultadoAutorizacaoCli(estado, erro_classe=erro)
    return ResultadoAutorizacaoCli(AUTORIZADO, api_key=api_key)
