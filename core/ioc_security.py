"""
Escrita no cache de IOC com autorizacao e auditoria (Passo 4b-3).

Decisoes aplicadas (Samuel): D3=B (permissao `ioc.write`), S1=ii.

  - `forensic ioc-import`: escreve sempre; exige `ioc.write` (credencial
    explicita MORACLE_API_KEY, como no 4a). Le e valida o ficheiro ANTES de
    qualquer escrita; emite o evento `ioc.imported` com outcome="requested"
    de forma duravel ANTES de gravar (falha fechada: sem audit nao grava) e
    um evento de resultado DEPOIS (melhor esforco, nunca reverte).
  - `forensic whois <ip>`: a consulta e a impressao sao sempre de leitura. A
    gravacao no cache so acontece com `ioc.write` (S1=ii); sem ela (sem
    credencial, invalida, sem a permissao) continua somente leitura, sem
    erro. Com ela, a gravacao segue o mesmo ciclo de auditoria.
  - Fusao de proveniencia: uma gravacao NUNCA rebaixa malicioso=True para
    False e NUNCA perde nem substitui a `fonte` ja registada
    (ioc_cache.mesclar_proveniencia, aplicada sob o lock do cache).

Nada aqui imprime: devolve um ResultadoIoc para a CLI mostrar. Nenhuma
mensagem inclui a credencial nem texto de excecoes.
"""
import os
import re

from core import ioc_cache, ioc_feed

PERMISSAO = "ioc.write"

OK = "ok"
NEGADO = "negado"
SOMENTE_LEITURA = "somente_leitura"
INVALIDO = "invalido"
FICHEIRO_ILEGIVEL = "ficheiro_ilegivel"
AUDIT_INDISPONIVEL = "audit_indisponivel"
FALHA = "falha"

_FONTE_VALIDA = re.compile(r"[^\x00-\x1f\x7f]{1,100}")


class ResultadoIoc:
    def __init__(self, estado, importados=0, ignorados=0, mensagem=None,
                 perda_de_rastreabilidade=False):
        self.estado = estado
        self.importados = importados
        self.ignorados = ignorados
        self.mensagem = mensagem          # estado de autorizacao ou classe de erro
        self.perda_de_rastreabilidade = perda_de_rastreabilidade

    @property
    def sucesso(self):
        return self.estado == OK

    def __repr__(self):
        return "ResultadoIoc(%r)" % (self.estado,)


def _ciclo(payload_pedido, gravar, ator):
    """Ciclo comum (core.audit_ciclo) para o evento `ioc.imported`. Devolve
    (estado, dados, perda, classe_erro) com os estados deste modulo."""
    from core import audit_ciclo as ac

    r = ac.ciclo_auditado("ioc.imported", payload_pedido, gravar, ator, "cli-local")
    if r.estado == ac.AUDIT_INDISPONIVEL:
        return AUDIT_INDISPONIVEL, None, False, None
    if r.estado == ac.FALHA:
        return FALHA, None, r.perda_de_rastreabilidade, r.erro
    return OK, r.dados, r.perda_de_rastreabilidade, None


def executar_ioc_import(caminho, fonte, ambiente=None):
    from core import cli_authz, security_runtime as rt

    autorizacao = cli_authz.autorizar_operacao_cli(PERMISSAO, ambiente)
    if not autorizacao.autorizado:
        return ResultadoIoc(NEGADO, mensagem=autorizacao.estado)

    if not isinstance(fonte, str) or not _FONTE_VALIDA.fullmatch(fonte):
        return ResultadoIoc(INVALIDO, mensagem="fonte invalida (1 a 100 caracteres, sem controlo)")

    try:
        candidatos, ignorados = ioc_feed.ler_candidatos(caminho, fonte)
    except Exception as exc:     # ficheiro inexistente/ilegivel: nada foi escrito
        return ResultadoIoc(FICHEIRO_ILEGIVEL, mensagem=type(exc).__name__)

    if not candidatos:           # lote vazio: sem E/S, sem evento (como antes)
        return ResultadoIoc(OK, importados=0, ignorados=ignorados)

    ator = rt.ator_http({"api_key": autorizacao.api_key})
    pedido = {"command": "ioc-import", "file": os.path.basename(str(caminho)),
              "source": fonte, "valid_ips": len(candidatos), "ignored": ignorados}
    estado, dados, perda, erro = _ciclo(
        pedido,
        lambda: {"imported": ioc_cache.guardar_lote(
            candidatos, mesclar=ioc_cache.mesclar_proveniencia)},
        ator)
    if estado == OK:
        return ResultadoIoc(OK, importados=dados["imported"], ignorados=ignorados,
                            perda_de_rastreabilidade=perda)
    return ResultadoIoc(estado, ignorados=ignorados, mensagem=erro,
                        perda_de_rastreabilidade=perda)


def registrar_whois(ip, resultado, malicioso, ambiente=None):
    """Grava o resultado de um whois SO com `ioc.write` (S1=ii)."""
    from core import cli_authz, security_runtime as rt

    autorizacao = cli_authz.autorizar_operacao_cli(PERMISSAO, ambiente)
    if not autorizacao.autorizado:
        return ResultadoIoc(SOMENTE_LEITURA, mensagem=autorizacao.estado)

    ator = rt.ator_http({"api_key": autorizacao.api_key})
    pedido = {"command": "whois", "ip": ip, "malicious": bool(malicioso)}
    estado, dados, perda, erro = _ciclo(
        pedido,
        lambda: {"imported": ioc_cache.guardar_lote(
            [(ip, resultado, bool(malicioso))], mesclar=ioc_cache.mesclar_proveniencia)},
        ator)
    if estado == OK:
        return ResultadoIoc(OK, importados=dados["imported"], perda_de_rastreabilidade=perda)
    return ResultadoIoc(estado, mensagem=erro, perda_de_rastreabilidade=perda)
