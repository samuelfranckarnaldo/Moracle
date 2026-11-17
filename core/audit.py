"""
Log de auditoria do próprio Moracle — quem rodou qual comando, quando.
Auditar o auditor: toda execução da CLI grava uma linha aqui antes de
qualquer outra coisa acontecer. Valores sensíveis são gravados como '***'
(nunca o valor).

A redação combina três regras, aplicadas só à cópia que vai para o log
(os argumentos recebidos nunca são alterados):
  1. piso por NOME de argumento (_CAMPO_SECRETO);
  2. tabela explícita por (grupo, comando) em ARGUMENTOS_SENSIVEIS, para
     argumentos cujo nome não denuncia o segredo (ex.: --virustotal);
  3. regra própria do `config set`: a sensibilidade do VALOR depende da
     CHAVE DE CONFIG alterada, não do nome do argumento.
A redação roda antes do comando e nunca levanta exceção: na dúvida,
privilegia não expor o valor.
"""
import json
import os
import re
import getpass
from datetime import datetime, timezone

from core import config

AUDIT_FILE = os.path.join(config.RAIZ_PROJETO, ".state", "audit.log")

_CAMPO_SECRETO = re.compile(
    r"(key|secret|token|passw|senha|credential|authorization|bearer|chave|segredo)", re.IGNORECASE
)

# Argumentos sensíveis por (grupo, comando), pelo NOME DE DESTINO do argparse
# (as chaves de vars(args)). Complementa o piso por nome.
ARGUMENTOS_SENSIVEIS = {
    ("forensic", "whois"): frozenset({"virustotal", "abuseipdb"}),
}

# `config set`: chaves de config conhecidas (as de core.config.PADRAO).
# Só o valor de uma chave de CHAVES_CONFIG_NAO_SENSIVEIS é gravado; qualquer
# outra (sensível, desconhecida, ausente ou de tipo inesperado) tem o valor
# redigido. tests/test_audit_redacao_por_comando.py garante que toda chave de
# PADRAO esteja classificada em exatamente uma das duas listas.
CHAVES_CONFIG_NAO_SENSIVEIS = frozenset({
    "idioma",
    "diretorio_saida",
    "limite_suspeitos_padrao",
    "defesa.intervalo_padrao",
    "defesa.limite_alerta_padrao",
    "ioc_cache_validade_horas",
    "bloqueio_expira_horas_padrao",
    "rate_limit.global_max",
    "rate_limit.global_janela_segundos",
    "rate_limit.por_ip_max",
    "rate_limit.por_ip_janela_segundos",
    "rate_limit.por_rota_max",
    "rate_limit.por_rota_janela_segundos",
    "auditoria.arquivo_eventos",
    "auditoria.diretorio_fila",
})
CHAVES_CONFIG_SENSIVEIS = frozenset({"webhook_url"})

_NOME_DE_CONFIG = re.compile(r"[A-Za-z0-9_.-]{1,100}")


def _mascarar(valor):
    return None if valor is None else "***"


def _redigir(valor, nome=None):
    if nome is not None and _CAMPO_SECRETO.search(str(nome)):
        return None if valor is None else "***"
    if isinstance(valor, dict):
        return {k: _redigir(v, k) for k, v in valor.items()}
    if isinstance(valor, (list, tuple)):
        return [_redigir(v) for v in valor]
    return valor


def _nome_de_config(valor):
    """Nome da chave de config: em claro quando tem forma de identificador;
    qualquer outra forma (URL, espaços, '=', vazio, tipo inesperado) pode ser
    um segredo colado no lugar errado e é mascarada."""
    if valor is None:
        return None
    if isinstance(valor, str) and _NOME_DE_CONFIG.fullmatch(valor):
        return valor
    return "***"


def _valor_de_config_visivel(chave):
    return (
        isinstance(chave, str)
        and chave in CHAVES_CONFIG_NAO_SENSIVEIS
        and chave not in CHAVES_CONFIG_SENSIVEIS
        and not _CAMPO_SECRETO.search(chave)
    )


def _redigir_argumentos(grupo, comando, argumentos):
    """Redação por comando. Nunca levanta exceção e nunca altera `argumentos`."""
    try:
        if not isinstance(argumentos, dict):
            return _redigir(argumentos)
        sensiveis = ARGUMENTOS_SENSIVEIS.get((grupo, comando), frozenset())
        eh_config_set = (grupo, comando) == ("config", "set")
        chave_config = argumentos.get("key") if eh_config_set else None
        saida = {}
        for nome, valor in argumentos.items():
            if nome in sensiveis:
                saida[nome] = _mascarar(valor)
            elif eh_config_set and nome == "key":
                saida[nome] = _nome_de_config(valor)
            elif eh_config_set and nome == "value":
                if _valor_de_config_visivel(chave_config):
                    saida[nome] = _redigir(valor)
                else:
                    saida[nome] = _mascarar(valor)
            else:
                saida[nome] = _redigir(valor, nome)
        return saida
    except Exception:
        return {"_redacao_falhou": True}


def registrar(grupo, comando, argumentos):
    os.makedirs(os.path.dirname(AUDIT_FILE), exist_ok=True)
    try:
        usuario = getpass.getuser()
    except Exception:
        usuario = "desconhecido"
    entrada = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "usuario": usuario,
        "grupo": grupo,
        "comando": comando,
        "argumentos": _redigir_argumentos(grupo, comando, argumentos),
    }
    fd = os.open(AUDIT_FILE, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    with os.fdopen(fd, "a") as f:
        f.write(json.dumps(entrada, default=str) + "\n")
    try:
        os.chmod(AUDIT_FILE, 0o600)
    except OSError:
        pass


def ler_recentes(limite=20):
    if not os.path.exists(AUDIT_FILE):
        return []
    with open(AUDIT_FILE) as f:
        linhas = f.readlines()
    resultado = []
    for linha in linhas[-limite:]:
        try:
            resultado.append(json.loads(linha))
        except ValueError:
            continue
    return resultado
