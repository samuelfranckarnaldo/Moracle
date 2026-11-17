"""
Parsers de formato de log — texto plano (Apache/Nginx-like), JSON lines,
e syslog. Cada parser normaliza para uma lista de linhas de texto que o
LogAnalyzer já sabe processar, preservando o padrão de deteção por regex.
"""
import json
import re

SYSLOG_RE = re.compile(
    r'^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+(?P<processo>\S+?):\s+(?P<mensagem>.*)$'
)


def detectar_formato(primeira_linha_nao_vazia):
    linha = primeira_linha_nao_vazia.strip()
    if not linha:
        return "plain"
    if linha.startswith("{"):
        try:
            json.loads(linha)
            return "json"
        except (json.JSONDecodeError, ValueError):
            pass
    if SYSLOG_RE.match(linha):
        return "syslog"
    return "plain"


def normalizar_linhas(linhas, formato):
    """Retorna lista de strings 'achatadas' prontas para os PATTERNS regex,
    independente do formato original."""
    if formato == "plain":
        return linhas

    normalizadas = []
    for linha in linhas:
        linha = linha.strip()
        if not linha:
            continue
        if formato == "json":
            try:
                dados = json.loads(linha)
                normalizadas.append(" ".join(str(v) for v in dados.values()))
            except (json.JSONDecodeError, ValueError):
                normalizadas.append(linha)
        elif formato == "syslog":
            m = SYSLOG_RE.match(linha)
            if m:
                normalizadas.append(f"{m.group('timestamp')} {m.group('host')} {m.group('mensagem')}")
            else:
                normalizadas.append(linha)
        else:
            normalizadas.append(linha)
    return normalizadas
