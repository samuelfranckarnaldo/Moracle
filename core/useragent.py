"""
Análise de user-agent — sinaliza ferramentas de scan/ataque conhecidas
e ausência de user-agent (comum em scripts automatizados).
"""
import re

UA_SUSPEITOS = [
    r"sqlmap", r"nikto", r"nmap", r"masscan", r"nuclei",
    r"gobuster", r"dirbuster", r"burp", r"zap", r"acunetix",
    r"curl/\d", r"python-urllib", r"python-requests", r"go-http-client",
    r"xeera",  # detectado no seu próprio ambiente de teste
]

UA_RE = re.compile(r'"([^"]*)"\s*$')
SUSPEITO_RE = re.compile("|".join(UA_SUSPEITOS), re.I)


def extrair_user_agent(linha):
    m = UA_RE.search(linha.strip())
    return m.group(1) if m else None


def eh_user_agent_suspeito(user_agent):
    if not user_agent or user_agent == "-":
        return True  # ausência de UA é sinal fraco, mas conta
    return bool(SUSPEITO_RE.search(user_agent))
