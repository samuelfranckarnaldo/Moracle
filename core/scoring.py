"""
Scoring combinado por linha - em vez de 'bateu regex = achado',
soma sinais independentes (padrao de ataque, user-agent, rota sensivel)
numa pontuacao de risco 0-100.
"""
from core.useragent import extrair_user_agent, eh_user_agent_suspeito

PESO_PADRAO_ATAQUE = {
    "sql_injection": 40, "xss": 35, "path_traversal": 40,
    "command_injection": 30, "bruteforce": 25, "scanner": 20,
}

ROTAS_SENSIVEIS = ["/admin", "/api/admin", "/login", "/api/auth", "/backup", "/api/backup"]


def calcular_score_linha(finding, linha_bruta):
    score = PESO_PADRAO_ATAQUE.get(finding["attack_type"], 15)

    ua = extrair_user_agent(linha_bruta)
    if eh_user_agent_suspeito(ua):
        score += 25

    conteudo_lower = finding["content"].lower()
    if any(rota in conteudo_lower for rota in ROTAS_SENSIVEIS):
        score += 20

    score = min(100, score)

    if score >= 70:
        nivel = "critico"
    elif score >= 45:
        nivel = "alto"
    elif score >= 25:
        nivel = "medio"
    else:
        nivel = "baixo"

    return {"score": score, "nivel": nivel, "user_agent": ua}
