"""
Combina resultados de múltiplas fontes de threat intel (VirusTotal,
AbuseIPDB, cache local de IOC) numa pontuação única de confiança,
em vez de tratar cada fonte isoladamente.
"""

PESOS = {
    "virustotal": 0.4,
    "abuseipdb": 0.4,
    "ioc_cache": 0.2,
}


def _score_virustotal(dados):
    if not dados or "error" in dados:
        return None
    try:
        stats = dados["data"]["attributes"]["last_analysis_stats"]
        maliciosos = stats.get("malicious", 0)
        total = sum(stats.values()) or 1
        return min(100, (maliciosos / total) * 100 * 3)  # amplifica sinal esparso
    except (KeyError, TypeError):
        return None


def _score_abuseipdb(dados):
    if not dados or "error" in dados:
        return None
    try:
        return float(dados["data"]["abuseConfidenceScore"])
    except (KeyError, TypeError):
        return None


def _score_ioc_cache(entrada_cache):
    if not entrada_cache:
        return None
    return 100.0 if entrada_cache.get("malicioso") else 0.0


def calcular_confianca(virustotal=None, abuseipdb=None, entrada_ioc_cache=None):
    """Retorna score 0-100 e o detalhamento por fonte. Fontes ausentes ou
    com erro são ignoradas — o peso é redistribuído entre as que responderam."""
    scores = {
        "virustotal": _score_virustotal(virustotal),
        "abuseipdb": _score_abuseipdb(abuseipdb),
        "ioc_cache": _score_ioc_cache(entrada_ioc_cache),
    }

    fontes_validas = {k: v for k, v in scores.items() if v is not None}
    if not fontes_validas:
        return {"score": None, "nivel": "desconhecido", "fontes": scores}

    peso_total = sum(PESOS[k] for k in fontes_validas)
    score_final = sum(scores[k] * PESOS[k] for k in fontes_validas) / peso_total

    if score_final >= 75:
        nivel = "critico"
    elif score_final >= 50:
        nivel = "alto"
    elif score_final >= 25:
        nivel = "medio"
    else:
        nivel = "baixo"

    return {"score": round(score_final, 1), "nivel": nivel, "fontes": scores}
