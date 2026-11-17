"""
Agrupamento de findings por IP+user-agent numa 'sessao de ataque' -
em vez de tratar cada linha isoladamente, junta o comportamento de
uma mesma origem ao longo do tempo.
"""
from collections import defaultdict


def agrupar_sessoes(findings):
    grupos = defaultdict(list)
    for f in findings:
        chave = (f["ip"], f.get("user_agent") or "desconhecido")
        grupos[chave].append(f)

    sessoes = []
    for (ip, user_agent), itens in grupos.items():
        tipos = defaultdict(int)
        for item in itens:
            tipos[item["attack_type"]] += 1

        score_medio = sum(i.get("risco_score", 0) for i in itens) / len(itens)
        score_maximo = max((i.get("risco_score", 0) for i in itens), default=0)

        sessoes.append({
            "ip": ip,
            "user_agent": user_agent,
            "total_eventos": len(itens),
            "tipos_ataque": dict(tipos),
            "score_medio": round(score_medio, 1),
            "score_maximo": score_maximo,
            "primeiro_timestamp": itens[0]["timestamp"],
            "ultimo_timestamp": itens[-1]["timestamp"],
        })

    sessoes.sort(key=lambda s: -s["score_maximo"])
    return sessoes
