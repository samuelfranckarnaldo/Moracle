"""
Deteção de anomalia por baseline — sinaliza quando o volume de eventos
numa janela foge muito da média histórica, além de assinaturas fixas.
"""
import re
from collections import defaultdict
from statistics import mean, pstdev

HORA_RE = re.compile(r'(\d{2}):\d{2}:\d{2}')


def _extrair_hora(timestamp):
    if not timestamp or timestamp == "unknown":
        return None
    m = HORA_RE.search(timestamp)
    return int(m.group(1)) if m else None


class DetectorAnomalia:
    """Agrupa findings por hora do dia e calcula desvio da média."""

    def __init__(self, limiar_desvios=2.0):
        self.limiar_desvios = limiar_desvios

    def analisar(self, findings):
        contagem_por_hora = defaultdict(int)
        for f in findings:
            hora = _extrair_hora(f.get("timestamp"))
            if hora is not None:
                contagem_por_hora[hora] += 1

        if len(contagem_por_hora) < 2:
            return {"anomalias": [], "baseline_media": 0, "baseline_desvio": 0}

        valores = list(contagem_por_hora.values())
        media = mean(valores)
        desvio = pstdev(valores) or 1  # evita divisão por zero se tudo igual

        anomalias = []
        for hora, contagem in sorted(contagem_por_hora.items()):
            z_score = (contagem - media) / desvio
            if z_score >= self.limiar_desvios:
                anomalias.append({
                    "hora": hora,
                    "eventos": contagem,
                    "z_score": round(z_score, 2),
                    "media_esperada": round(media, 1),
                })

        return {
            "anomalias": anomalias,
            "baseline_media": round(media, 1),
            "baseline_desvio": round(desvio, 1),
        }
