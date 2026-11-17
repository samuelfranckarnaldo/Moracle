"""
Correlação de eventos entre múltiplos logs — timeline única a partir
de fontes diferentes, com deduplicação e deteção de anomalia.
"""
import os
from collections import OrderedDict

from core.logs import LogAnalyzer
from core.anomaly import DetectorAnomalia


class TimelineCorrelacionada:
    def __init__(self, arquivos, janela_dedup_segundos=60):
        self.arquivos = arquivos
        self.analisadores = []
        self.eventos = []
        self.eventos_deduplicados = []
        self.janela_dedup_segundos = janela_dedup_segundos

    def carregar_e_analisar(self, filters=None):
        for arquivo in self.arquivos:
            analyzer = LogAnalyzer(arquivo)
            analyzer.load()
            findings = analyzer.analyze(filters)
            for finding in findings:
                evento = dict(finding)
                evento["fonte"] = os.path.basename(arquivo)
                self.eventos.append(evento)
            self.analisadores.append(analyzer)

        self.eventos.sort(key=lambda e: (e["timestamp"] == "unknown", e["timestamp"]))
        self.eventos_deduplicados = self._deduplicar(self.eventos)
        return self.eventos

    def _deduplicar(self, eventos):
        """Agrupa eventos idênticos (mesmo IP + tipo de ataque + conteúdo)
        que se repetem em sequência, mantendo uma contagem em vez de
        listar cada ocorrência — reduz ruído numa timeline longa."""
        agrupados = OrderedDict()
        for evento in eventos:
            chave = (evento["ip"], evento["attack_type"], evento["content"])
            if chave not in agrupados:
                agrupados[chave] = dict(evento)
                agrupados[chave]["ocorrencias"] = 1
                agrupados[chave]["fontes"] = {evento["fonte"]}
            else:
                agrupados[chave]["ocorrencias"] += 1
                agrupados[chave]["fontes"].add(evento["fonte"])
        resultado = list(agrupados.values())
        for item in resultado:
            item["fontes"] = sorted(item["fontes"])
        return resultado

    def detectar_anomalias(self, limiar_desvios=2.0):
        detector = DetectorAnomalia(limiar_desvios)
        return detector.analisar(self.eventos)

    def get_summary(self):
        ips = {}
        for evento in self.eventos:
            ips[evento["ip"]] = ips.get(evento["ip"], 0) + 1
        return {
            "total_eventos": len(self.eventos),
            "total_eventos_unicos": len(self.eventos_deduplicados),
            "total_fontes": len(self.arquivos),
            "ips_envolvidos": len(ips),
        }

    def to_markdown(self):
        resumo = self.get_summary()
        anomalias = self.detectar_anomalias()

        linhas = [
            "# Timeline Correlacionada",
            "",
            f"**Fontes:** {', '.join(os.path.basename(a) for a in self.arquivos)}",
            f"**Eventos totais:** {resumo['total_eventos']}",
            f"**Eventos únicos (deduplicados):** {resumo['total_eventos_unicos']}",
            f"**IPs envolvidos:** {resumo['ips_envolvidos']}",
            "",
        ]

        if anomalias["anomalias"]:
            linhas += [
                "## Anomalias Detectadas (volume fora do padrão)",
                "",
                f"*Baseline: média {anomalias['baseline_media']} eventos/hora, desvio {anomalias['baseline_desvio']}*",
                "",
                "| Hora | Eventos | Esperado (média) | Z-score |",
                "|---|---|---|---|",
            ]
            for a in anomalias["anomalias"]:
                linhas.append(f"| {a['hora']:02d}:00 | {a['eventos']} | {a['media_esperada']} | {a['z_score']} |")
            linhas.append("")

        linhas += [
            "## Eventos (ordem cronológica, deduplicados)",
            "",
            "| Timestamp | Fonte(s) | IP | Ataque | Ocorrências | Conteúdo |",
            "|---|---|---|---|---|---|",
        ]
        for evento in self.eventos_deduplicados:
            linhas.append(
                f"| {evento['timestamp']} | {', '.join(evento['fontes'])} | {evento['ip']} | "
                f"{evento['attack_name']} | {evento['ocorrencias']} | `{evento['content'][:80]}` |"
            )
        return "\n".join(linhas)
