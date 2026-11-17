"""
Análise de logs de servidor.
Deteta padrões de ataque e identifica IPs suspeitos.
"""

import re
import os
from datetime import datetime
from collections import Counter

from core.custody import coletar_evidencia
from core.log_formats import detectar_formato, normalizar_linhas
from core.whitelist import esta_na_whitelist
from core.scoring import calcular_score_linha
from core.freshness import esta_em_escrita_ativa

class LogAnalyzer:
    """Analisa logs e deteta ataques."""

    PATTERNS = {
        "sql_injection": re.compile(r"(union|select|insert|drop|alter|--|' OR '1'='1)", re.I),
        "xss": re.compile(r"(<script|onerror|alert|javascript:|onload)", re.I),
        "path_traversal": re.compile(r"(\.\./|/etc/passwd|/proc/|/boot.ini)", re.I),
        "command_injection": re.compile(r"(;\s*(whoami|id|uname|cat|ls|rm|wget|curl)\b|\|\s*(whoami|id|uname)\b|`(whoami|id|uname|cat)`|\$\((whoami|id|uname|cat)\)|&&\s*(whoami|id)\b)", re.I),
        "bruteforce": re.compile(r"(POST.*login|failed password|401|403)", re.I),
        "scanner": re.compile(r"(/wp-admin|/admin|/phpmyadmin|/cpanel|/webmail)", re.I),
    }

    ATTACK_NAMES = {
        "sql_injection": "SQL Injection",
        "xss": "Cross-Site Scripting (XSS)",
        "path_traversal": "Path Traversal",
        "command_injection": "Command Injection",
        "bruteforce": "Brute Force",
        "scanner": "Scanner/Reconhecimento",
    }

    # Nível de confiança por padrão: alguns são quase inequívocos quando
    # batem (path_traversal, sql_injection), outros geram mais falso
    # positivo por natureza (command_injection casa com texto comum).
    CONFIANCA_PADRAO = {
        "sql_injection": "alta",
        "xss": "alta",
        "path_traversal": "alta",
        "command_injection": "media",
        "bruteforce": "media",
        "scanner": "alta",
    }

    def __init__(self, log_file):
        self.log_file = os.path.expanduser(log_file)
        self.lines = []
        self.findings = []
        self.suspect_ips = Counter()
        self.custodia = None
        self.formato_detectado = None
        self.aviso_arquivo_ativo = False

    def load(self, avisar_se_ativo=True):
        """Carrega o ficheiro de logs. Preserva a evidência antes de tocar nela."""
        if not os.path.exists(self.log_file):
            raise FileNotFoundError(f"Log não encontrado: {self.log_file}")

        if avisar_se_ativo and esta_em_escrita_ativa(self.log_file):
            self.aviso_arquivo_ativo = True
        else:
            self.aviso_arquivo_ativo = False

        # Cadeia de custódia: hash + registro ANTES de qualquer leitura de análise
        self.custodia = coletar_evidencia(
            self.log_file,
            coletor="moracle",
            motivo="análise de log iniciada"
        )

        with open(self.log_file, 'r', encoding='utf-8', errors='ignore') as f:
            linhas_brutas = f.readlines()

        primeira_nao_vazia = next((l for l in linhas_brutas if l.strip()), "")
        self.formato_detectado = detectar_formato(primeira_nao_vazia)
        self.lines = normalizar_linhas(linhas_brutas, self.formato_detectado)
        return self

    def verificar_integridade(self):
        """Confirma que o log não foi alterado desde a coleta original."""
        if not self.custodia:
            raise RuntimeError("Nenhuma evidência coletada ainda — chame load() primeiro.")
        return self.custodia.verificar_integridade()

    # Ordem de prioridade quando uma linha bate em mais de um padrao —
    # o mais especifico/grave vence, evita contar a mesma linha 2x
    # com tipos diferentes.
    PRIORIDADE = [
        "sql_injection", "xss", "path_traversal",
        "command_injection", "bruteforce", "scanner",
    ]

    def analyze(self, filters=None):
        """Analisa os logs em busca de padrões de ataque.
        Cada linha gera no máximo um achado (o padrão de maior prioridade
        que bater), evitando dupla-contagem quando vários regex casam
        com o mesmo conteúdo."""
        self.findings = []
        self.suspect_ips = Counter()

        for line_num, line in enumerate(self.lines, 1):
            line_lower = line.lower()

            ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', line)
            ip = ip_match.group(1) if ip_match else "unknown"

            if esta_na_whitelist(line):
                continue

            padrao_escolhido = None
            for pattern_name in self.PRIORIDADE:
                pattern = self.PATTERNS[pattern_name]
                if pattern.search(line_lower):
                    if filters and pattern_name not in filters:
                        continue
                    padrao_escolhido = pattern_name
                    break

            if padrao_escolhido:
                achado = {
                    "line": line_num,
                    "ip": ip,
                    "attack_type": padrao_escolhido,
                    "attack_name": self.ATTACK_NAMES.get(padrao_escolhido, padrao_escolhido),
                    "content": line.strip()[:200],
                    "timestamp": self._extract_timestamp(line),
                    "confianca": self.CONFIANCA_PADRAO.get(padrao_escolhido, "media")
                }
                risco = calcular_score_linha(achado, line)
                achado["risco_score"] = risco["score"]
                achado["risco_nivel"] = risco["nivel"]
                achado["user_agent"] = risco["user_agent"]
                self.findings.append(achado)
                self.suspect_ips[ip] += 1

        return self.findings

    def _extract_timestamp(self, line):
        """Tenta extrair timestamp da linha."""
        patterns = [
            r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})',
            r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})',
            r'(\w{3} \d{2} \d{2}:\d{2}:\d{2})',
        ]
        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                return match.group(1)
        return "unknown"

    def get_suspects(self, min_hits=3):
        """Retorna IPs suspeitos com contagem."""
        return {ip: count for ip, count in self.suspect_ips.items() if count >= min_hits}

    def get_summary(self):
        """Resumo da análise."""
        return {
            "total_lines": len(self.lines),
            "total_findings": len(self.findings),
            "suspect_ips": len(self.get_suspects()),
            "attack_types": Counter([f["attack_name"] for f in self.findings])
        }

    def to_markdown(self):
        """Gera relatório em Markdown, incluindo cadeia de custódia."""
        summary = self.get_summary()
        lines = [
            "# Relatório de Análise de Logs",
            "",
            f"**Ficheiro:** {self.log_file}",
            f"**Total de linhas:** {summary['total_lines']}",
            f"**Total de achados:** {summary['total_findings']}",
            f"**IPs suspeitos:** {summary['suspect_ips']}",
            "",
        ]

        if self.custodia:
            lines += [
                "## Cadeia de Custódia",
                "",
                f"- **Hash SHA-256:** `{self.custodia.hash_sha256}`",
                f"- **Coletado em:** {self.custodia.timestamp_coleta}",
                f"- **Coletor:** {self.custodia.coletor}",
                f"- **Tamanho:** {self.custodia.tamanho_bytes} bytes",
                "",
            ]

        lines += [
            "## Distribuição de Ataques",
            "",
            "| Tipo | Quantidade |",
            "|------|------------|",
        ]

        for attack_type, count in summary["attack_types"].most_common():
            lines.append(f"| {attack_type} | {count} |")

        lines.append("")
        lines.append("## IPs Suspeitos")
        lines.append("")
        lines.append("| IP | Número de tentativas |")
        lines.append("|----|----------------------|")

        for ip, count in sorted(self.get_suspects().items(), key=lambda x: -x[1]):
            lines.append(f"| {ip} | {count} |")

        lines.append("")
        lines.append("## Detalhes dos Achados")
        lines.append("")
        for finding in self.findings[:10]:
            lines.append(f"### Linha {finding['line']}")
            lines.append(f"- **IP:** {finding['ip']}")
            lines.append(f"- **Ataque:** {finding['attack_name']}")
            lines.append(f"- **Timestamp:** {finding['timestamp']}")
            lines.append(f"- **Conteúdo:** `{finding['content']}`")
            lines.append("")

        return "\n".join(lines)
