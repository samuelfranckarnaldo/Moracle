"""
Internacionalização — pt/en. Idioma controlado por config.json (idioma).
"""
from core import config

TRADUCOES = {
    "pt": {
        "analisando_logs": "A analisar logs: {file}",
        "resumo_titulo": "RESUMO DA ANÁLISE",
        "total_linhas": "Total de linhas",
        "achados": "Achados",
        "ips_suspeitos": "IPs suspeitos",
        "distribuicao_ataques": "Distribuição de ataques",
        "hash_custodia": "Hash SHA-256 (custódia)",
        "relatorio_guardado": "Relatório guardado em {path}",
        "dados_exportados": "Dados exportados para {path}",
        "verificando_integridade": "Verificando integridade de: {path}",
        "integridade_confirmada": "Integridade confirmada — hash bate: {hash}",
        "integridade_falhou": "ALERTA: o hash não confere — a evidência pode ter sido alterada desde a coleta!",
        "custodia_nao_encontrada": "Nenhum registro de custódia encontrado para {file}",
        "estado_agente_titulo": "ESTADO DO AGENTE — DEFESA",
        "ativo": "Ativo", "sim": "sim", "nao": "não",
        "iniciado_em": "Iniciado em", "parado_em": "Parado em",
        "ips_blocklist": "IPs na blocklist", "blocklist_titulo": "Blocklist",
        "bloqueado_adicionado": "{ip} adicionado à blocklist — motivo: {motivo}",
        "monitorando": "Monitorando {file} (Ctrl+C para parar)",
        "monitoramento_interrompido": "Monitoramento interrompido.",
        "alerta_ataque": "{tipo} de {ip} — {conteudo}",
        "bloqueio_automatico": "{ip} adicionado à blocklist ({tentativas} tentativas)",
        "bloqueio_ioc": "{ip} bloqueado imediatamente — já conhecido como malicioso (cache IOC)",
        "erro": "Erro: {msg}",
        "timeline_titulo": "LINHA DO TEMPO CORRELACIONADA",
        "fontes": "Fontes", "eventos_totais": "Eventos totais", "ips_envolvidos": "IPs envolvidos",
        "config_titulo": "CONFIGURAÇÃO ATUAL",
        "config_definido": "{chave} definido como {valor}",
        "ioc_cache_hit": "IP {ip} já verificado há {horas}h (cache local) — não consultado de novo",
    },
    "en": {
        "analisando_logs": "Analyzing logs: {file}",
        "resumo_titulo": "ANALYSIS SUMMARY",
        "total_linhas": "Total lines",
        "achados": "Findings",
        "ips_suspeitos": "Suspect IPs",
        "distribuicao_ataques": "Attack distribution",
        "hash_custodia": "SHA-256 hash (custody)",
        "relatorio_guardado": "Report saved to {path}",
        "dados_exportados": "Data exported to {path}",
        "verificando_integridade": "Verifying integrity of: {path}",
        "integridade_confirmada": "Integrity confirmed — hash matches: {hash}",
        "integridade_falhou": "ALERT: hash mismatch — evidence may have been tampered with since collection!",
        "custodia_nao_encontrada": "No custody record found for {file}",
        "estado_agente_titulo": "AGENT STATUS — DEFENSE",
        "ativo": "Active", "sim": "yes", "nao": "no",
        "iniciado_em": "Started at", "parado_em": "Stopped at",
        "ips_blocklist": "IPs in blocklist", "blocklist_titulo": "Blocklist",
        "bloqueado_adicionado": "{ip} added to blocklist — reason: {motivo}",
        "monitorando": "Monitoring {file} (Ctrl+C to stop)",
        "monitoramento_interrompido": "Monitoring stopped.",
        "alerta_ataque": "{tipo} from {ip} — {conteudo}",
        "bloqueio_automatico": "{ip} added to blocklist ({tentativas} attempts)",
        "bloqueio_ioc": "{ip} blocked immediately — already known malicious (IOC cache)",
        "erro": "Error: {msg}",
        "timeline_titulo": "CORRELATED TIMELINE",
        "fontes": "Sources", "eventos_totais": "Total events", "ips_envolvidos": "IPs involved",
        "config_titulo": "CURRENT CONFIGURATION",
        "config_definido": "{chave} set to {valor}",
        "ioc_cache_hit": "IP {ip} already checked {horas}h ago (local cache) — not re-queried",
    }
}

def t(_chave_msg, **kwargs):
    dicionario = TRADUCOES.get(config.idioma(), TRADUCOES["pt"])
    texto = dicionario.get(_chave_msg, TRADUCOES["pt"].get(_chave_msg, _chave_msg))
    return texto.format(**kwargs) if kwargs else texto
