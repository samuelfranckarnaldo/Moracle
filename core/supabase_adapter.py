"""
Adaptador para puxar eventos de security_events do Supabase e
convertê-los para o mesmo formato de 'finding' usado pelo LogAnalyzer,
permitindo correlacionar com forensic timeline.

Requer SUPABASE_URL e SUPABASE_KEY nas variaveis de ambiente (o
projeto ja usa dotenv, entao um .env com essas chaves e suficiente).
"""
import os
from datetime import datetime


def _obter_cliente():
    try:
        from supabase import create_client
    except ImportError:
        raise RuntimeError("Pacote 'supabase' nao instalado. pip install supabase --break-system-packages")

    url = os.environ.get("SUPABASE_URL")
    key = os.environ.get("SUPABASE_KEY") or os.environ.get("SUPABASE_SERVICE_KEY")
    if not url or not key:
        raise RuntimeError("SUPABASE_URL / SUPABASE_KEY nao definidos no ambiente")

    return create_client(url, key)


def buscar_eventos(limite=500, desde_iso=None):
    """Busca eventos de security_events e normaliza para o formato de
    'finding' do Moracle, para poder entrar numa TimelineCorrelacionada."""
    cliente = _obter_cliente()
    query = cliente.table("security_events").select("*").order("created_at", desc=True).limit(limite)
    if desde_iso:
        query = query.gte("created_at", desde_iso)

    resposta = query.execute()
    eventos = resposta.data or []

    findings = []
    for e in eventos:
        findings.append({
            "line": 0,
            "ip": e.get("ip") or "unknown",
            "attack_type": e.get("event_type", "security_event"),
            "attack_name": e.get("event_type", "Security Event"),
            "content": f"{e.get('detail', '')} — {e.get('path', '')}",
            "timestamp": e.get("created_at", "unknown"),
            "confianca": "alta",
            "fonte": "supabase:security_events",
        })
    return findings
