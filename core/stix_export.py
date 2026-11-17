"""
Exportacao de achados em formato STIX 2.1 simplificado - padrao
usado para troca de threat intel entre ferramentas (SIEM, TIP, etc).
Gera 'indicator' objects a partir dos findings do Moracle.
"""
import json
import uuid
from datetime import datetime, timezone


def _novo_id(tipo):
    return f"{tipo}--{uuid.uuid4()}"


def exportar_stix(findings, titulo="Moracle Export"):
    agora = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    bundle = {
        "type": "bundle",
        "id": _novo_id("bundle"),
        "objects": []
    }

    ips_ja_processados = set()
    for f in findings:
        ip = f.get("ip")
        if not ip or ip == "unknown" or ip in ips_ja_processados:
            continue
        ips_ja_processados.add(ip)

        indicador = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": _novo_id("indicator"),
            "created": agora,
            "modified": agora,
            "name": f"Suspicious activity from {ip}",
            "description": f"Detected {f.get('attack_name', 'unknown')} pattern by Moracle",
            "pattern": f"[ipv4-addr:value = '{ip}']",
            "pattern_type": "stix",
            "valid_from": agora,
            "labels": [f.get("attack_type", "unknown")],
        }
        bundle["objects"].append(indicador)

    return bundle


def exportar_misp(findings):
    """Formato simplificado compativel com import manual no MISP
    (lista de atributos tipo 'ip-dst' com categoria/comentario)."""
    ips_ja_processados = set()
    atributos = []

    for f in findings:
        ip = f.get("ip")
        if not ip or ip == "unknown" or ip in ips_ja_processados:
            continue
        ips_ja_processados.add(ip)

        atributos.append({
            "type": "ip-dst",
            "category": "Network activity",
            "value": ip,
            "comment": f"Moracle: {f.get('attack_name', 'unknown')}",
            "to_ids": True,
        })

    return {"Event": {"info": "Moracle export", "Attribute": atributos}}
