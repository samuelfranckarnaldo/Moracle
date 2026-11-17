"""Validação de entrada da camada de defesa: IP, prazo de expiração e motivo."""
import ipaddress
import math

EXPIRA_MAX_HORAS = 24 * 365


def normalizar_ip(valor):
    """Devolve o IP em forma canônica (str) ou levanta ValueError."""
    if not isinstance(valor, str):
        raise ValueError("ip deve ser texto")
    if not valor or valor != valor.strip() or "%" in valor:
        raise ValueError("ip inválido")
    try:
        ip = ipaddress.ip_address(valor)
    except ValueError:
        raise ValueError("ip inválido") from None
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local:
        raise ValueError("ip não bloqueável (loopback, não especificado, multicast ou link-local)")
    return str(ip)


def validar_expiracao(valor):
    """None ou 0 = sem expiração. Caso contrário: número positivo, finito, até EXPIRA_MAX_HORAS."""
    if valor is None:
        return None
    if isinstance(valor, bool) or not isinstance(valor, (int, float)):
        raise ValueError("expires_hours deve ser um número")
    if valor == 0:
        return None
    if not math.isfinite(valor) or valor < 0:
        raise ValueError("expires_hours deve ser positivo e finito")
    if valor > EXPIRA_MAX_HORAS:
        raise ValueError(f"expires_hours máximo é {EXPIRA_MAX_HORAS}")
    return valor


def sanitizar_motivo(valor, limite=200):
    texto = "" if valor is None else str(valor)
    return "".join(c if c.isprintable() else " " for c in texto)[:limite]
