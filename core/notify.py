"""
Notificação por webhook genérico (compatível com Slack/Discord/Telegram
via bot proxy, ou qualquer endpoint que aceite JSON POST) quando um
bloqueio automático acontece.
"""
import json
import requests
from core import config


def enviar(mensagem, dados_extra=None):
    cfg = config.carregar()
    webhook_url = cfg.get("webhook_url")
    if not webhook_url:
        return False

    payload = {"text": mensagem}
    if dados_extra:
        payload["extra"] = dados_extra

    try:
        requests.post(webhook_url, json=payload, timeout=5)
        return True
    except Exception:
        return False
