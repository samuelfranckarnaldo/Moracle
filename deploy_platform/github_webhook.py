"""
Recebe webhooks do GitHub (push/release) e dispara um deploy. Valida
a assinatura HMAC-SHA256 que o GitHub envia no header
X-Hub-Signature-256, exatamente como fizemos para a assinatura de
custodia forense - stdlib hmac/hashlib, sem dependencia externa.
"""
import hashlib
import hmac
import json

from server.response import Response


def verificar_assinatura(segredo, corpo_bytes, assinatura_recebida):
    """assinatura_recebida vem no formato 'sha256=<hex>'."""
    if not assinatura_recebida or not assinatura_recebida.startswith("sha256="):
        return False
    esperada = "sha256=" + hmac.new(segredo.encode(), corpo_bytes, hashlib.sha256).hexdigest()
    return hmac.compare_digest(esperada, assinatura_recebida)


def criar_handler_github_webhook(segredo, deploy_callback):
    """deploy_callback(evento: dict) e' chamado quando a assinatura e'
    valida e o evento e' um push/release - decide o que fazer com o
    payload (ex: chamar deploy_platform.deploy.deploy(...))."""

    def handler(request, context):
        assinatura = request.header("x-hub-signature-256")
        if not verificar_assinatura(segredo, request.body, assinatura):
            return Response.json({"error": "invalid signature"}, status=401)

        evento_tipo = request.header("x-github-event", "unknown")

        try:
            payload = json.loads(request.body) if request.body else {}
        except json.JSONDecodeError:
            return Response.json({"error": "invalid JSON payload"}, status=400)

        if evento_tipo not in ("push", "release"):
            return Response.json({"status": "ignored", "event": evento_tipo}, status=200)

        try:
            resultado = deploy_callback({"event": evento_tipo, "payload": payload})
        except Exception as e:
            return Response.json({"error": f"deploy_callback failed: {e}"}, status=500)

        return Response.json({"status": "accepted", "event": evento_tipo, "result": resultado}, status=202)

    return handler
