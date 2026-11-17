"""
Application Adapter - unico ponto onde a infraestrutura HTTP generica
(server/) toca a logica de negocio do Moracle (core/defense.py,
core/logs.py, core/scoring.py). O pacote server/ nunca importa nada
daqui; e este arquivo que importa dos dois lados.
"""
import json
import re

from server.router import Router
from server.response import Response

from core import defense
from core.logs import LogAnalyzer
from core.scoring import calcular_score_linha
from core.http_authz import requer_permissao
from core.validacao_defesa import normalizar_ip
from core import security_runtime as rt
from core.security_actions import processar

IP_RE = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')


def handler_health(request, context):
    return Response.json({"status": "ok", "service": "moracle"})


def handler_status(request, context):
    return Response.json(defense.obter_status())


def handler_blocklist(request, context):
    return Response.json(defense.carregar_blocklist())


def handler_alerts(request, context):
    try:
        limite = int(request.query.get("limit", "50"))
    except ValueError:
        limite = 50
    limite = max(1, min(limite, 1000))
    return Response.json({"alerts": defense.ler_alertas_recentes(limite)})


def _bloquear_via_ciclo_ingest(ip_valido, finding, risco, context):
    """Bloqueio automatico do /ingest, agora pelo ciclo de SecurityAction.
    Q2: se o audit estiver indisponivel (ou o ciclo falhar por qualquer
    razao), o bloqueio NAO e executado e o alerta sai pelo canal de
    audit; a resposta do /ingest continua 200 com o mesmo corpo."""
    try:
        action = rt.novo_registry().propor(
            "block_ip", ("ip", ip_valido), ("automatico", "ingest"),
            f"deteccao via /ingest: {finding['attack_name']} (score {risco['score']})",
            risco={"score": risco["score"], "nivel": risco["nivel"]},
            actor=rt.ator_http(context, automatic="ingest"),
            origin="automatic:ingest",
            correlation_id=rt.request_id_de(context))
        auditor = rt.obter_auditor()
    except Exception as exc:
        rt.alertar_infraestrutura(exc, "ingest")
        return None
    try:
        return processar(action, registry=rt.novo_registry(), auditor=auditor,
                         policy=rt.obter_policy(), executor=rt.obter_executor())
    except Exception as exc:
        rt.alertar_infraestrutura(exc, "ingest")
        return None


def handler_ingest(request, context):
    try:
        dados = json.loads(request.body) if request.body else None
    except json.JSONDecodeError:
        return Response.json({"error": "invalid JSON body"}, status=400)

    if not isinstance(dados, dict) or not dados:
        return Response.json({"error": "invalid or missing JSON body"}, status=400)

    ip = dados.get("ip", "unknown")
    metodo = dados.get("method", "GET")
    caminho_req = dados.get("path", "")
    user_agent = dados.get("user_agent", "-")
    status_code = dados.get("status_code", 0)

    linha_sintetica = f'{ip} - - [-] "{metodo} {caminho_req} HTTP/1.1" {status_code} 0 "-" "{user_agent}"'

    padrao_encontrado = None
    for pattern_name in LogAnalyzer.PRIORIDADE:
        if LogAnalyzer.PATTERNS[pattern_name].search(linha_sintetica.lower()):
            padrao_encontrado = pattern_name
            break

    if not padrao_encontrado:
        return Response.json({"detected": False})

    finding = {
        "ip": ip,
        "attack_type": padrao_encontrado,
        "attack_name": LogAnalyzer.ATTACK_NAMES.get(padrao_encontrado, padrao_encontrado),
        "content": linha_sintetica[:200],
        "confianca": LogAnalyzer.CONFIANCA_PADRAO.get(padrao_encontrado, "media"),
    }
    risco = calcular_score_linha(finding, linha_sintetica)
    finding["risco_score"] = risco["score"]
    finding["risco_nivel"] = risco["nivel"]

    ip_valido = None
    if risco["nivel"] in ("alto", "critico"):
        try:
            ip_valido = normalizar_ip(ip)
        except ValueError:
            ip_valido = None
    if ip_valido:
        if not defense.ip_bloqueado(ip_valido):
            _bloquear_via_ciclo_ingest(ip_valido, finding, risco, context)
        defense.registrar_alerta(ip_valido, finding["attack_name"], finding["content"])

    return Response.json({"detected": True, "finding": finding})


def handler_block(request, context):
    try:
        dados = json.loads(request.body) if request.body else None
    except json.JSONDecodeError:
        return Response.json({"error": "invalid JSON body"}, status=400)

    if not isinstance(dados, dict) or not dados.get("ip"):
        return Response.json({"error": "ip is required"}, status=400)

    motivo = dados.get("reason", "manual block via API")
    expira = dados.get("expires_hours")
    try:
        ip = normalizar_ip(dados["ip"])
    except ValueError as exc:
        return Response.json({"error": str(exc)}, status=400)

    registry = rt.novo_registry()
    try:
        action = registry.propor(
            "block_ip", ("ip", ip), ("humano", context["api_key"].role_name),
            motivo, actor=rt.ator_http(context), origin="http",
            correlation_id=rt.request_id_de(context))
    except ValueError as exc:
        return Response.json({"error": str(exc)}, status=400)

    try:
        auditor = rt.obter_auditor()
    except Exception as exc:
        rt.alertar_infraestrutura(exc, "block")
        return Response.json({"error": "audit unavailable"}, status=503)

    resultado = processar(action, registry=registry, auditor=auditor,
                          policy=rt.obter_policy(), executor=rt.obter_executor(),
                          expira_em_horas=expira)
    if resultado.audit_indisponivel:
        return Response.json({"error": "audit unavailable"}, status=503)
    if resultado.negada:
        return Response.json({"error": "denied by policy"}, status=403)
    if resultado.executado:
        return Response.json({"blocked": ip, "info": resultado.info})
    if resultado.validacao_falhou:
        return Response.json({"error": resultado.erro_mensagem}, status=400)
    return Response.json({"error": "block failed"}, status=500)


def build_router():
    router = Router()
    router.add_route("GET", "/health", handler_health)
    router.add_route("GET", "/status", requer_permissao("defense.read")(handler_status))
    router.add_route("GET", "/blocklist", requer_permissao("defense.read")(handler_blocklist))
    router.add_route("GET", "/alerts", requer_permissao("defense.read")(handler_alerts))
    router.add_route("POST", "/ingest", requer_permissao("ingest.write")(handler_ingest))
    router.add_route("POST", "/block", requer_permissao("defense.block")(handler_block))
    return router
