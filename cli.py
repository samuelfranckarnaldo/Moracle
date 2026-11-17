#!/usr/bin/env python3
"""
Moracle - Digital Forensics & Active Defense
"""
import argparse
import sys
import os
import json
import re
from datetime import datetime

from core.logs import LogAnalyzer
from core.intelligence import Intelligence
from core.report import ForensicsReport
from core.custody import RegistroCustodia
from core.timeline import TimelineCorrelacionada
from core import defense, config, ioc_cache, ioc_feed, audit, cleanup, synth_log
from core.threat_score import calcular_confianca
from core.watchdog import rodar_com_reinicio
from core.i18n import t
from server.access_log import AccessLogger, JsonlSink


class ansi:
    @staticmethod
    def ok(text): print(f"\033[92m[OK]\033[0m {text}")
    @staticmethod
    def err(text): print(f"\033[91m[ERR]\033[0m {text}")
    @staticmethod
    def info(text): print(f"\033[94m[INFO]\033[0m {text}")
    @staticmethod
    def warn(text): print(f"\033[93m[WARN]\033[0m {text}")


def _defense_block(args):
    """`mc defense block` (Passo 4a): operacao humana protegida.

    Sequencia: credencial explicita (MORACLE_API_KEY) -> autenticacao e
    permissao defense.block (core.cli_authz, que reutiliza core.auth e
    core.authorization) -> validacao do IP -> ciclo de SecurityAction
    (Registry/Auditor/Policy/Executor, o mesmo do /block HTTP) com
    origin=cli-local. Fail-closed: sem audit duravel no destino
    principal (P1) nada executa; sem break-glass (D7). Nenhuma mensagem
    inclui a credencial nem o texto de excecoes."""
    from core import cli_authz, security_runtime as rt
    from core.security_actions import processar
    from core.validacao_defesa import normalizar_ip

    autorizacao = cli_authz.autorizar_operacao_cli("defense.block")
    if not autorizacao.autorizado:
        ansi.err(t("erro", msg=_MENSAGENS_AUTORIZACAO_CLI.get(
            autorizacao.estado, _MENSAGENS_AUTORIZACAO_CLI[cli_authz.INDISPONIVEL])))
        return 1
    api_key = autorizacao.api_key

    try:
        ip = normalizar_ip(args.ip)
    except ValueError as exc:
        ansi.err(t("erro", msg=str(exc)))
        return 1

    registry = rt.novo_registry()
    try:
        action = registry.propor(
            "block_ip", ("ip", ip), ("humano", api_key.role_name), args.reason,
            actor=rt.ator_http({"api_key": api_key}), origin="cli-local")
    except ValueError:
        ansi.err(t("erro", msg="pedido de bloqueio invalido; nada foi executado"))
        return 1

    try:
        auditor = rt.obter_auditor()
    except Exception as exc:  # construir o auditor falhou: nenhum alerta saiu ainda
        rt.alertar_infraestrutura(exc, "cli-block")
        ansi.err(t("erro", msg="auditoria indisponivel; bloqueio nao executado"))
        return 1

    try:
        resultado = processar(action, registry=registry, auditor=auditor,
                              policy=rt.obter_policy(), executor=rt.obter_executor(),
                              expira_em_horas=args.expires_hours)
    except Exception as exc:
        rt.alertar_infraestrutura(exc, "cli-block")
        ansi.err(t("erro", msg="falha interna no ciclo de seguranca; "
                               "o estado do bloqueio nao esta confirmado"))
        return 1

    if resultado.audit_indisponivel:  # persistir falhou: o Auditor ja alertou
        ansi.err(t("erro", msg="auditoria indisponivel; bloqueio nao executado"))
        return 1
    if resultado.negada:
        ansi.err(t("erro", msg="negado pela Policy; bloqueio nao executado"))
        return 1
    if resultado.aguardando_confirmacao:
        ansi.err(t("erro", msg="a acao aguarda confirmacao; bloqueio nao executado"))
        return 1
    if resultado.executado:
        motivo = (resultado.info or {}).get("motivo", action.motivo)
        ansi.warn(t("bloqueado_adicionado", ip=ip, motivo=motivo))
        if resultado.perda_de_rastreabilidade:
            print("[AVISO] o bloqueio de %s foi aplicado, mas a auditoria final "
                  "nao foi confirmada (perda de rastreabilidade do resultado)" % ip,
                  file=sys.stderr)
        return 0
    if resultado.validacao_falhou:
        ansi.err(t("erro", msg=resultado.erro_mensagem))
        return 1
    ansi.err(t("erro", msg="falha na execucao do bloqueio"))
    return 1


_MENSAGENS_AUTORIZACAO_CLI = {
    "credencial_ausente": "credencial ausente; defina a variavel de ambiente MORACLE_API_KEY",
    "nenhuma_chave": "nenhuma chave configurada; crie uma chave com a permissao "
                     "defense.block (POST /admin/keys, com o servidor ativo)",
    "credencial_invalida": "credencial invalida, revogada ou expirada",
    "sem_permissao": "permissao defense.block necessaria",
    "indisponivel": "autorizacao indisponivel; operacao nao executada",
}


def _mensagem_autorizacao(estado, permissao):
    """Mensagem de autorizacao da CLI para qualquer permissao; nunca inclui
    credencial nem texto de excecoes."""
    modelos = dict(_MENSAGENS_AUTORIZACAO_CLI)
    modelos["nenhuma_chave"] = ("nenhuma chave configurada; crie uma chave com a permissao "
                                "%s (POST /admin/keys, com o servidor ativo)" % permissao)
    modelos["sem_permissao"] = "permissao %s necessaria" % permissao
    return modelos.get(estado, modelos["indisponivel"])


def _config_set(args):
    """`mc config set` (Passo 4b-2): classificacao por efeito, permissao
    config.security_write para chaves protegidas/desconhecidas, validacao
    de tipo e limites, escrita atomica e evento config.changed."""
    from core import config_security as cs

    res = cs.executar_config_set(args.key, args.value)
    if res.estado == cs.NEGADO:
        ansi.err(t("erro", msg=_mensagem_autorizacao(res.mensagem, cs.PERMISSAO)
                   + "; a chave '%s' exige essa permissao; nada foi alterado" % _nome_seguro(args.key)))
        return 1
    if res.estado == cs.INVALIDO:
        ansi.err(t("erro", msg="%s; nada foi alterado" % res.mensagem))
        return 1
    if res.estado == cs.AUDIT_INDISPONIVEL:
        ansi.err(t("erro", msg="auditoria indisponivel; alteracao nao executada"))
        return 1
    if res.estado == cs.FALHA:
        ansi.err(t("erro", msg="falha ao gravar a configuracao (%s); o estado nao foi alterado"
                   % res.mensagem))
        return 1
    mostrado = res.valor if res.visivel else ("***" if res.valor is not None else None)
    if res.estado == cs.SEM_ALTERACAO:
        ansi.info("%s ja tem esse valor; nada foi alterado" % _nome_seguro(res.chave))
        return 0
    ansi.ok(t("config_definido", chave=_nome_seguro(res.chave), valor=mostrado))
    if res.perda_de_rastreabilidade:
        print("[AVISO] a configuracao foi alterada, mas a auditoria final nao foi "
              "confirmada (perda de rastreabilidade do resultado)", file=sys.stderr)
    return 0


def _ioc_import(args):
    """`mc forensic ioc-import` (Passo 4b-3): exige `ioc.write`."""
    from core import ioc_security as isec

    res = isec.executar_ioc_import(args.file, args.source)
    if res.estado == isec.NEGADO:
        ansi.err(t("erro", msg=_mensagem_autorizacao(res.mensagem, isec.PERMISSAO)
                   + "; a importacao exige a permissao %s; nada foi importado" % isec.PERMISSAO))
        return 1
    if res.estado == isec.INVALIDO:
        ansi.err(t("erro", msg="%s; nada foi importado" % res.mensagem))
        return 1
    if res.estado == isec.FICHEIRO_ILEGIVEL:
        ansi.err(t("erro", msg="nao foi possivel ler o ficheiro (%s); nada foi importado" % res.mensagem))
        return 1
    if res.estado == isec.AUDIT_INDISPONIVEL:
        ansi.err(t("erro", msg="auditoria indisponivel; importacao nao executada"))
        return 1
    if res.estado == isec.FALHA:
        ansi.err(t("erro", msg="falha ao gravar o cache de IOC (%s); nada foi importado" % res.mensagem))
        return 1
    ansi.ok(f"{res.importados} IOCs importados, {res.ignorados} linhas ignoradas")
    if res.perda_de_rastreabilidade:
        print("[AVISO] a importacao foi aplicada, mas a auditoria final nao foi "
              "confirmada (perda de rastreabilidade do resultado)", file=sys.stderr)
    return 0


def _whois_gravar(ip, resultado, malicioso):
    """Gravacao do whois no cache (S1=ii): so com `ioc.write`; sem ela o
    comando continua somente leitura. Devolve 0 ou 1."""
    from core import ioc_security as isec

    res = isec.registrar_whois(ip, resultado, malicioso)
    if res.estado == isec.SOMENTE_LEITURA:
        ansi.info("cache de IOC nao atualizado (somente leitura; a gravacao exige %s)" % isec.PERMISSAO)
        return 0
    if res.estado == isec.AUDIT_INDISPONIVEL:
        ansi.err(t("erro", msg="auditoria indisponivel; cache de IOC nao atualizado"))
        return 1
    if res.estado == isec.FALHA:
        ansi.err(t("erro", msg="falha ao gravar o cache de IOC (%s)" % res.mensagem))
        return 1
    if res.perda_de_rastreabilidade:
        print("[AVISO] o cache foi atualizado, mas a auditoria final nao foi confirmada",
              file=sys.stderr)
    return 0


def _host_loopback(host):
    from admin_api.client import _eh_loopback
    return _eh_loopback(host)


def _nome_seguro(chave):
    from core.audit import _nome_de_config
    return _nome_de_config(chave)


def main():
    parser = argparse.ArgumentParser(prog="mc", description="Moracle - Digital Forensics & Active Defense")
    top_subparsers = parser.add_subparsers(dest="group")

    # ============ GROUP: FORENSIC ============
    forensic_parser = top_subparsers.add_parser("forensic", help="Forensic mode (investigation, evidence, reports)")
    forensic_subparsers = forensic_parser.add_subparsers(dest="command")

    logs_parser = forensic_subparsers.add_parser("logs", help="Analyze server logs")
    logs_parser.add_argument("file")
    logs_parser.add_argument("--filter")
    logs_parser.add_argument("--suspects", type=int, default=None)
    logs_parser.add_argument("--report")
    logs_parser.add_argument("--json")
    logs_parser.add_argument("--geo", action="store_true", help="Geolocate suspect IPs automatically")
    logs_parser.add_argument("--sessions", action="store_true", help="Group findings into attack sessions by IP+user-agent")

    timeline_parser = forensic_subparsers.add_parser("timeline", help="Correlate multiple logs into one timeline")
    timeline_parser.add_argument("files", nargs="+")
    timeline_parser.add_argument("--filter")
    timeline_parser.add_argument("--report")
    timeline_parser.add_argument("--json")

    whois_parser = forensic_subparsers.add_parser("whois", help="Geolocate IP or query WHOIS")
    whois_parser.add_argument("target")
    whois_parser.add_argument("--virustotal")
    whois_parser.add_argument("--abuseipdb")
    whois_parser.add_argument("--no-cache", action="store_true", dest="no_cache")

    report_parser = forensic_subparsers.add_parser("report", help="Generate a forensic report")
    report_parser.add_argument("--title", default="Relatório Forense")
    report_parser.add_argument("--output", default="relatorio_forense.md")
    report_parser.add_argument("--format", choices=["markdown", "json", "pdf"], default="markdown")

    verify_parser = forensic_subparsers.add_parser("verify", help="Verify integrity of a collected evidence file")
    verify_parser.add_argument("file")

    rotate_parser = forensic_subparsers.add_parser("rotate", help="Rotate a log file: archive current content with custody, start a fresh empty log")
    rotate_parser.add_argument("file")

    export_parser = forensic_subparsers.add_parser("export-intel", help="Export findings from a log as STIX or MISP threat intel")
    export_parser.add_argument("file")
    export_parser.add_argument("--format", choices=["stix", "misp"], default="stix")
    export_parser.add_argument("--output", required=True)

    supabase_parser = forensic_subparsers.add_parser("supabase-sync", help="Pull security_events from Supabase and merge into a timeline-compatible JSON")
    supabase_parser.add_argument("--output", default="supabase_events.json")
    supabase_parser.add_argument("--limit", type=int, default=500)

    synth_parser = forensic_subparsers.add_parser("synth", help="Generate a synthetic log file for testing detection/defense without a real incident")
    synth_parser.add_argument("output")
    synth_parser.add_argument("--lines", type=int, default=200)
    synth_parser.add_argument("--attack-ratio", type=float, default=0.3, dest="attack_ratio")
    synth_parser.add_argument("--seed", type=int, default=None)

    ioc_import_parser = forensic_subparsers.add_parser("ioc-import", help="Import a public IOC feed (one IP per line, or CSV) into the local cache")
    ioc_import_parser.add_argument("file")
    ioc_import_parser.add_argument("--source", default="feed_importado")

    # ============ GROUP: DEFENSE ============
    defense_parser = top_subparsers.add_parser("defense", help="Defense mode (active monitoring, agent state)")
    defense_subparsers = defense_parser.add_subparsers(dest="command")
    defense_subparsers.add_parser("status", help="Show agent status and blocklist")

    monitor_parser = defense_subparsers.add_parser("monitor", help="Start real-time monitoring of a log")
    monitor_parser.add_argument("file")
    monitor_parser.add_argument("--interval", type=int, default=None)
    monitor_parser.add_argument("--threshold", type=int, default=None)
    monitor_parser.add_argument("--dry-run", action="store_true", dest="dry_run")

    block_parser = defense_subparsers.add_parser("block", help="Block an IP manually (adds to blocklist); requires MORACLE_API_KEY with defense.block")
    block_parser.add_argument("ip")
    block_parser.add_argument("--reason", default="manual block")
    block_parser.add_argument("--expires-hours", type=float, default=None, dest="expires_hours")

    watch_parser = defense_subparsers.add_parser("watch", help="Monitor with automatic restart on crash (for background/service use)")
    watch_parser.add_argument("file")
    watch_parser.add_argument("--interval", type=int, default=None)
    watch_parser.add_argument("--threshold", type=int, default=None)

    health_parser = defense_subparsers.add_parser("health", help="Quick health check (config valid, blocklist readable, agent state)")
    health_parser.add_argument("--log-file", default=None, dest="log_file", help="Optionally check this log file exists and is readable")

    alerts_parser = defense_subparsers.add_parser("alerts", help="Show recent alerts recorded by defense monitor/watch")
    alerts_parser.add_argument("--limit", type=int, default=50)

    # ============ TECH ============
    tech_parser = top_subparsers.add_parser("tech", help="Detect WAF/CMS/Framework")
    tech_parser.add_argument("url")

    # ============ SERVER ============
    server_parser = top_subparsers.add_parser("server", help="Run Moracle as an HTTP server (own process, like 'npm run dev')")
    server_subparsers = server_parser.add_subparsers(dest="command")

    server_start_parser = server_subparsers.add_parser("start", help="Start the Moracle HTTP server")
    server_start_parser.add_argument("--host", default="127.0.0.1")
    server_start_parser.add_argument("--port", type=int, default=7000)

    server_start_parser.add_argument("--workers", type=int, default=20)
    server_start_parser.add_argument("--tls", action="store_true", help="Enable TLS (self-signed cert generated locally if none provided)")
    server_start_parser.add_argument("--cert", default=None, help="Path to TLS certificate (PEM)")
    server_start_parser.add_argument("--key", default=None, help="Path to TLS private key (PEM)")
    server_start_parser.add_argument("--github-webhook-secret", default=None, dest="github_webhook_secret",
                                      help="If set, registers POST /webhooks/github using this secret for HMAC validation")

    server_subparsers.add_parser("key", help="Show the API key for this Moracle installation")

    # ============ PLATFORM (deploy) ============
    def _add_admin_api_args(p):
        p.add_argument("--admin-url", default="http://127.0.0.1:7000", dest="admin_url",
                        help="Base URL of a running Moracle server (mc server start)")
        p.add_argument("--admin-key", default=None, dest="admin_key",
                        help="API key; defaults to this installation's key (mc server key)")

    apps_parser = top_subparsers.add_parser("apps", help="Manage applications via the Admin API (requires 'mc server start' running)")
    apps_subparsers = apps_parser.add_subparsers(dest="command")

    apps_list_parser = apps_subparsers.add_parser("list", help="List all applications")
    _add_admin_api_args(apps_list_parser)

    apps_show_parser = apps_subparsers.add_parser("show", help="Show one application (add --include-env to reveal environment)")
    apps_show_parser.add_argument("app_name")
    apps_show_parser.add_argument("--include-env", action="store_true", dest="include_env")
    _add_admin_api_args(apps_show_parser)

    apps_create_parser = apps_subparsers.add_parser("create", help="Create a new application")
    apps_create_parser.add_argument("app_name")
    apps_create_parser.add_argument("--working-directory", required=True, dest="working_directory")
    apps_create_parser.add_argument("--start-command", required=True, dest="start_command",
                                     help="Comma-separated argument list, e.g. 'node,server.js'")
    apps_create_parser.add_argument("--port", type=int, default=None)
    apps_create_parser.add_argument("--domain", default=None)
    apps_create_parser.add_argument("--health-check-path", default="/health", dest="health_check_path")
    apps_create_parser.add_argument("--restart-policy", default="NEVER", dest="restart_policy",
                                     choices=["NEVER", "ON_FAILURE", "ALWAYS"])
    _add_admin_api_args(apps_create_parser)

    apps_delete_parser = apps_subparsers.add_parser("delete", help="Delete a stopped application")
    apps_delete_parser.add_argument("app_name")
    _add_admin_api_args(apps_delete_parser)

    apps_start_parser = apps_subparsers.add_parser("start", help="Start an application's current deployment")
    apps_start_parser.add_argument("app_name")
    _add_admin_api_args(apps_start_parser)

    apps_stop_parser = apps_subparsers.add_parser("stop", help="Stop an application's process")
    apps_stop_parser.add_argument("app_name")
    _add_admin_api_args(apps_stop_parser)

    apps_restart_parser = apps_subparsers.add_parser("restart", help="Restart (redeploy) an application")
    apps_restart_parser.add_argument("app_name")
    _add_admin_api_args(apps_restart_parser)

    apps_status_parser = apps_subparsers.add_parser("status", help="Show an application's process status")
    apps_status_parser.add_argument("app_name")
    _add_admin_api_args(apps_status_parser)

    apps_logs_parser = apps_subparsers.add_parser("logs", help="Show an application's stdout/stderr")
    apps_logs_parser.add_argument("app_name")
    apps_logs_parser.add_argument("--lines", type=int, default=100)
    _add_admin_api_args(apps_logs_parser)

    deploy_parser = top_subparsers.add_parser("deploy", help="Deploy an application (via Admin API)")
    deploy_parser.add_argument("app_name")
    deploy_parser.add_argument("--health-url", default=None, dest="health_url",
                                help="Override the health-check base URL for this deploy")
    _add_admin_api_args(deploy_parser)

    rollback_parser = top_subparsers.add_parser("rollback", help="Roll back to a previous deployment (via Admin API)")
    rollback_parser.add_argument("deployment_id")
    _add_admin_api_args(rollback_parser)

    # ============ ACCESS LOG ============
    access_log_parser = top_subparsers.add_parser("access-log", help="Manage the structured Access Log (mc server request log)")
    access_log_subparsers = access_log_parser.add_subparsers(dest="command")
    access_log_subparsers.add_parser("rotate", help="Archive the current access_log.jsonl and start a fresh empty one")

    # ============ CONFIG ============
    config_parser = top_subparsers.add_parser("config", help="View or change configuration")
    config_subparsers = config_parser.add_subparsers(dest="command")
    config_subparsers.add_parser("show")
    cleanup_parser = config_subparsers.add_parser("cleanup", help="Remove old files from the output directory")
    cleanup_parser.add_argument("--days", type=int, default=30, dest="days")
    cleanup_parser.add_argument("--dry-run", action="store_true", dest="dry_run")
    set_parser = config_subparsers.add_parser("set")
    set_parser.add_argument("key")
    set_parser.add_argument("value")
    audit_parser = config_subparsers.add_parser("audit")
    audit_parser.add_argument("--limit", type=int, default=20)

    args = parser.parse_args()
    if not args.group:
        parser.print_help()
        return 0

    if args.group == "server":
        from core.api_key import obter_ou_criar
        if args.command == "key":
            ansi.info(f"API key: {obter_ou_criar()}")
            return 0
        if args.command == "start":
            chave = obter_ou_criar()
            from core.identity import migrate_legacy_admin_key
            _migrada = migrate_legacy_admin_key(os.path.join(config.RAIZ_PROJETO, '.state'))
            if _migrada is not None:   # 4b-4: auditar o FATO (nao muda a autorizacao do server start)
                from core import audit_ciclo, security_runtime as _rt
                if not audit_ciclo.registar_fato(
                        "key.migrated", {"target_id": _migrada.id, "role": _migrada.role_name},
                        _rt.ator_http({}), "cli-local"):
                    ansi.warn("a migracao da chave legada foi aplicada, mas o evento de auditoria nao foi confirmado")
            from core.security_runtime import reconciliar_na_partida
            _estado_audit = reconciliar_na_partida()
            if _estado_audit.degradado:
                ansi.warn(f"Audit de seguranca: reconciliacao {_estado_audit.texto} (acoes protegidas so executam com evento duravel)")
            ansi.ok(f"Moracle server starting on http://{args.host}:{args.port}")
            ansi.info(f"API key (use: Authorization: Bearer <key>): {chave}")

            if True:
                from core.logging_setup import configurar_logging
                configurar_logging()
                from server.server import Server, ServerConfig
                from core.moracle_adapter import build_router
                from core.moracle_middleware import auth_middleware
                from core.rate_limit_middleware import rate_limit_middleware

                router = build_router()

                from admin_api.router import registrar_rotas_admin
                registrar_rotas_admin(router)
                ansi.ok("Admin API registered under /admin/*")

                from admin_api.static_files import criar_handler_estatico
                _diretorio_console = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web", "console")
                _handler_console = criar_handler_estatico(_diretorio_console, spa_fallback=True)
                router.add_route("GET", "/console", _handler_console)
                router.add_route("GET", "/console/{path}", _handler_console)
                ansi.ok("Console available at /console")

                if args.github_webhook_secret:
                    from deploy_platform.github_webhook import criar_handler_github_webhook
                    from deploy_platform import deploy as deploy_mod

                    def _deploy_callback(evento):
                        payload = evento.get("payload", {})
                        repo = payload.get("repository", {})
                        app_name = repo.get("name", "webhook-app")
                        ref = payload.get("ref", "")

                        ansi.info(f"GitHub webhook: {evento['event']} em {app_name} ({ref})")

                        webhook_cfg = config.carregar().get("webhook_deploy", {})
                        app_cfg = webhook_cfg.get(app_name)

                        if not app_cfg:
                            ansi.warn(f"Nenhuma config de deploy para '{app_name}' em config.json (webhook_deploy.{app_name}) — evento recebido mas ignorado")
                            return {"deployed": False, "reason": "no deploy config for this app"}

                        try:
                            resultado = deploy_mod.deploy(
                                app_name=app_name,
                                source_path=app_cfg.get("source_path", repo.get("full_name", "")),
                                health_check_base_url=app_cfg["health_check_base_url"],
                                health_check_path=app_cfg.get("health_check_path", "/health"),
                                domain=app_cfg.get("domain"),
                            )
                            if resultado.status == "active":
                                ansi.ok(f"Deploy automatico OK: {app_name} -> {resultado.deployment_id}")
                            else:
                                ansi.err(f"Deploy automatico FALHOU: {app_name} -> {resultado.error_message}")
                            return {"deployed": resultado.status == "active", "deployment_id": resultado.deployment_id, "status": resultado.status}
                        except deploy_mod.DeployError as e:
                            ansi.err(f"Deploy automatico invalido: {e}")
                            return {"deployed": False, "error": str(e)}

                    webhook_handler = criar_handler_github_webhook(args.github_webhook_secret, _deploy_callback)
                    router.add_route("POST", "/webhooks/github", webhook_handler)
                    ansi.ok("GitHub webhook registered at /webhooks/github")

                tls_context = None
                if args.tls:
                    from core.tls_config import obter_contexto_tls
                    try:
                        tls_context = obter_contexto_tls(args.cert, args.key)
                        ansi.ok("TLS enabled")
                    except Exception as e:
                        ansi.err(f"Failed to configure TLS: {e}")
                        return 1
                if not tls_context and not _host_loopback(args.host):
                    print("[AVISO] o servidor vai aceitar ligacoes em %s SEM TLS: a chave de API e os "
                          "dados viajam em texto simples. Use --tls ou limite a 127.0.0.1." % args.host,
                          file=sys.stderr)
                server_config = ServerConfig(host=args.host, port=args.port, max_workers=args.workers, tls_context=tls_context)
                caminho_access_log = os.path.join(config.RAIZ_PROJETO, ".state", "access_log.jsonl")
                access_logger = AccessLogger(jsonl_sink=JsonlSink(caminho_access_log))
                servidor = Server(server_config, router, middlewares=[rate_limit_middleware, auth_middleware], access_logger=access_logger)
                try:
                    servidor.start(block=True, handle_signals=True)
                except KeyboardInterrupt:
                    ansi.info("Shutting down...")
                    servidor.stop()
            return 0
        server_parser.print_help()
        return 0

    audit.registrar(args.group, getattr(args, "command", None), vars(args))

    def _admin_client(args):
        from admin_api.client import AdminAPIClient
        from core.api_key import obter_ou_criar
        chave = args.admin_key or obter_ou_criar()
        return AdminAPIClient(args.admin_url, chave)

    if args.group == "deploy":
        from admin_api.client import AdminAPIError
        cliente = _admin_client(args)
        try:
            resultado = cliente.deploy_app(args.app_name, health_check_base_url=args.health_url)
        except AdminAPIError as e:
            ansi.err(str(e))
            return 1

        if resultado.get("status") == "active":
            ansi.ok(f"Deployment {resultado['deployment_id']} ACTIVE for {args.app_name}")
            return 0
        ansi.err(f"Deployment {resultado.get('deployment_id')} FAILED: {resultado.get('error_message')}")
        return 1

    if args.group == "rollback":
        from admin_api.client import AdminAPIError
        cliente = _admin_client(args)
        try:
            resultado = cliente.rollback_deployment(args.deployment_id)
            ansi.ok(f"{resultado['app_name']} rolled back to {resultado['deployment_id']}")
            return 0
        except AdminAPIError as e:
            ansi.err(str(e))
            return 1

    if args.group == "apps":
        from admin_api.client import AdminAPIError
        cliente = _admin_client(args)

        if not args.command or args.command == "list":
            try:
                apps = cliente.list_apps()
            except AdminAPIError as e:
                ansi.err(str(e))
                return 1
            if not apps:
                print("No applications yet.")
                return 0
            print("\n" + "=" * 60)
            print("APPLICATIONS")
            print("=" * 60)
            for app in apps:
                print(f"  {app['name']}  domain={app.get('domain') or '-'}  current={app.get('current_deployment_id') or '-'}")
            print("=" * 60)
            return 0

        if args.command == "create":
            try:
                app = cliente.create_app(
                    args.app_name, args.working_directory,
                    args.start_command.split(","),
                    port=args.port, domain=args.domain,
                    health_check_path=args.health_check_path,
                    restart_policy_mode=args.restart_policy,
                )
                ansi.ok(f"Application {app['name']!r} created")
                return 0
            except AdminAPIError as e:
                ansi.err(str(e))
                return 1

        if args.command == "delete":
            try:
                cliente.delete_app(args.app_name)
                ansi.ok(f"Application {args.app_name!r} deleted")
                return 0
            except AdminAPIError as e:
                ansi.err(str(e))
                return 1

        if args.command == "start":
            try:
                resultado = cliente.start_app(args.app_name)
                ansi.ok(f"Started — pid={resultado.get('pid')}")
                return 0
            except AdminAPIError as e:
                ansi.err(str(e))
                return 1

        if args.command == "stop":
            try:
                cliente.stop_app(args.app_name)
                ansi.ok(f"{args.app_name} stopped")
                return 0
            except AdminAPIError as e:
                ansi.err(str(e))
                return 1

        if args.command == "restart":
            try:
                resultado = cliente.restart_app(args.app_name)
                ansi.ok(f"Restarted — deployment {resultado.get('deployment_id')} ({resultado.get('status')})")
                return 0
            except AdminAPIError as e:
                ansi.err(str(e))
                return 1

        if args.command == "status":
            try:
                status = cliente.status_app(args.app_name)
            except AdminAPIError as e:
                ansi.err(str(e))
                return 1
            print("\n" + "=" * 60)
            print(f"STATUS — {args.app_name}")
            print("=" * 60)
            for chave_status, valor in status.items():
                print(f"  {chave_status}: {valor}")
            print("=" * 60)
            return 0

        if args.command == "logs":
            try:
                logs = cliente.logs_app(args.app_name, lines=args.lines)
            except AdminAPIError as e:
                ansi.err(str(e))
                return 1
            print("--- stdout ---")
            print(logs.get("stdout", ""))
            print("--- stderr ---")
            print(logs.get("stderr", ""))
            return 0

        if args.command == "show":
            try:
                app = cliente.get_app(args.app_name, include_env=args.include_env)
                deployments = cliente.list_deployments(args.app_name)
            except AdminAPIError as e:
                ansi.err(str(e))
                return 1
            print("\n" + "=" * 60)
            print(f"APPLICATION — {args.app_name}")
            print("=" * 60)
            for chave_app, valor in app.items():
                if chave_app != "status":
                    print(f"  {chave_app}: {valor}")
            print("\n  Status:")
            for chave_status, valor in app.get("status", {}).items():
                print(f"    {chave_status}: {valor}")
            print("\n  Deployments:")
            for d in sorted(deployments, key=lambda d: d["created_at"]):
                marcador = " (CURRENT)" if d["deployment_id"] == app.get("current_deployment_id") else ""
                print(f"    {d['deployment_id']}  status={d['status']}{marcador}")
            print("=" * 60)
            return 0

        apps_parser.print_help()
        return 0

    # ============ ACCESS LOG ============
    if args.group == "access-log":
        if args.command == "rotate":
            from core.log_rotation import rotacionar
            caminho_access_log = os.path.join(config.RAIZ_PROJETO, ".state", "access_log.jsonl")
            try:
                resultado = rotacionar(caminho_access_log)
                ansi.ok(f"Access log rotacionado: {resultado['arquivo_arquivado']}")
                ansi.info(f"Hash da evidencia arquivada: {resultado['hash']}")
                return 0
            except FileNotFoundError:
                ansi.err(f"Nenhum access log ativo encontrado em {caminho_access_log} (nenhuma requisicao registrada ainda?)")
                return 1
            except Exception as e:
                ansi.err(t("erro", msg=str(e)))
                return 1

        access_log_parser.print_help()
        return 0

    # ============ CONFIG ============
    if args.group == "config":
        if args.command == "set":
            return _config_set(args)
        if args.command == "cleanup":
            resultado = cleanup.limpar_saida(dias_retencao=args.days, simular=args.dry_run)
            acao = "Seriam removidos" if args.dry_run else "Removidos"
            ansi.ok(f"{acao} {len(resultado['removidos'])} arquivos ({resultado['total_liberado_bytes']} bytes)")
            for caminho in resultado["removidos"]:
                print(f"    {caminho}")
            return 0

        if args.command == "audit":
            for entrada in audit.ler_recentes(args.limit):
                print(f"{entrada['timestamp']} | {entrada['usuario']} | {entrada['grupo']} {entrada.get('comando') or ''}")
            return 0

        cfg = config.carregar()
        print("\n" + t("config_titulo"))
        print(json.dumps(cfg, indent=2, ensure_ascii=False))
        return 0

    # ============ FORENSIC ============
    if args.group == "forensic":
        if not args.command:
            forensic_parser.print_help()
            return 0

        if args.command == "logs":
            ansi.info(t("analisando_logs", file=args.file))
            try:
                analyzer = LogAnalyzer(args.file)
                analyzer.load()
                filters = args.filter.split(",") if args.filter else None
                findings = analyzer.analyze(filters)
                summary = analyzer.get_summary()
                suspects_min = args.suspects or config.carregar()["limite_suspeitos_padrao"]

                print("\n" + "=" * 60)
                print(t("resumo_titulo"))
                print("=" * 60)
                print(f"  {t('total_linhas')}: {summary['total_lines']}")
                print(f"  {t('achados')}: {summary['total_findings']}")
                print(f"  {t('ips_suspeitos')}: {summary['suspect_ips']}")
                print(f"\n  {t('distribuicao_ataques')}:")
                for attack, count in summary["attack_types"].most_common():
                    print(f"    {attack}: {count}")

                suspects = analyzer.get_suspects(suspects_min)
                if suspects:
                    print(f"\n  {t('ips_suspeitos')}:")
                    for ip, count in sorted(suspects.items(), key=lambda x: -x[1]):
                        print(f"    {ip}: {count}")

                alta_confianca = [f for f in findings if f.get("confianca") == "alta"]
                if alta_confianca:
                    print(f"\n  Achados de alta confiança: {len(alta_confianca)}")

                if args.sessions and findings:
                    from core.attack_session import agrupar_sessoes
                    sessoes = agrupar_sessoes(findings)
                    print(f"\n  Sessões de ataque ({len(sessoes)}):")
                    for s in sessoes[:10]:
                        print(f"    {s['ip']} ({s['user_agent'][:40]}) — {s['total_eventos']} eventos, score max {s['score_maximo']}")

                if args.geo and suspects:
                    intelligence = Intelligence()
                    print(f"\n  Geolocalização dos IPs suspeitos:")
                    for ip in suspects:
                        if ip == "unknown" or ip.startswith(("10.", "192.168.", "127.")):
                            print(f"    {ip}: rede privada/local, sem geolocalização pública")
                            continue
                        geo = intelligence.geolocate(ip)
                        print(f"    {ip}: {geo.get('city', 'N/A')}, {geo.get('country', 'N/A')} ({geo.get('org', 'N/A')})")
                print("=" * 60)

                if analyzer.aviso_arquivo_ativo:
                    ansi.warn(f"Ficheiro modificado ha menos de 5s — pode ainda estar em escrita ativa. Considere congelar (copiar) antes de gerar custodia definitiva.")

                if analyzer.custodia:
                    print(f"\n  {t('hash_custodia')}: {analyzer.custodia.hash_sha256}")

                if args.report:
                    caminho = config.resolver_caminho_saida(args.report, "relatorio")
                    with open(caminho, 'w') as f:
                        f.write(analyzer.to_markdown())
                    ansi.ok(t("relatorio_guardado", path=caminho))

                if args.json:
                    caminho = config.resolver_caminho_saida(args.json, "dados")
                    with open(caminho, 'w') as f:
                        json.dump({
                            "summary": {**{k: v for k, v in summary.items() if k != "attack_types"},
                                        "attack_types": dict(summary["attack_types"])},
                            "findings": findings, "suspects": suspects,
                            "custodia": analyzer.custodia.to_dict() if analyzer.custodia else None,
                        }, f, indent=2)
                    ansi.ok(t("dados_exportados", path=caminho))
                return 0
            except Exception as e:
                ansi.err(t("erro", msg=str(e)))
                return 1

        if args.command == "timeline":
            try:
                filters = args.filter.split(",") if args.filter else None
                tl = TimelineCorrelacionada(args.files)
                tl.carregar_e_analisar(filters)
                resumo = tl.get_summary()

                print("\n" + "=" * 60)
                print(t("timeline_titulo"))
                print("=" * 60)
                print(f"  {t('fontes')}: {len(args.files)}")
                print(f"  {t('eventos_totais')}: {resumo['total_eventos']}")
                print(f"  {t('ips_envolvidos')}: {resumo['ips_envolvidos']}")
                print("=" * 60)

                if args.report:
                    caminho = config.resolver_caminho_saida(args.report, "relatorio")
                    with open(caminho, 'w') as f:
                        f.write(tl.to_markdown())
                    ansi.ok(t("relatorio_guardado", path=caminho))

                if args.json:
                    caminho = config.resolver_caminho_saida(args.json, "dados")
                    with open(caminho, 'w') as f:
                        json.dump({"summary": resumo, "eventos": tl.eventos}, f, indent=2)
                    ansi.ok(t("dados_exportados", path=caminho))
                return 0
            except Exception as e:
                ansi.err(t("erro", msg=str(e)))
                return 1

        if args.command == "export-intel":
            analyzer = LogAnalyzer(args.file)
            analyzer.load()
            findings = analyzer.analyze()

            if args.format == "stix":
                from core.stix_export import exportar_stix
                dados = exportar_stix(findings)
            else:
                from core.stix_export import exportar_misp
                dados = exportar_misp(findings)

            caminho = config.resolver_caminho_saida(args.output, "dados")
            with open(caminho, "w") as f:
                json.dump(dados, f, indent=2)
            ansi.ok(f"Threat intel exportado ({args.format}): {caminho}")
            return 0

        if args.command == "supabase-sync":
            try:
                from core.supabase_adapter import buscar_eventos
                eventos = buscar_eventos(limite=args.limit)
                caminho = config.resolver_caminho_saida(args.output, "dados")
                with open(caminho, "w") as f:
                    json.dump({"eventos": eventos}, f, indent=2)
                ansi.ok(f"{len(eventos)} eventos sincronizados do Supabase: {caminho}")
                return 0
            except Exception as e:
                ansi.err(t("erro", msg=str(e)))
                return 1

        if args.command == "rotate":
            try:
                from core.log_rotation import rotacionar
                resultado = rotacionar(args.file)
                ansi.ok(f"Log rotacionado: {resultado['arquivo_arquivado']}")
                ansi.info(f"Hash da evidencia arquivada: {resultado['hash']}")
                return 0
            except Exception as e:
                ansi.err(t("erro", msg=str(e)))
                return 1

        if args.command == "synth":
            resultado = synth_log.gerar(args.output, total_linhas=args.lines,
                                         proporcao_ataque=args.attack_ratio, seed=args.seed)
            ansi.ok(f"Log sintético gerado: {resultado['caminho']} ({resultado['linhas']} linhas)")
            return 0

        if args.command == "ioc-import":
            return _ioc_import(args)

        if args.command == "verify":
            caminho_custodia = os.path.expanduser(args.file) + ".custodia.json"
            if not os.path.exists(caminho_custodia):
                ansi.err(t("custodia_nao_encontrada", file=args.file))
                return 1
            registro = RegistroCustodia.carregar(caminho_custodia)
            ansi.info(t("verificando_integridade", path=registro.caminho_evidencia))
            ok = registro.verificar_integridade()
            registro.registrar_acesso("integrity check — " + ("OK" if ok else "FAILED"))
            registro.salvar(caminho_custodia)
            if ok:
                ansi.ok(t("integridade_confirmada", hash=registro.hash_sha256))
                return 0
            ansi.err(t("integridade_falhou"))
            return 1

        if args.command == "whois":
            intelligence = Intelligence()
            is_ip = re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', args.target)

            if is_ip and not args.no_cache:
                cache_hit = ioc_cache.obter(args.target)
                if cache_hit:
                    ansi.info(t("ioc_cache_hit", ip=args.target, horas=cache_hit["idade_horas"]))
                    print(json.dumps(cache_hit["dados"], indent=2, default=str))
                    return 0

            if is_ip:
                geo = intelligence.geolocate(args.target)
                print("\n" + "=" * 60 + "\nGEOLOCATION\n" + "=" * 60)
                for campo in ["ip", "country", "city", "region", "isp", "org", "timezone"]:
                    print(f"  {campo}: {geo.get(campo, 'N/A')}")
                print("=" * 60)

                resultado = {"geo": geo}
                malicioso = False
                if args.virustotal:
                    vt = intelligence.check_virustotal(args.target, args.virustotal)
                    resultado["virustotal"] = vt
                    print(json.dumps(vt, indent=2))
                if args.abuseipdb:
                    abuse = intelligence.check_abuseipdb(args.target, args.abuseipdb)
                    resultado["abuseipdb"] = abuse
                    print(json.dumps(abuse, indent=2))
                cache_entry_atual = ioc_cache.obter(args.target)
                confianca = calcular_confianca(
                    virustotal=resultado.get("virustotal"),
                    abuseipdb=resultado.get("abuseipdb"),
                    entrada_ioc_cache=cache_entry_atual,
                )
                if confianca["score"] is not None:
                    print(f"\n  Threat score: {confianca['score']}/100 ({confianca['nivel']})")
                    malicioso = confianca["score"] >= 50

                if _whois_gravar(args.target, resultado, malicioso) != 0:
                    return 1
            else:
                whois_data = intelligence.whois(args.target)
                print(json.dumps(whois_data, indent=2, default=str))
            return 0

        if args.command == "report":
            report = ForensicsReport(args.title)
            report.add_section("metadata", {"title": args.title, "created": datetime.now().isoformat(), "author": "Moracle"})
            report.add_section("summary", "Report auto-generated by Moracle")

            if args.format == "pdf":
                try:
                    from core.pdf_export import markdown_simples_para_pdf
                except ImportError:
                    ansi.err("PDF export requires the 'reportlab' package. Install with: pip install reportlab --break-system-packages")
                    return 1
                caminho_md = config.resolver_caminho_saida(args.output.replace(".pdf", ".md"), "relatorio")
                report.save(caminho_md, "markdown")
                with open(caminho_md) as f:
                    texto_md = f.read()
                caminho_pdf = config.resolver_caminho_saida(args.output, "relatorio")
                markdown_simples_para_pdf(texto_md, caminho_pdf, titulo=args.title)
                ansi.ok(t("relatorio_guardado", path=caminho_pdf))
            else:
                caminho = config.resolver_caminho_saida(args.output, "relatorio" if args.format == "markdown" else "dados")
                report.save(caminho, args.format)
                ansi.ok(t("relatorio_guardado", path=caminho))
            return 0

    # ============ DEFENSE ============
    if args.group == "defense":
        if not args.command:
            defense_parser.print_help()
            return 0

        if args.command == "status":
            estado = defense.obter_status()
            print("\n" + "=" * 60 + "\n" + t("estado_agente_titulo") + "\n" + "=" * 60)
            print(f"  {t('ativo')}: {t('sim') if estado['ativo'] else t('nao')}")
            if estado.get("iniciado_em"):
                print(f"  {t('iniciado_em')}: {estado['iniciado_em']}")
            if estado.get("parado_em"):
                print(f"  {t('parado_em')}: {estado['parado_em']}")
            print(f"  {t('ips_blocklist')}: {estado['ips_bloqueados']}")
            blocklist = defense.carregar_blocklist()
            if blocklist:
                print(f"\n  {t('blocklist_titulo')}:")
                for ip, info in blocklist.items():
                    print(f"    {ip} — {info['motivo']} ({info['bloqueado_em']})")
            print("=" * 60)
            return 0

        if args.command == "monitor":
            try:
                defense.monitorar(args.file, intervalo=args.interval, limite_alerta=args.threshold, dry_run=args.dry_run)
            except FileNotFoundError as e:
                ansi.err(t("erro", msg=str(e)))
                return 1
            return 0

        if args.command == "block":
            return _defense_block(args)

        if args.command == "watch":
            rodar_com_reinicio(args.file, intervalo=args.interval, limite_alerta=args.threshold)
            return 0

        if args.command == "alerts":
            for linha in defense.ler_alertas_recentes(args.limit):
                print(linha)
            return 0

        if args.command == "health":
            problemas = []
            try:
                config.carregar()
            except Exception as e:
                problemas.append(f"config.json inválido: {e}")

            try:
                defense.carregar_blocklist()
                defense.obter_status()
            except Exception as e:
                problemas.append(f"estado do agente inacessível: {e}")

            if args.log_file:
                if not os.path.exists(args.log_file):
                    problemas.append(f"log informado não existe: {args.log_file}")
                elif not os.access(args.log_file, os.R_OK):
                    problemas.append(f"log informado sem permissão de leitura: {args.log_file}")

            if problemas:
                for p in problemas:
                    ansi.err(p)
                return 1
            ansi.ok("Moracle OK — config válida, estado do agente acessível" + (f", log '{args.log_file}' legível" if args.log_file else ""))
            return 0

    # ============ TECH ============
    if args.group == "tech":
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from modules.scan_tech import detect_tech
        result = detect_tech(args.url)
        print("\n" + "=" * 50 + "\nTECHNOLOGY DETECTION\n" + "=" * 50)
        for campo in ["server", "waf", "cms", "framework", "language"]:
            valor = result.get(campo, "N/A")
            if isinstance(valor, list):
                valor = ', '.join(valor) or "Nenhum"
            print(f"  {campo}: {valor}")
        print("=" * 50)
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
