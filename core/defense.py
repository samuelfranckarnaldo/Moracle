"""
Defesa ativa - estado do agente, blocklist e monitoramento em tempo
real. Todo acesso a blocklist.json, defesa_state.json e alerts.log
passa por atomic_state (lock + escrita atomica) - resolve a race
condition de multiplas threads/requests tocando o mesmo estado.
Nao manipula firewall/iptables (exigiria root); a blocklist e um
registro de decisao que outra integracao pode consumir.
"""
import os
import time
from datetime import datetime, timezone

from core.logs import LogAnalyzer
from core import config, ioc_cache, notify
from core.i18n import t
from core.atomic_state import modificar_json_com_lock, ler_json, append_linha_com_lock, FileLock
from core.validacao_defesa import normalizar_ip, validar_expiracao, sanitizar_motivo

STATE_DIR = os.path.join(config.RAIZ_PROJETO, ".state")
STATE_FILE = os.path.join(STATE_DIR, "defesa_state.json")
BLOCKLIST_FILE = os.path.join(STATE_DIR, "blocklist.json")
ALERTS_FILE = os.path.join(STATE_DIR, "alerts.log")


def _garantir_state_dir():
    os.makedirs(STATE_DIR, exist_ok=True)


def obter_status():
    _garantir_state_dir()
    estado = ler_json(STATE_FILE, {"ativo": False, "iniciado_em": None})
    estado = dict(estado)
    estado["ips_bloqueados"] = len(carregar_blocklist())
    return estado


def ativar():
    _garantir_state_dir()
    novo_estado = {"ativo": True, "iniciado_em": datetime.now(timezone.utc).isoformat()}
    return modificar_json_com_lock(STATE_FILE, lambda _: novo_estado, padrao={})


def desativar():
    _garantir_state_dir()
    novo_estado = {"ativo": False, "parado_em": datetime.now(timezone.utc).isoformat()}
    return modificar_json_com_lock(STATE_FILE, lambda _: novo_estado, padrao={})


def carregar_blocklist():
    _garantir_state_dir()
    return ler_json(BLOCKLIST_FILE, {})


def bloquear_ip(ip, motivo="bloqueio manual", expira_em_horas=None):
    ip = normalizar_ip(ip)
    expira_em_horas = validar_expiracao(expira_em_horas)
    motivo = sanitizar_motivo(motivo)
    _garantir_state_dir()

    def _adicionar(blocklist_atual):
        blocklist_atual = dict(blocklist_atual)
        entrada = {"bloqueado_em": datetime.now(timezone.utc).isoformat(), "motivo": motivo}
        if expira_em_horas:
            entrada["expira_em_horas"] = expira_em_horas
        blocklist_atual[ip] = entrada
        return blocklist_atual

    novo_estado = modificar_json_com_lock(BLOCKLIST_FILE, _adicionar, padrao={})
    return novo_estado[ip]


def limpar_expirados():
    """Remove da blocklist entradas cujo prazo de expiracao ja passou.
    A leitura-verificacao-escrita inteira acontece dentro do lock, para
    nao haver janela entre 'checar quais expiraram' e 'escrever sem
    eles' onde outra thread poderia bloquear um IP que acabou de
    expirar e ter isso perdido."""
    _garantir_state_dir()
    removidos = []

    def _filtrar(blocklist_atual):
        nonlocal removidos
        agora = datetime.now(timezone.utc)
        restantes = {}
        for ip, info in blocklist_atual.items():
            try:
                horas = info["expira_em_horas"]
                bloqueado_em = datetime.fromisoformat(info["bloqueado_em"])
                if bloqueado_em.tzinfo is None:
                    bloqueado_em = bloqueado_em.replace(tzinfo=timezone.utc)
                expirou = (agora - bloqueado_em).total_seconds() / 3600 >= horas
            except (KeyError, TypeError, ValueError, AttributeError, OverflowError):
                expirou = False
            if expirou:
                removidos.append(ip)
            else:
                restantes[ip] = info
        return restantes

    modificar_json_com_lock(BLOCKLIST_FILE, _filtrar, padrao={})
    return removidos


def ip_bloqueado(ip):
    return ip in carregar_blocklist()


def registrar_alerta(ip, tipo_ataque, conteudo_resumo):
    _garantir_state_dir()
    linha = f"{datetime.now(timezone.utc).isoformat()} | {ip} | {tipo_ataque} | {conteudo_resumo}"
    append_linha_com_lock(ALERTS_FILE, linha)


def ler_alertas_recentes(limite=50):
    if not os.path.exists(ALERTS_FILE):
        return []
    with FileLock(ALERTS_FILE):
        with open(ALERTS_FILE) as f:
            linhas = f.readlines()
    return [l.strip() for l in linhas[-limite:]]


# 4b-1: indicacao interna de degradacao da consulta de IOC (alem do alerta).
# Reposto no arranque de cada `monitorar` e FIXO durante a execucao: nao volta
# a falso por uma consulta posterior bem-sucedida (evita oscilar com uma
# entrada ma isolada). `falhas` conta por `causa` (vocabulario fechado de
# core.ioc_cache). Nunca guarda caminhos, conteudo nem mensagens.
ESTADO_IOC = {"degradado": False, "falhas": {}, "ultima_falha_em": None}
_causas_ioc_sinalizadas = set()


def _reiniciar_estado_ioc():
    ESTADO_IOC.update(degradado=False, falhas={}, ultima_falha_em=None)
    _causas_ioc_sinalizadas.clear()


def _registar_falha_ioc(consulta, dry_run):
    """Cache de IOC ilegivel: o IP NAO e tratado como malicioso nem como
    sem correspondencia; o criterio de contagem continua. Regista o estado
    interno, imprime uma linha [IOC] e (fora de dry_run) emite UM alerta de
    infraestrutura por causa, uma vez por execucao do monitorar. Nunca
    levanta."""
    causa = consulta.causa
    ESTADO_IOC["degradado"] = True
    ESTADO_IOC["falhas"][causa] = ESTADO_IOC["falhas"].get(causa, 0) + 1
    ESTADO_IOC["ultima_falha_em"] = datetime.now(timezone.utc).isoformat()
    if causa in _causas_ioc_sinalizadas:
        return
    _causas_ioc_sinalizadas.add(causa)
    print(f"[IOC] cache de IOC ilegivel (causa={causa}); consulta de IOC desativada, criterio de contagem mantido")
    if dry_run:  # dry_run: sem efeito externo (so ecra + estado interno)
        return
    try:
        from core import security_runtime
        security_runtime.obter_alertador().alertar(
            "cache de IOC ilegivel; consulta de IOC desativada (watchdog)",
            {"componente": "watchdog", "onde": "ioc_cache", "causa": causa,
             "erro_classe": consulta.erro_classe},
            chave_dedup=("ioc_cache", causa))
    except Exception:
        pass


def _reconciliar_audit_na_partida():
    """3d-1 (Q6/P-D): reconcilia a fila de auditoria na partida de
    monitorar (inclui cada reinicio do `watch`). Nunca levanta. Falha
    parcial ou total NAO e fila vazia: avisa na tela e (no runtime) alerta;
    o watchdog continua detectando e cada acao protegida so executa com o
    seu evento duravel no principal ou na fila."""
    try:
        from core import security_runtime
        res = security_runtime.reconciliar_na_partida()
        if res.degradado:
            print(f"[AUDIT] reconciliacao da fila de auditoria {res.texto}")
    except Exception as exc:
        print(f"[AUDIT] reconciliacao da fila de auditoria falhou: {type(exc).__name__}")


def monitorar(log_file, intervalo=None, limite_alerta=None, dry_run=False):
    cfg = config.carregar()["defesa"]
    intervalo = intervalo or cfg["intervalo_padrao"]
    limite_alerta = limite_alerta or cfg["limite_alerta_padrao"]

    log_file = os.path.expanduser(log_file)
    if not os.path.exists(log_file):
        raise FileNotFoundError(f"Log não encontrado: {log_file}")

    _reiniciar_estado_ioc()
    ativar()
    print(t("monitorando", file=log_file))
    if not dry_run:  # dry_run nao tem efeito de audit: nada de reconciliar
        _reconciliar_audit_na_partida()

    posicao = os.path.getsize(log_file)
    contagem_ips = {}
    ignorados = set()

    try:
        while True:
            limpar_expirados()

            with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(posicao)
                novas_linhas = f.readlines()
                posicao = f.tell()

            if novas_linhas:
                analyzer = LogAnalyzer(log_file)
                analyzer.lines = novas_linhas
                findings = analyzer.analyze()

                for finding in findings:
                    ip = finding["ip"]
                    contagem_ips[ip] = contagem_ips.get(ip, 0) + 1
                    print("[ALERTA] " + t("alerta_ataque", tipo=finding["attack_name"], ip=ip, conteudo=finding["content"][:80]))
                    registrar_alerta(ip, finding["attack_name"], finding["content"][:120])

                    if not ip_bloqueado(ip):
                        cfg2 = config.carregar()
                        expira = cfg2.get("bloqueio_expira_horas_padrao")
                        motivo_bloqueio = None
                        categoria = None

                        # 4b-1: consulta que nunca levanta; ilegivel != ausente.
                        consulta = ioc_cache.consultar_malicioso(ip)
                        if consulta.estado == ioc_cache.ILEGIVEL:
                            _registar_falha_ioc(consulta, dry_run)

                        if consulta.estado == ioc_cache.ENCONTRADO and consulta.malicioso is True:
                            motivo_bloqueio = "IOC conhecido malicioso (cache)"
                            categoria = "ioc_conhecido"
                        elif contagem_ips[ip] >= limite_alerta:
                            motivo_bloqueio = f"{contagem_ips[ip]} tentativas detectadas em tempo real"
                            categoria = "contagem"

                        if motivo_bloqueio:
                            if dry_run:
                                print(f"[DRY-RUN] Seria bloqueado: {ip} — {motivo_bloqueio}")
                            else:
                                # 3d-1: bloqueio pelo ciclo de SecurityAction (audit duravel +
                                # Policy + Executor). Divida de autorizacao C1/G4: ver
                                # core/security_watchdog.py (pendencia do Passo 4).
                                from core import security_watchdog
                                resultado = security_watchdog.tentar_bloqueio(
                                    ip, categoria, motivo_bloqueio, expira)
                                if resultado.ignorado:
                                    if ip not in ignorados:
                                        ignorados.add(ip)
                                        print(f"[IGNORADO] {ip} não foi bloqueado: {resultado.mensagem}")
                                    continue
                                if not resultado.bloqueado:
                                    continue
                                print(f"[BLOQUEIO] {ip} — {motivo_bloqueio}")
                                notify.enviar(
                                    f"Moracle bloqueou {ip}: {motivo_bloqueio}",
                                    dados_extra={"ip": ip, "motivo": motivo_bloqueio}
                                )

            time.sleep(intervalo)
    except KeyboardInterrupt:
        desativar()
        print("\n" + t("monitoramento_interrompido"))
