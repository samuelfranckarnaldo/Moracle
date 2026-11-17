"""Passo 3d-0 - testes de CARACTERIZACAO de defense.monitorar() e do watchdog.

Travam o comportamento ATUAL (antes de ligar o watchdog ao ciclo de
SecurityAction). Devem passar no codigo de producao como esta e
continuar passando depois da 3d-1, exceto onde a 3d-1 declarar uma
mudanca explicita. Nao alteram nenhum modulo de producao.

Tecnica: `monitorar` roda para sempre; o `time.sleep` do modulo
defense e trocado por um stub que, a cada chamada, acrescenta ao log o
proximo lote de linhas e, esgotados os lotes, levanta KeyboardInterrupt
(que o loop ja trata, encerrando normalmente).
"""
import contextlib
import io
import types

import pytest

from core import defense, ioc_cache, whitelist
from core import watchdog
from tests.helpers.audit_fakes import isolar_config

pytestmark = pytest.mark.usefixtures("estado_isolado")

MODELO = '{ip} - - [-] "GET /product?id=1 UNION SELECT NULL-- HTTP/1.1" 200 0 "-" "curl/8.0"\n'


def _linha(ip):
    return MODELO.format(ip=ip)


@pytest.fixture(autouse=True)
def _zerar_espera_do_watchdog():
    """A espera do watchdog e estado de processo (3d-1): zerar por teste."""
    from core import security_watchdog
    security_watchdog.reiniciar_estado()
    yield
    security_watchdog.reiniciar_estado()


@pytest.fixture
def ambiente(monkeypatch, tmp_path):
    """Config e estado isolados, whitelist vazia, notify.enviar espionado."""
    cfg = isolar_config(monkeypatch, tmp_path)
    monkeypatch.setattr(whitelist, "_compilados", [])
    notificacoes = []

    def espiao(mensagem, dados_extra=None):
        notificacoes.append((mensagem, dados_extra))
        return False
    monkeypatch.setattr(defense.notify, "enviar", espiao)
    return types.SimpleNamespace(cfg=cfg, notificacoes=notificacoes,
                                 log=tmp_path / "acesso.log", mp=monkeypatch)


def _rodar(amb, lotes, limite, dry_run=False, durante=None):
    """Roda monitorar() com os lotes de linhas e devolve o stdout.
    `durante`, se dado, e chamado na 1a pausa (loop ativo)."""
    amb.log.write_text("")
    chamadas = {"n": 0}

    def sleep_falso(_segundos):
        chamadas["n"] += 1
        if chamadas["n"] == 1 and durante is not None:
            durante()
        if chamadas["n"] <= len(lotes):
            with open(amb.log, "a", encoding="utf-8") as f:
                f.write("".join(lotes[chamadas["n"] - 1]))
            return
        raise KeyboardInterrupt

    amb.mp.setattr(defense, "time", types.SimpleNamespace(sleep=sleep_falso))
    saida = io.StringIO()
    with contextlib.redirect_stdout(saida):
        defense.monitorar(str(amb.log), intervalo=0.01, limite_alerta=limite, dry_run=dry_run)
    return saida.getvalue()


# 1 ---------------------------------------------------------------------
def test_contagem_no_limite_bloqueia_com_motivo_e_sem_expiracao_por_padrao(ambiente):
    ip = "203.0.113.9"
    saida = _rodar(ambiente, [[_linha(ip)] * 3], limite=3)
    bl = defense.carregar_blocklist()
    assert ip in bl
    assert bl[ip]["motivo"] == "3 tentativas detectadas em tempo real"
    assert "expira_em_horas" not in bl[ip]
    assert "[BLOQUEIO] %s" % ip in saida


def test_expiracao_padrao_da_config_e_aplicada_ao_bloqueio(ambiente):
    ambiente.cfg["bloqueio_expira_horas_padrao"] = 2
    ip = "203.0.113.11"
    _rodar(ambiente, [[_linha(ip)] * 2], limite=2)
    assert defense.carregar_blocklist()[ip]["expira_em_horas"] == 2


# 2 ---------------------------------------------------------------------
def test_ioc_conhecido_bloqueia_na_primeira_ocorrencia(ambiente):
    ip = "203.0.113.10"
    ioc_cache.guardar(ip, {"fonte": "teste"}, malicioso=True)
    saida = _rodar(ambiente, [[_linha(ip)]], limite=99)
    bl = defense.carregar_blocklist()
    assert bl[ip]["motivo"] == "IOC conhecido malicioso (cache)"
    assert "[BLOQUEIO] %s" % ip in saida


def test_ioc_nao_malicioso_nao_bloqueia(ambiente):
    ip = "203.0.113.12"
    ioc_cache.guardar(ip, {}, malicioso=False)
    _rodar(ambiente, [[_linha(ip)]], limite=99)
    assert ip not in defense.carregar_blocklist()


# 3 ---------------------------------------------------------------------
def test_abaixo_do_limite_nao_bloqueia_mas_todo_achado_gera_alerta(ambiente):
    ip = "203.0.113.13"
    saida = _rodar(ambiente, [[_linha(ip)] * 2], limite=3)
    assert ip not in defense.carregar_blocklist()
    alertas = defense.ler_alertas_recentes(50)
    assert len(alertas) == 2
    assert all(("| %s |" % ip) in a for a in alertas)
    assert saida.count("[ALERTA]") == 2
    assert "[BLOQUEIO]" not in saida


# 4 ---------------------------------------------------------------------
def test_ip_ja_bloqueado_nao_e_bloqueado_de_novo_mas_alerta_continua(ambiente):
    ip = "203.0.113.20"
    defense.bloquear_ip(ip, motivo="previo")
    saida = _rodar(ambiente, [[_linha(ip)] * 3], limite=1)
    assert defense.carregar_blocklist()[ip]["motivo"] == "previo"  # nao sobrescrito
    assert len(defense.ler_alertas_recentes(50)) == 3
    assert "[BLOQUEIO]" not in saida
    assert ambiente.notificacoes == []


# 5 ---------------------------------------------------------------------
def test_dry_run_imprime_nao_bloqueia_e_registra_alerta(ambiente):
    ip = "203.0.113.21"
    saida = _rodar(ambiente, [[_linha(ip)] * 2], limite=2, dry_run=True)
    assert ip not in defense.carregar_blocklist()
    assert "[DRY-RUN] Seria bloqueado: %s" % ip in saida
    assert len(defense.ler_alertas_recentes(50)) == 2
    assert "[BLOQUEIO]" not in saida
    assert ambiente.notificacoes == []


def test_dry_run_nao_valida_ip_e_imprime_mesmo_para_loopback(ambiente):
    # comportamento atual: o ramo dry_run vem ANTES de qualquer validacao
    saida = _rodar(ambiente, [[_linha("127.0.0.1")]], limite=1, dry_run=True)
    assert "[DRY-RUN] Seria bloqueado: 127.0.0.1" in saida
    assert "[IGNORADO]" not in saida


# 6 ---------------------------------------------------------------------
def test_ip_loopback_imprime_ignorado_uma_vez_e_nunca_bloqueia(ambiente):
    ip = "127.0.0.1"
    saida = _rodar(ambiente, [[_linha(ip)] * 2, [_linha(ip)] * 2], limite=1)
    assert ip not in defense.carregar_blocklist()
    assert saida.count("[IGNORADO] %s" % ip) == 1
    assert "[BLOQUEIO]" not in saida
    assert len(defense.ler_alertas_recentes(50)) == 4  # o loop continuou
    assert ambiente.notificacoes == []


# 7 ---------------------------------------------------------------------
def test_notify_e_chamado_com_mensagem_e_dados_depois_do_bloqueio(ambiente):
    ip = "203.0.113.30"
    _rodar(ambiente, [[_linha(ip)] * 2], limite=2)
    motivo = "2 tentativas detectadas em tempo real"
    assert ambiente.notificacoes == [
        ("Moracle bloqueou %s: %s" % (ip, motivo), {"ip": ip, "motivo": motivo})]


def test_notify_nao_e_chamado_quando_nao_ha_bloqueio(ambiente):
    _rodar(ambiente, [[_linha("203.0.113.31")]], limite=5)
    assert ambiente.notificacoes == []


# 8 ---------------------------------------------------------------------
def test_ips_diferentes_tem_contagens_independentes(ambiente):
    a, b = "203.0.113.40", "203.0.113.41"
    _rodar(ambiente, [[_linha(a), _linha(b), _linha(a)]], limite=2)
    bl = defense.carregar_blocklist()
    assert a in bl and b not in bl


# 9 ---------------------------------------------------------------------
def test_keyboardinterrupt_chama_desativar_e_o_loop_estava_ativo(ambiente):
    ativos = []
    saida = _rodar(ambiente, [[_linha("203.0.113.50")]], limite=9,
                   durante=lambda: ativos.append(defense.obter_status()["ativo"]))
    assert ativos == [True]
    assert defense.obter_status()["ativo"] is False
    from core.i18n import t
    assert t("monitoramento_interrompido") in saida


def test_arquivo_de_log_inexistente_levanta_filenotfound(ambiente):
    with pytest.raises(FileNotFoundError):
        defense.monitorar(str(ambiente.log) + ".nao-existe", intervalo=0.01, limite_alerta=1)


# 3d-0b -----------------------------------------------------------------
def test_erro_inesperado_de_bloquear_ip_nao_derruba_o_monitorar__mudanca_declarada_3d1(ambiente):
    """REESCRITO NA 3d-1 DE PROPOSITO (decisao P-E; antes: a excecao propagava).

    Comportamento ANTERIOR (travado na 3d-0b): so ValueError era capturado
    em monitorar(); um OSError de bloquear_ip subia, derrubava o loop e o
    `watch` reiniciava com a posicao de leitura no fim do arquivo (linhas
    do intervalo perdidas). Comportamento NOVO: o bloqueio passa pelo ciclo;
    o erro vira FALHA_EXECUCAO + alerta e o loop CONTINUA. Detalhes em
    tests/test_security_watchdog.py."""
    ip = "203.0.113.60"

    def bloquear_quebrado(*args, **kwargs):
        raise OSError("disco cheio simulado")

    ambiente.mp.setattr(defense, "bloquear_ip", bloquear_quebrado)
    saida = _rodar(ambiente, [[_linha(ip)]], limite=1)  # nao levanta mais
    assert ip not in defense.carregar_blocklist()
    assert "[BLOQUEIO]" not in saida
    assert "[FALHA-EXECUCAO] %s" % ip in saida and "OSError" in saida
    assert [m for m, _ in ambiente.notificacoes if m.startswith("Moracle bloqueou")] == []


def test_expiracao_padrao_invalida_imprime_ignorado_uma_vez_e_nao_bloqueia(ambiente):
    ambiente.cfg["bloqueio_expira_horas_padrao"] = -5
    ip = "203.0.113.61"
    saida = _rodar(ambiente, [[_linha(ip)] * 2, [_linha(ip)]], limite=1)
    assert saida.count("[IGNORADO] %s" % ip) == 1
    assert "[IGNORADO] %s não foi bloqueado: expires_hours deve ser positivo e finito" % ip in saida
    assert ip not in defense.carregar_blocklist()
    assert "[BLOQUEIO]" not in saida
    assert ambiente.notificacoes == []
    assert len(defense.ler_alertas_recentes(50)) == 3  # o loop continuou


def test_ioc_prevalece_sobre_contagem_na_escolha_do_motivo(ambiente):
    ip = "203.0.113.62"
    ioc_cache.guardar(ip, {}, malicioso=True)
    # limite=1: a contagem TAMBEM qualificaria; o motivo mostra quem vence
    _rodar(ambiente, [[_linha(ip)]], limite=1)
    assert defense.carregar_blocklist()[ip]["motivo"] == "IOC conhecido malicioso (cache)"


# 10 --------------------------------------------------------------------
def test_watchdog_reinicia_apos_excecao_e_sai_limpo_quando_monitorar_retorna(monkeypatch):
    chamadas = []
    esperas = []

    def monitorar_falso(log_file, intervalo=None, limite_alerta=None):
        chamadas.append((log_file, intervalo, limite_alerta))
        if len(chamadas) == 1:
            raise RuntimeError("falha simulada")

    monkeypatch.setattr(watchdog.defense, "monitorar", monitorar_falso)
    monkeypatch.setattr(watchdog, "time", types.SimpleNamespace(sleep=esperas.append))
    saida, erro = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(saida), contextlib.redirect_stderr(erro):
        watchdog.rodar_com_reinicio("x.log", intervalo=3, limite_alerta=4, espera_reinicio=7)
    assert len(chamadas) == 2
    assert chamadas == [("x.log", 3, 4), ("x.log", 3, 4)]
    assert esperas == [7]
    assert "[WATCHDOG]" in saida.getvalue()


def test_watchdog_espera_5_segundos_por_padrao_antes_de_reiniciar(monkeypatch):
    chamadas = []
    esperas = []

    def monitorar_falso(log_file, intervalo=None, limite_alerta=None):
        chamadas.append(1)
        if len(chamadas) == 1:
            raise RuntimeError("falha simulada")

    monkeypatch.setattr(watchdog.defense, "monitorar", monitorar_falso)
    monkeypatch.setattr(watchdog, "time", types.SimpleNamespace(sleep=esperas.append))
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        watchdog.rodar_com_reinicio("x.log")
    assert esperas == [5]


def test_watchdog_sai_sem_reiniciar_com_keyboardinterrupt(monkeypatch):
    chamadas = []

    def monitorar_falso(log_file, intervalo=None, limite_alerta=None):
        chamadas.append(1)
        raise KeyboardInterrupt

    monkeypatch.setattr(watchdog.defense, "monitorar", monitorar_falso)
    monkeypatch.setattr(watchdog, "time", types.SimpleNamespace(
        sleep=lambda s: (_ for _ in ()).throw(AssertionError("nao devia esperar"))))
    watchdog.rodar_com_reinicio("x.log")
    assert chamadas == [1]


def test_watchdog_nao_passa_dry_run_ao_monitorar(monkeypatch):
    # #3-B: `watch` nao tem dry_run; a chamada so leva estes tres argumentos
    kwargs_vistos = []

    def monitorar_falso(log_file, **kwargs):
        kwargs_vistos.append(set(kwargs))

    monkeypatch.setattr(watchdog.defense, "monitorar", monitorar_falso)
    watchdog.rodar_com_reinicio("x.log", intervalo=1, limite_alerta=2)
    assert kwargs_vistos == [{"intervalo", "limite_alerta"}]
