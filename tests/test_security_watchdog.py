"""Passo 3d-1 - watchdog ligado ao ciclo de SecurityAction + estados de
reconciliacao.

Cobre as decisoes P-A..P-E/K1 e as tres condicoes adicionais do Gate #6:
causas distintas (audit / execucao / perda de rastreabilidade), excecao
da Policy nunca autoriza, `watch` e C1/G4 intocados. A divida C1/G4 esta
documentada em core/security_watchdog.py (pendencia do Passo 4).

Tecnica de `monitorar` como em test_defense_monitorar_caracterizacao.py:
`defense.time.sleep` vira um stub que executa um PASSO por chamada
(acrescentar linhas ao log, executar um callable, simular queda) e, esgotados
os passos, levanta KeyboardInterrupt.
"""
import contextlib
import io
import json
import os
import stat
import types

import pytest

from core import defense, ioc_cache, whitelist, watchdog
from core import security_audit as sa
from core import security_policy as P
from core import security_runtime as rt
from core import security_watchdog as W
from tests.helpers.audit_fakes import isolar_config

pytestmark = pytest.mark.usefixtures("estado_isolado")

MODELO = '{ip} - - [-] "GET /product?id=1 UNION SELECT NULL-- HTTP/1.1" 200 0 "-" "curl/8.0"\n'
CRASH = "CRASH"


def _linha(ip):
    return MODELO.format(ip=ip)


class DestinoPorTipo:
    """Destino falso: interface gravar(evento)->bool, falha por tipo ou total."""

    def __init__(self, falhar=False, falhar_em=()):
        self.falhar = falhar
        self.falhar_em = set(falhar_em)
        self.eventos = []
        self.tentativas = 0
        self.ultimo_erro = None

    def gravar(self, evento):
        self.tentativas += 1
        if self.falhar or evento["event_type"] in self.falhar_em:
            self.ultimo_erro = "OSError"
            return False
        self.eventos.append(evento)
        self.ultimo_erro = None
        return True

    def esta_vazia(self):
        return True


class PrincipalInstavel(sa.DestinoJsonl):
    """Principal em disco que pode ser derrubado sob comando."""
    falhar = False

    def gravar(self, evento):
        if self.falhar:
            self.ultimo_erro = "OSError"
            return False
        return super().gravar(evento)


@pytest.fixture(autouse=True)
def _zerar_espera_do_watchdog():
    W.reiniciar_estado()
    yield
    W.reiniciar_estado()


@pytest.fixture
def amb(monkeypatch, tmp_path):
    cfg = isolar_config(monkeypatch, tmp_path)
    monkeypatch.setattr(whitelist, "_compilados", [])
    notificacoes = []

    def espiao(mensagem, dados_extra=None):
        notificacoes.append((mensagem, dados_extra))
        return False
    monkeypatch.setattr(defense.notify, "enviar", espiao)

    alertador = sa.Alertador()
    monkeypatch.setattr(rt, "_alertador", alertador)
    principal, fila = DestinoPorTipo(), DestinoPorTipo()
    chamadas_fabrica = []

    def fabrica():
        chamadas_fabrica.append(1)
        return sa.Auditor(principal, fila, alertador=alertador)
    monkeypatch.setattr(rt, "fabrica_auditor", fabrica)

    relogio = [1000.0]
    monkeypatch.setattr(W, "_relogio", lambda: relogio[0])
    return types.SimpleNamespace(
        cfg=cfg, notificacoes=notificacoes, log=tmp_path / "acesso.log", mp=monkeypatch,
        principal=principal, fila=fila, alertador=alertador, relogio=relogio,
        fabrica=fabrica, chamadas_fabrica=chamadas_fabrica)


def _executar(a, passos, chamada):
    a.log.write_text("")
    n = {"i": 0}

    def sleep_falso(_s):
        i = n["i"]
        n["i"] += 1
        if i >= len(passos):
            raise KeyboardInterrupt
        passo = passos[i]
        if callable(passo):
            passo()
        elif passo == CRASH:
            raise RuntimeError("queda simulada")
        else:
            with open(a.log, "a", encoding="utf-8") as f:
                f.write("".join(passo))

    a.mp.setattr(defense, "time", types.SimpleNamespace(sleep=sleep_falso))
    a.mp.setattr(watchdog, "time", types.SimpleNamespace(sleep=lambda s: None))
    saida, erro = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(saida), contextlib.redirect_stderr(erro):
        chamada()
    return saida.getvalue(), erro.getvalue()


def _rodar(a, passos, limite=1, dry_run=False):
    return _executar(a, passos, lambda: defense.monitorar(
        str(a.log), intervalo=0.01, limite_alerta=limite, dry_run=dry_run))


def _alertas(erro):
    return [l for l in erro.splitlines() if l.startswith("[MORACLE AUDIT]")]


def _tipos(destino):
    return [e["event_type"] for e in destino.eventos]


def _bloqueios_notificados(a):
    return [m for m, _ in a.notificacoes if m.startswith("Moracle bloqueou")]


def _avancar(a, segundos):
    return lambda: a.relogio.__setitem__(0, a.relogio[0] + segundos)


# ------------------------------------------------------------ caminho feliz

def test_ioc_bloqueia_pelo_ciclo_com_actor_automatico_sem_identity(amb):
    ip = "198.51.100.1"
    ioc_cache.guardar(ip, {}, malicioso=True)
    saida, erro = _rodar(amb, [[_linha(ip)]], limite=99)
    assert defense.ip_bloqueado(ip)
    assert _tipos(amb.principal) == ["PROPOSTA", "AUTORIZADA", "EXECUTADA"]
    assert len({e["decision_id"] for e in amb.principal.eventos}) == 1
    ev = amb.principal.eventos[0]
    assert ev["actor"]["automatic"] == "watchdog"
    assert "identity" not in ev["actor"]
    assert ev["origin"] == "automatic:watchdog"
    assert "correlation_id" not in ev
    assert "risk" not in ev["payload"]
    assert ev["payload"]["source"] == {"type": "automatico", "id": "watchdog"}
    assert ev["payload"]["target"] == {"type": "ip", "id": ip}
    assert ev["payload"]["reason"] == "IOC conhecido malicioso (cache)"
    assert amb.fila.eventos == []
    assert "[BLOQUEIO] %s" % ip in saida
    assert _bloqueios_notificados(amb) == ["Moracle bloqueou %s: IOC conhecido malicioso (cache)" % ip]
    assert erro == ""


def test_contagem_bloqueia_pelo_ciclo_e_o_motivo_completo_fica_no_evento(amb):
    ip = "198.51.100.2"
    _rodar(amb, [[_linha(ip)] * 2], limite=2)
    assert defense.ip_bloqueado(ip)
    assert amb.principal.eventos[0]["payload"]["reason"] == "2 tentativas detectadas em tempo real"


def test_expiracao_padrao_da_config_chega_ao_bloqueio(amb):
    amb.cfg["bloqueio_expira_horas_padrao"] = 3
    ip = "198.51.100.3"
    _rodar(amb, [[_linha(ip)]], limite=1)
    assert defense.carregar_blocklist()[ip]["expira_em_horas"] == 3


# ------------------------------------------- falha do principal, fila, disco

def test_principal_falha_fila_aceita_executa_e_reinicio_reconcilia_sem_duplicar(amb):
    principal = PrincipalInstavel(sa.caminho_eventos)
    fila = sa.FilaDuravel(sa.caminho_fila)
    alerta = amb.alertador
    amb.mp.setattr(rt, "fabrica_auditor", lambda: sa.Auditor(principal, fila, alertador=alerta))
    ip = "198.51.100.4"
    principal.falhar = True
    saida, erro = _rodar(amb, [[_linha(ip)]], limite=1)
    assert defense.ip_bloqueado(ip) and "[BLOQUEIO] %s" % ip in saida
    assert [e["event_type"] for e in fila.ler_eventos()] == ["PROPOSTA", "AUTORIZADA", "EXECUTADA"]
    assert principal.ler_eventos() == [] and _alertas(erro) == []
    assert stat.S_IMODE(os.stat(fila.caminho()).st_mode) == 0o600

    principal.falhar = False
    saida2, _ = _rodar(amb, [])  # novo monitorar = reinicio: reconcilia na partida
    movidos = principal.ler_eventos()
    assert [(e["event_type"], e["seq"]) for e in movidos] == [("PROPOSTA", 1), ("AUTORIZADA", 2), ("EXECUTADA", 3)]
    assert len({e["decision_id"] for e in movidos}) == 1
    assert all("reconciled_at" in e for e in movidos)
    assert fila.esta_vazia()
    assert stat.S_IMODE(os.stat(principal.caminho()).st_mode) == 0o600
    assert "[AUDIT]" not in saida2
    _rodar(amb, [])  # idempotente: nada novo para reconciliar
    assert len(principal.ler_eventos()) == 3


# ---------------------------------------------------- audit indisponivel

def test_audit_indisponivel_nao_bloqueia_alerta_uma_vez_e_separa_canais(amb):
    ip = "198.51.100.5"
    amb.principal.falhar = amb.fila.falhar = True
    saida, erro = _rodar(amb, [[_linha(ip)]], limite=1)
    assert not defense.ip_bloqueado(ip)
    assert amb.principal.eventos == [] and amb.fila.eventos == []
    assert "[AUDIT-INDISPONIVEL] %s" % ip in saida and "[BLOQUEIO]" not in saida
    assert len(_alertas(erro)) == 1 and "falha de auditoria" in _alertas(erro)[0]
    assert _bloqueios_notificados(amb) == []
    linhas_alerts_log = defense.ler_alertas_recentes(50)
    assert len(linhas_alerts_log) == 1 and "auditoria" not in linhas_alerts_log[0]  # so o alerta de deteccao


def test_espera_no_mesmo_par_nao_cria_decisao_evento_nem_alerta(amb):
    ip = "198.51.100.6"
    amb.principal.falhar = amb.fila.falhar = True
    saida, erro = _rodar(amb, [[_linha(ip)], [_linha(ip)], [_linha(ip)]], limite=1)
    assert amb.principal.tentativas == 1 and amb.fila.tentativas == 1  # uma unica tentativa
    assert saida.count("[AUDIT-INDISPONIVEL]") == 1
    assert len(_alertas(erro)) == 1


def test_chave_e_ip_e_categoria_nao_o_texto_do_motivo(amb):
    ip = "198.51.100.7"
    amb.principal.falhar = amb.fila.falhar = True
    # contagem 1 e 2: o motivo muda ("1 tentativas..." / "2 tentativas...")
    _rodar(amb, [[_linha(ip), _linha(ip)]], limite=1)
    assert amb.principal.tentativas == 1


def test_apos_60s_ha_nova_tentativa_com_novo_decision_id_e_sucesso(amb):
    ip = "198.51.100.8"
    amb.principal.falhar = amb.fila.falhar = True

    def curar():
        amb.principal.falhar = amb.fila.falhar = False
        amb.relogio[0] += W.ESPERA_SEGUNDOS + 1
    saida, erro = _rodar(amb, [[_linha(ip)], curar, [_linha(ip)]], limite=1)
    assert defense.ip_bloqueado(ip) and "[BLOQUEIO] %s" % ip in saida
    assert _tipos(amb.principal) == ["PROPOSTA", "AUTORIZADA", "EXECUTADA"]
    assert len(_alertas(erro)) == 1  # a falha inicial foi alertada uma vez


def test_espera_de_59s_ainda_bloqueia_e_de_60s_libera(amb):
    ip = "198.51.100.9"
    amb.principal.falhar = amb.fila.falhar = True
    _rodar(amb, [[_linha(ip)], _avancar(amb, 59), [_linha(ip)]], limite=1)
    assert amb.principal.tentativas == 1
    _rodar(amb, [_avancar(amb, 1), [_linha(ip)]], limite=1)  # total 60s desde a falha
    assert amb.principal.tentativas == 2


def test_falha_continua_apos_a_espera_tenta_de_novo_mas_nao_repete_o_alerta(amb):
    ip = "198.51.100.10"
    amb.principal.falhar = amb.fila.falhar = True
    saida, erro = _rodar(amb, [[_linha(ip)], _avancar(amb, 61), [_linha(ip)]], limite=1)
    assert amb.principal.tentativas == 2           # a espera nao e Policy: tenta de novo
    assert saida.count("[AUDIT-INDISPONIVEL]") == 2
    assert len(_alertas(erro)) == 1                 # K1: um alerta inicial por (ip, categoria)


def test_outro_ip_nao_herda_a_espera(amb):
    a, b = "198.51.100.11", "198.51.100.12"
    amb.principal.falhar = amb.fila.falhar = True
    _, erro = _rodar(amb, [[_linha(a), _linha(b)]], limite=1)
    assert amb.principal.tentativas == 2
    assert len(_alertas(erro)) == 2


def test_categorias_do_mesmo_ip_sao_independentes(amb):
    ip = "198.51.100.13"
    amb.principal.falhar = amb.fila.falhar = True
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        W.tentar_bloqueio(ip, W.CATEGORIA_IOC, "ioc", None)
        W.tentar_bloqueio(ip, W.CATEGORIA_CONTAGEM, "contagem", None)
        W.tentar_bloqueio(ip, W.CATEGORIA_IOC, "ioc", None)  # em espera
    assert amb.principal.tentativas == 2


def test_alerta_e_limpo_na_recuperacao_e_uma_falha_posterior_alerta_de_novo(amb):
    ip = "198.51.100.14"
    erro = io.StringIO()
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(erro):
        amb.principal.falhar = amb.fila.falhar = True
        W.tentar_bloqueio(ip, W.CATEGORIA_CONTAGEM, "x", None)
        amb.principal.falhar = amb.fila.falhar = False
        amb.relogio[0] += 61
        r = W.tentar_bloqueio(ip, W.CATEGORIA_CONTAGEM, "x", None)
        assert r.bloqueado and not r.perda_de_rastreabilidade
        # o bloqueio expirou/foi removido; o audit volta a cair
        defense.modificar_json_com_lock(defense.BLOCKLIST_FILE, lambda b: {}, padrao={})
        amb.principal.falhar = amb.fila.falhar = True
        amb.relogio[0] += 61
        W.tentar_bloqueio(ip, W.CATEGORIA_CONTAGEM, "x", None)
    assert len(_alertas(erro.getvalue())) == 2


# ------------------------------------------------------ validacao previa

def test_ip_invalido_ou_nao_bloqueavel_ignorado_sem_evento_alerta_nem_auditor(amb):
    ip = "127.0.0.1"
    saida, erro = _rodar(amb, [[_linha(ip)] * 2, [_linha(ip)]], limite=1)
    assert saida.count("[IGNORADO] %s" % ip) == 1
    assert amb.principal.tentativas == 0 and amb.fila.tentativas == 0
    assert _alertas(erro) == [] and amb.chamadas_fabrica == [1]  # so a reconciliacao da partida
    assert not defense.ip_bloqueado(ip)


def test_expiracao_padrao_invalida_ignorada_sem_evento_documentado_face_ao_block(amb):
    # DIFERENCA DECLARADA face ao /block da 3c: la a expiracao invalida gera
    # PROPOSTA/AUTORIZADA/FALHA_EXECUCAO; no watchdog (loop) valida-se antes
    # do Registry para nao gerar eventos a cada linha de log.
    amb.cfg["bloqueio_expira_horas_padrao"] = -5
    ip = "198.51.100.15"
    saida, erro = _rodar(amb, [[_linha(ip)] * 2], limite=1)
    assert saida.count("[IGNORADO] %s não foi bloqueado: expires_hours deve ser positivo e finito" % ip) == 1
    assert amb.principal.tentativas == 0 and _alertas(erro) == []
    assert not defense.ip_bloqueado(ip)


# --------------------------------------------------------------- dry_run

def test_dry_run_nao_cria_auditor_nem_reconcilia_nem_gera_eventos(amb):
    ip = "198.51.100.16"
    fila = sa.FilaDuravel(sa.caminho_fila)
    pendente = sa.novo_evento("config.changed", "success", payload={"k": 1}, origin="cli-local")
    assert fila.gravar(pendente)
    tamanho = os.path.getsize(fila.caminho())
    saida, erro = _rodar(amb, [[_linha(ip)]], limite=1, dry_run=True)
    assert "[DRY-RUN] Seria bloqueado: %s" % ip in saida
    assert amb.chamadas_fabrica == [] and amb.principal.tentativas == 0
    assert os.path.getsize(fila.caminho()) == tamanho  # fila intocada
    assert not defense.ip_bloqueado(ip) and erro == ""


# ----------------------------------------------- orfa / resultado perdido

def test_decisao_orfa_nao_executa_e_a_nova_tentativa_usa_outro_decision_id(amb):
    ip = "198.51.100.17"
    amb.principal.falhar_em = {"AUTORIZADA"}
    amb.fila.falhar_em = {"AUTORIZADA"}

    def curar():
        amb.principal.falhar_em = set()
        amb.fila.falhar_em = set()
        amb.relogio[0] += 61
    saida, erro = _rodar(amb, [[_linha(ip)], curar, [_linha(ip)]], limite=1)
    eventos = amb.principal.eventos
    assert [e["event_type"] for e in eventos] == ["PROPOSTA", "PROPOSTA", "AUTORIZADA", "EXECUTADA"]
    d1, d2 = eventos[0]["decision_id"], eventos[1]["decision_id"]
    assert d1 != d2 and {e["decision_id"] for e in eventos[1:]} == {d2}
    assert len(_alertas(erro)) == 1 and defense.ip_bloqueado(ip)


def test_resultado_gravado_so_na_fila_bloqueia_normalmente_sem_falha_de_execucao(amb):
    ip = "198.51.100.18"
    amb.principal.falhar_em = {"EXECUTADA"}
    saida, erro = _rodar(amb, [[_linha(ip)]], limite=1)
    assert defense.ip_bloqueado(ip) and "[BLOQUEIO] %s" % ip in saida
    assert _tipos(amb.fila) == ["EXECUTADA"]
    assert "FALHA_EXECUCAO" not in _tipos(amb.principal) + _tipos(amb.fila)
    assert len(_bloqueios_notificados(amb)) == 1 and _alertas(erro) == []


def test_resultado_perdido_nos_dois_e_perda_de_rastreabilidade_nao_falha_de_execucao(amb):
    ip = "198.51.100.19"
    amb.principal.falhar_em = {"EXECUTADA"}
    amb.fila.falhar_em = {"EXECUTADA"}
    saida, erro = _rodar(amb, [[_linha(ip)]], limite=1)
    assert defense.ip_bloqueado(ip)                               # a acao ocorreu
    assert "[BLOQUEIO] %s" % ip in saida and "[RASTREABILIDADE] %s" % ip in saida
    assert "[FALHA-EXECUCAO]" not in saida and "[AUDIT-INDISPONIVEL]" not in saida
    assert _tipos(amb.principal) == ["PROPOSTA", "AUTORIZADA"]    # EXECUTADA nao gravada
    assert "FALHA_EXECUCAO" not in _tipos(amb.principal) + _tipos(amb.fila)
    alertas = _alertas(erro)
    assert len(alertas) == 1 and "perda de rastreabilidade" in alertas[0]
    assert len(_bloqueios_notificados(amb)) == 1                  # notificacao normal de bloqueio


def test_alerta_de_perda_de_rastreabilidade_nao_e_suprimido_pelo_alerta_anterior_de_audit(amb):
    ip = "198.51.100.27"
    amb.principal.falhar = amb.fila.falhar = True

    def curar_so_ate_a_autorizacao():
        amb.principal.falhar = amb.fila.falhar = False
        amb.principal.falhar_em = {"EXECUTADA"}
        amb.fila.falhar_em = {"EXECUTADA"}
        amb.relogio[0] += 61
    saida, erro = _rodar(amb, [[_linha(ip)], curar_so_ate_a_autorizacao, [_linha(ip)]], limite=1)
    alertas = _alertas(erro)
    assert len(alertas) == 2                       # causas distintas, chaves distintas
    assert "falha de auditoria" in alertas[0] and "perda de rastreabilidade" in alertas[1]
    assert defense.ip_bloqueado(ip) and "[RASTREABILIDADE] %s" % ip in saida


# ------------------------------------------------ execucao e Policy (P-E)

def test_falha_de_execucao_registra_alerta_e_o_monitorar_continua(amb):
    ip = "198.51.100.20"

    def bloquear_quebrado(*a, **k):
        raise OSError("/data/segredo/disco cheio")
    amb.mp.setattr(defense, "bloquear_ip", bloquear_quebrado)
    saida, erro = _rodar(amb, [[_linha(ip)], [_linha(ip)]], limite=1)  # NAO levanta
    assert _tipos(amb.principal) == ["PROPOSTA", "AUTORIZADA", "FALHA_EXECUCAO"]
    assert amb.principal.eventos[-1]["payload"]["error_class"] == "OSError"
    assert "segredo" not in json.dumps(amb.principal.eventos) + saida + erro
    assert not defense.ip_bloqueado(ip) and "[BLOQUEIO]" not in saida
    assert "[FALHA-EXECUCAO] %s" % ip in saida and "[AUDIT-INDISPONIVEL]" not in saida
    alertas = _alertas(erro)
    assert len(alertas) == 1 and "falha de execucao" in alertas[0]
    assert _bloqueios_notificados(amb) == []
    assert saida.count("[FALHA-EXECUCAO]") == 1                    # segunda linha: em espera


def test_excecao_da_policy_nao_autoriza_nao_executa_sinaliza_e_o_loop_continua(amb):
    a, b = "198.51.100.21", "198.51.100.22"

    class PolicyQuebrada:
        def avaliar(self, action):
            raise RuntimeError("bug na policy")
    amb.mp.setattr(rt, "policy", PolicyQuebrada())
    saida, erro = _rodar(amb, [[_linha(a)], [_linha(b)]], limite=1)
    assert not defense.ip_bloqueado(a) and not defense.ip_bloqueado(b)   # nunca vira autorizacao
    assert _tipos(amb.principal) == ["PROPOSTA", "PROPOSTA"]            # sem AUTORIZADA, sem estado novo
    assert saida.count("[FALHA-CICLO]") == 2                            # o loop continuou ao 2o IP
    assert len(_alertas(erro)) == 2 and all("falha no ciclo" in x for x in _alertas(erro))
    assert "[BLOQUEIO]" not in saida and _bloqueios_notificados(amb) == []


# ------------------------------------------------- reconciliacao (estados)

def test_estado_reconciliacao_tabela():
    r = sa.ResultadoReconciliacao
    assert sa.estado_reconciliacao(None) == "vazia"
    x = r(); assert sa.estado_reconciliacao(x) == "reconciliada"
    x = r(); x.movidos = 2; assert sa.estado_reconciliacao(x) == "reconciliada"
    x = r(); x.restantes = 1; assert sa.estado_reconciliacao(x) == "parcial"
    x = r(); x.ilegiveis = 1; assert sa.estado_reconciliacao(x) == "parcial"
    x = r(); x.principal_indisponivel = True; assert sa.estado_reconciliacao(x) == "parcial"
    x = r(); x.erro = "OSError"; x.restantes = None; assert sa.estado_reconciliacao(x) == "falhou"


def test_esta_vazia_so_e_true_se_verificavelmente_vazia_e_erro_propaga(tmp_path, monkeypatch):
    fila = sa.FilaDuravel(lambda: str(tmp_path / "fila" / "q.jsonl"))
    assert fila.esta_vazia() is True                       # inexistente
    os.makedirs(tmp_path / "fila")
    (tmp_path / "fila" / "q.jsonl").write_text("")
    assert fila.esta_vazia() is True                       # tamanho 0
    (tmp_path / "fila" / "q.jsonl").write_text("{}\n")
    assert fila.esta_vazia() is False
    real = os.stat

    def stat_negado(caminho, *a, **k):
        if str(caminho).endswith("q.jsonl"):
            raise PermissionError("negado")
        return real(caminho, *a, **k)
    monkeypatch.setattr(sa.os, "stat", stat_negado)
    with pytest.raises(PermissionError):
        fila.esta_vazia()                                   # NAO mascara como vazia


def test_falha_ao_verificar_a_fila_nunca_e_devolvida_como_fila_vazia():
    class FilaIlegivel:
        def esta_vazia(self):
            raise PermissionError("negado")
    auditor = sa.Auditor(DestinoPorTipo(), FilaIlegivel(), alertador=sa.Alertador())
    res = auditor.reconciliar_se_necessario()
    assert res is not None and res.erro == "PermissionError" and res.restantes is None
    assert sa.estado_reconciliacao(res) == "falhou"


def test_partida_vazia_e_reconciliada(amb):
    amb.mp.setattr(rt, "fabrica_auditor", None)  # destinos reais em disco
    assert rt.reconciliar_na_partida().estado == "vazia"
    fila = sa.FilaDuravel(sa.caminho_fila)
    ev = sa.novo_evento("config.changed", "success", payload={"k": 1}, origin="cli-local")
    assert fila.gravar(ev)
    r = rt.reconciliar_na_partida()
    assert r.estado == "reconciliada" and not r.degradado
    assert [e["event_id"] for e in sa.DestinoJsonl(sa.caminho_eventos).ler_eventos()] == [ev["event_id"]]
    assert rt.reconciliar_na_partida().estado == "vazia"


def test_partida_parcial_quando_principal_indisponivel_alerta_uma_vez_e_limpa_na_recuperacao(amb):
    amb.mp.setattr(rt, "fabrica_auditor", None)
    principal = PrincipalInstavel(sa.caminho_eventos)
    fila = sa.FilaDuravel(sa.caminho_fila)
    assert fila.gravar(sa.novo_evento("config.changed", "success", payload={"k": 1}, origin="cli-local"))
    amb.mp.setattr(rt, "fabrica_auditor", lambda: sa.Auditor(principal, fila, alertador=amb.alertador))
    principal.falhar = True
    erro = io.StringIO()
    with contextlib.redirect_stderr(erro):
        r1 = rt.reconciliar_na_partida()
        r2 = rt.reconciliar_na_partida()
    assert r1.estado == "parcial" and r1.degradado and r1.detalhe.get("principal_indisponivel")
    assert r2.estado == "parcial" and len(_alertas(erro.getvalue())) == 1   # dedup por estado
    principal.falhar = False
    assert rt.reconciliar_na_partida().estado == "reconciliada"
    principal.falhar = True
    assert fila.gravar(sa.novo_evento("config.changed", "success", payload={"k": 2}, origin="cli-local"))
    erro2 = io.StringIO()
    with contextlib.redirect_stderr(erro2):
        assert rt.reconciliar_na_partida().estado == "parcial"
    assert len(_alertas(erro2.getvalue())) == 1                              # chave limpa na recuperacao


def test_partida_falhou_quando_a_fila_nao_pode_ser_lida_e_nunca_e_vazia(amb):
    amb.mp.setattr(rt, "fabrica_auditor", None)
    fila = sa.FilaDuravel(sa.caminho_fila)
    assert fila.gravar(sa.novo_evento("config.changed", "success", payload={"k": 1}, origin="cli-local"))
    caminho = fila.caminho()
    real = os.stat

    def stat_negado(p, *a, **k):
        if str(p) == caminho:
            raise PermissionError("negado")
        return real(p, *a, **k)
    amb.mp.setattr(sa.os, "stat", stat_negado)
    with contextlib.redirect_stderr(io.StringIO()):
        r = rt.reconciliar_na_partida()
    assert r.estado == "falhou" and r.estado != "vazia" and r.degradado
    assert r.detalhe.get("erro") == "PermissionError"


def test_partida_falhou_com_configuracao_de_audit_invalida(amb):
    amb.mp.setattr(rt, "fabrica_auditor", None)
    amb.cfg["auditoria"] = {"arquivo_eventos": "a/ev.jsonl", "diretorio_fila": "a"}
    erro = io.StringIO()
    with contextlib.redirect_stderr(erro):
        r = rt.reconciliar_na_partida()
    assert r.estado == "falhou" and r.detalhe["causa"] == "configuracao_invalida"
    assert len(_alertas(erro.getvalue())) == 1


# ------------------------------- monitorar: partida degradada (P-D) e reinicio

def test_reconciliacao_parcial_na_partida_avisa_e_o_watchdog_continua_a_bloquear_via_fila(amb):
    principal = PrincipalInstavel(sa.caminho_eventos)
    fila = sa.FilaDuravel(sa.caminho_fila)
    assert fila.gravar(sa.novo_evento("config.changed", "success", payload={"k": 1}, origin="cli-local"))
    principal.falhar = True
    amb.mp.setattr(rt, "fabrica_auditor", lambda: sa.Auditor(principal, fila, alertador=amb.alertador))
    ip = "198.51.100.23"
    saida, erro = _rodar(amb, [[_linha(ip)]], limite=1)
    assert "[AUDIT] reconciliacao da fila de auditoria parcial" in saida
    assert defense.ip_bloqueado(ip)                                  # evento duravel na fila
    assert "EXECUTADA" in [e["event_type"] for e in fila.ler_eventos()]


def test_reconciliacao_falhada_na_partida_nao_e_fila_vazia_e_a_acao_segue_condicionada_ao_evento(amb):
    principal = PrincipalInstavel(sa.caminho_eventos)
    fila = sa.FilaDuravel(sa.caminho_fila)
    assert fila.gravar(sa.novo_evento("config.changed", "success", payload={"k": 1}, origin="cli-local"))
    caminho = fila.caminho()
    real = os.stat

    def stat_negado(p, *a, **k):
        if str(p) == caminho:
            raise PermissionError("negado")
        return real(p, *a, **k)
    amb.mp.setattr(sa.os, "stat", stat_negado)
    amb.mp.setattr(rt, "fabrica_auditor", lambda: sa.Auditor(principal, fila, alertador=amb.alertador))
    ip = "198.51.100.24"
    saida, erro = _rodar(amb, [[_linha(ip)]], limite=1)
    assert "[AUDIT] reconciliacao da fila de auditoria falhou" in saida
    assert "vazia" not in saida.split("[AUDIT]")[1].splitlines()[0]
    assert defense.ip_bloqueado(ip)   # principal aceitou o evento: durabilidade garantida


def test_watch_reinicia_reconcilia_de_novo_e_a_espera_persiste_entre_reinicios(amb):
    principal = PrincipalInstavel(sa.caminho_eventos)
    fila = sa.FilaDuravel(sa.caminho_fila)
    amb.mp.setattr(rt, "fabrica_auditor", lambda: sa.Auditor(principal, fila, alertador=amb.alertador))
    ip, ip2 = "198.51.100.25", "198.51.100.26"
    principal.falhar = True

    def curar():
        principal.falhar = False

    # run 1: ip bloqueia via fila; cura; queda; run 2 (reinicio): reconcilia
    _executar(amb, [[_linha(ip)], curar, CRASH],
              lambda: watchdog.rodar_com_reinicio(str(amb.log), intervalo=0.01, limite_alerta=1,
                                                  espera_reinicio=0))
    movidos = principal.ler_eventos()
    assert [e["event_type"] for e in movidos] == ["PROPOSTA", "AUTORIZADA", "EXECUTADA"]
    assert fila.esta_vazia() and defense.ip_bloqueado(ip)

    # espera persiste entre reinicios do mesmo processo: falha no run 1, mesmo par no run 2
    principal.falhar = True
    fila_morta = DestinoPorTipo(falhar=True)
    amb.mp.setattr(rt, "fabrica_auditor", lambda: sa.Auditor(principal, fila_morta, alertador=amb.alertador))
    _executar(amb, [[_linha(ip2)], CRASH, [_linha(ip2)]],
              lambda: watchdog.rodar_com_reinicio(str(amb.log), intervalo=0.01, limite_alerta=1,
                                                  espera_reinicio=0))
    assert fila_morta.tentativas == 1       # uma unica tentativa nos dois monitorar()


# ------------------------------------------------------------- unidades

def test_guarda_de_espera_fronteiras_limpar_e_poda():
    g = W.GuardaDeEspera()
    g.iniciar(("a", "contagem"), 100.0)
    assert g.em_espera(("a", "contagem"), 100.0)
    assert g.em_espera(("a", "contagem"), 159.9)
    assert not g.em_espera(("a", "contagem"), 160.0)
    g.iniciar(("b", "contagem"), 0.0)
    g.limpar(("b", "contagem"))
    assert not g.em_espera(("b", "contagem"), 1.0)
    for i in range(2000):
        g.iniciar(("ip%d" % i, "contagem"), 0.0)
    g.iniciar(("novo", "contagem"), 1000.0)   # poda as expiradas
    assert len(g._ate) < 2000


def test_alertador_esquecer_permite_novo_alerta(monkeypatch):
    from core import notify
    monkeypatch.setattr(notify, "enviar", lambda m, dados_extra=None: False)
    a = sa.Alertador()
    with contextlib.redirect_stderr(io.StringIO()):
        assert a.alertar("x", {}, chave_dedup="k") == "stderr"
        assert a.alertar("x", {}, chave_dedup="k") == "suprimido"
        a.esquecer("k")
        assert a.alertar("x", {}, chave_dedup="k") == "stderr"
        a.esquecer("inexistente")  # nao levanta


def test_o_modulo_do_watchdog_documenta_a_divida_c1_g4_e_nao_afirma_conformidade():
    texto = W.__doc__
    assert "C1/G4" in texto and "Passo 4" in texto
    assert "NAO constitui conformidade" in texto
