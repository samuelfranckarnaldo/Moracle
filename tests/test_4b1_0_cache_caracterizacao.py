"""
Passo 4b-1-0 - caracterizacao do `defense.monitorar`, do
`watchdog.rodar_com_reinicio` e das primitivas de escrita/alerta ANTES do
4b-1-1 (integridade do cache de IOCs). Sem alteracoes de producao.

Regra: estes testes DESCREVEM o comportamento atual, nao o aprovam. Os
prefixados `test_observado_` registam comportamento que o contrato do 4b-1
muda ou que motiva o contrato; cada um traz "MUDA NO 4b-1-1" ou
"OBSERVADO:" com o motivo. Os `test_base_*` fixam comportamento correto que
o 4b-1-1 NAO pode alterar (referencia de nao-regressao).

Isolamento: RAIZ_PROJETO, config, PADRAO (deepcopy), estado da defesa,
audit legado, runtime de seguranca e alertador apontam para tmp_path/espioes.
O analisador de logs e substituido por um falso deterministico: estes testes
caracterizam a logica do monitorar e do cache, nao os padroes de ataque. O
tempo e controlado por um `time.sleep` falso (nenhuma espera real).
"""
import copy
import fcntl
import json
import os
import stat
import subprocess
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

import cli
from core import atomic_state, audit, config, defense, ioc_cache, notify, watchdog
from core import security_audit as sa
from core import security_runtime as rt
from core import security_watchdog
from core.atomic_state import FileLock

IP_A = "198.51.100.7"
IP_B = "198.51.100.8"


# ------------------------------------------------------------------ apoio

class Parar(BaseException):
    """Interrompe o teste a partir do `sleep` falso (nao e apanhada pelo
    monitorar nem pelo watchdog, que so tratam Exception/KeyboardInterrupt)."""


class Excedeu(Parar):
    """Rede de seguranca: se o comportamento mudar e o monitorar deixar de
    terminar, o teste falha em vez de ficar preso num ciclo infinito."""


class ColetorAlertas:
    """Substitui o alertador do runtime: regista chamadas, nunca escreve."""

    def __init__(self):
        self.chamadas = []

    def alertar(self, mensagem, dados=None, chave_dedup=None):
        self.chamadas.append((mensagem, dados, chave_dedup))
        return "stderr"

    def esquecer(self, chave):
        pass


class AnalisadorFalso:
    """cada linha 'IP resto' vira um achado do IP."""

    def __init__(self, log_file):
        self.lines = []

    def analyze(self, filtros=None):
        return [{"ip": l.split()[0], "attack_name": "SQLi", "content": l.strip()}
                for l in self.lines if l.strip()]


@pytest.fixture
def amb(tmp_path, monkeypatch):
    estado = tmp_path / ".state"
    estado.mkdir()
    monkeypatch.setattr(config, "RAIZ_PROJETO", str(tmp_path))
    monkeypatch.setattr(config, "CONFIG_PATH", str(tmp_path / "config.json"))
    monkeypatch.setattr(config, "_cache", None)
    monkeypatch.setattr(config, "PADRAO", copy.deepcopy(config.PADRAO))
    monkeypatch.setattr(defense, "STATE_DIR", str(estado))
    monkeypatch.setattr(defense, "STATE_FILE", str(estado / "defesa_state.json"))
    monkeypatch.setattr(defense, "BLOCKLIST_FILE", str(estado / "blocklist.json"))
    monkeypatch.setattr(defense, "ALERTS_FILE", str(estado / "alerts.log"))
    monkeypatch.setattr(audit, "AUDIT_FILE", str(estado / "audit.log"))
    coletor = ColetorAlertas()
    monkeypatch.setattr(rt, "_alertador", coletor)
    monkeypatch.setattr(rt, "fabrica_auditor", None)
    monkeypatch.setattr(rt, "policy", None)
    monkeypatch.setattr(rt, "executor", None)
    security_watchdog.reiniciar_estado()
    monkeypatch.setattr(defense, "LogAnalyzer", AnalisadorFalso)
    monkeypatch.setattr(defense.notify, "enviar", lambda *a, **k: False)
    log = tmp_path / "access.log"
    log.write_text("")
    return SimpleNamespace(
        raiz=tmp_path, estado=estado, log=log, alertas_infra=coletor,
        cache=tmp_path / "saida" / "ioc_cache.json",
        blocklist=estado / "blocklist.json",
        alertas=estado / "alerts.log",
        defesa_state=estado / "defesa_state.json",
    )


def acrescentar(amb, texto):
    with open(amb.log, "a") as f:
        f.write(texto if texto.endswith("\n") else texto + "\n")


def cache_bruto(amb, texto):
    amb.cache.parent.mkdir(parents=True, exist_ok=True)
    amb.cache.write_text(texto)


def cache_com(amb, ip, malicioso, horas=0):
    from datetime import datetime, timedelta, timezone
    cache_bruto(amb, json.dumps({ip: {
        "dados": {"fonte": "t"}, "malicioso": malicioso,
        "verificado_em": (datetime.now(timezone.utc) - timedelta(hours=horas)).isoformat()}}))


def bloqueados(amb):
    if not amb.blocklist.exists():
        return {}
    return json.loads(amb.blocklist.read_text())


def instalar_relogio(monkeypatch, on_tick, on_espera=lambda n: None):
    """sleep(1) = tick do monitorar; sleep(5) = espera de reinicio do
    watchdog; qualquer outro valor (ex.: lock) passa sem esperar."""
    estado = SimpleNamespace(ticks=0, esperas=0)

    def falso(segundos):
        if estado.ticks > 40 or estado.esperas > 40:
            raise Excedeu("o monitorar nao terminou")
        if segundos == 1:
            estado.ticks += 1
            on_tick(estado.ticks)
        elif segundos == 5:
            estado.esperas += 1
            on_espera(estado.esperas)

    monkeypatch.setattr(defense.time, "sleep", falso)
    return estado


def rodar_lotes(amb, monkeypatch, lotes, limite=2, dry_run=False):
    """Cada tick acrescenta o lote seguinte; o tick a seguir ao ultimo
    lote termina o monitorar com Ctrl+C (saida limpa)."""
    def on_tick(n):
        if n <= len(lotes):
            acrescentar(amb, lotes[n - 1])
        else:
            raise KeyboardInterrupt

    instalar_relogio(monkeypatch, on_tick)
    defense.monitorar(str(amb.log), intervalo=1, limite_alerta=limite, dry_run=dry_run)


# ===================================================================
# Referencia: comportamento correto que o 4b-1-1 nao pode alterar
# ===================================================================

def test_base_sem_cache_bloqueia_por_contagem(amb, monkeypatch):
    rodar_lotes(amb, monkeypatch, [f"{IP_A} x\n{IP_A} x\n{IP_B} x\n"], limite=2)
    b = bloqueados(amb)
    assert set(b) == {IP_A}
    assert b[IP_A]["motivo"].startswith("2 tentativas")


def test_base_ioc_malicioso_valido_bloqueia_ao_primeiro_achado(amb, monkeypatch):
    cache_com(amb, IP_A, True)
    rodar_lotes(amb, monkeypatch, [f"{IP_A} x\n"], limite=5)
    assert bloqueados(amb)[IP_A]["motivo"] == "IOC conhecido malicioso (cache)"


def test_base_ioc_expirado_equivale_a_ausente(amb, monkeypatch):
    cache_com(amb, IP_A, True, horas=48)
    rodar_lotes(amb, monkeypatch, [f"{IP_A} x\n"], limite=5)
    assert bloqueados(amb) == {}
    rodar_lotes(amb, monkeypatch, [f"{IP_A} x\n" * 5], limite=5)
    assert bloqueados(amb)[IP_A]["motivo"].startswith("5 tentativas")


def test_base_entrada_valida_nao_maliciosa_cai_na_contagem(amb, monkeypatch):
    cache_com(amb, IP_A, False)
    rodar_lotes(amb, monkeypatch, [f"{IP_A} x\n{IP_A} x\n"], limite=2)
    assert bloqueados(amb)[IP_A]["motivo"].startswith("2 tentativas")


def test_base_ip_ja_bloqueado_nao_consulta_o_cache(amb, monkeypatch):
    # Um IP ja na blocklist nunca chega ao cache: cache corrompido nao
    # o afeta (so os IPs ainda nao bloqueados).
    defense.bloquear_ip(IP_A, "pre")
    cache_bruto(amb, "{corrompido")
    rodar_lotes(amb, monkeypatch, [f"{IP_A} x\n"], limite=1)
    assert amb.cache.read_text() == "{corrompido"
    assert bloqueados(amb)[IP_A]["motivo"] == "pre"


# ===================================================================
# monitorar com cache ilegivel (a falha que o D6b manda tratar)
# ===================================================================

def test_json_invalido_nao_derruba_o_monitorar_e_sinaliza(amb, monkeypatch, capsys):
    # ATUALIZADO NO 4b-1-1 (antes: a JSONDecodeError escapava do monitorar,
    # sem alerta, com a defesa "ativa" sem parado_em). Agora: tolerancia,
    # linha [IOC], estado interno, UM alerta so com os campos previstos.
    cache_bruto(amb, "{corrompido")
    rodar_lotes(amb, monkeypatch, [f"{IP_A} x\n"], limite=5)
    out = capsys.readouterr().out
    assert "[ALERTA]" in out and "[IOC]" in out and "causa=json_invalido" in out
    assert IP_A in amb.alertas.read_text()
    estado = json.loads(amb.defesa_state.read_text())
    assert estado["ativo"] is False and "parado_em" in estado  # saida limpa
    assert defense.ESTADO_IOC["degradado"] is True
    assert defense.ESTADO_IOC["falhas"] == {"json_invalido": 1}
    assert len(amb.alertas_infra.chamadas) == 1
    mensagem, dados, chave = amb.alertas_infra.chamadas[0]
    assert chave == ("ioc_cache", "json_invalido")
    assert dados == {"componente": "watchdog", "onde": "ioc_cache",
                     "causa": "json_invalido", "erro_classe": "JSONDecodeError"}
    assert str(amb.raiz) not in repr(amb.alertas_infra.chamadas)
    assert "corrompido" not in repr(amb.alertas_infra.chamadas)
    assert amb.cache.read_text() == "{corrompido"
    assert bloqueados(amb) == {}


def test_ficheiro_vazio_truncado_e_json_invalido(amb, monkeypatch):
    # ATUALIZADO NO 4b-1-1 (antes: a excecao escapava do monitorar).
    cache_bruto(amb, "")
    rodar_lotes(amb, monkeypatch, [f"{IP_A} x\n"], limite=5)
    assert defense.ESTADO_IOC["falhas"] == {"json_invalido": 1}
    assert [c[1]["causa"] for c in amb.alertas_infra.chamadas] == ["json_invalido"]
    assert bloqueados(amb) == {}


def test_raiz_que_nao_e_dicionario_e_estrutura_invalida(amb, monkeypatch):
    # ATUALIZADO NO 4b-1-1 (antes: a excecao escapava do monitorar).
    cache_bruto(amb, "[]")
    rodar_lotes(amb, monkeypatch, [f"{IP_A} x\n"], limite=5)
    assert defense.ESTADO_IOC["falhas"] == {"estrutura_invalida": 1}
    assert [c[1]["causa"] for c in amb.alertas_infra.chamadas] == ["estrutura_invalida"]
    assert bloqueados(amb) == {}


def test_entrada_corrompida_afeta_so_esse_ip_e_nao_bloqueia_por_ioc(amb, monkeypatch):
    # ATUALIZADO NO 4b-1-1 (antes: KeyError so para esse IP). Agora: so a
    # consulta de IP_A e ilegivel; IP_B (sem entrada) segue normal; a
    # entrada ma de IP_A, mesmo com malicioso=True, NAO bloqueia por IOC.
    cache_bruto(amb, json.dumps({IP_A: {"dados": {}, "malicioso": True}}))
    rodar_lotes(amb, monkeypatch, [f"{IP_B} x\n{IP_A} x\n"], limite=5)
    assert defense.ESTADO_IOC["falhas"] == {"entrada_invalida": 1}
    assert bloqueados(amb) == {}


def test_data_invalida_e_entrada_invalida(amb, monkeypatch):
    # ATUALIZADO NO 4b-1-1 (antes: a excecao escapava do monitorar).
    cache_bruto(amb, json.dumps({IP_A: {"dados": {}, "malicioso": True,
                                         "verificado_em": "ontem"}}))
    rodar_lotes(amb, monkeypatch, [f"{IP_A} x\n"], limite=5)
    assert defense.ESTADO_IOC["falhas"] == {"entrada_invalida": 1}
    assert [c[1]["causa"] for c in amb.alertas_infra.chamadas] == ["entrada_invalida"]
    assert bloqueados(amb) == {}


def test_entrada_que_nao_e_dicionario_e_entrada_invalida(amb, monkeypatch):
    # ATUALIZADO NO 4b-1-1 (antes: a excecao escapava do monitorar).
    cache_bruto(amb, json.dumps({IP_A: "texto"}))
    rodar_lotes(amb, monkeypatch, [f"{IP_A} x\n"], limite=5)
    assert defense.ESTADO_IOC["falhas"] == {"entrada_invalida": 1}
    assert [c[1]["causa"] for c in amb.alertas_infra.chamadas] == ["entrada_invalida"]
    assert bloqueados(amb) == {}


def test_cache_que_e_diretorio_e_erro_de_leitura(amb, monkeypatch):
    # ATUALIZADO NO 4b-1-1 (antes: a excecao escapava do monitorar).
    amb.cache.mkdir(parents=True)
    rodar_lotes(amb, monkeypatch, [f"{IP_A} x\n"], limite=5)
    assert defense.ESTADO_IOC["falhas"] == {"erro_de_leitura": 1}
    assert [c[1]["causa"] for c in amb.alertas_infra.chamadas] == ["erro_de_leitura"]
    assert bloqueados(amb) == {}


def test_diretorio_saida_com_tipo_errado_e_configuracao_invalida(amb, monkeypatch):
    # ATUALIZADO NO 4b-1-1 (antes: a excecao escapava do monitorar).
    (amb.raiz / "config.json").write_text(json.dumps({"diretorio_saida": 5}))
    config._cache = None
    rodar_lotes(amb, monkeypatch, [f"{IP_A} x\n"], limite=5)
    assert defense.ESTADO_IOC["falhas"] == {"configuracao_invalida": 1}
    assert [c[1]["causa"] for c in amb.alertas_infra.chamadas] == ["configuracao_invalida"]
    assert bloqueados(amb) == {}


def test_criterio_de_contagem_funciona_com_cache_ilegivel(amb, monkeypatch):
    # ATUALIZADO NO 4b-1-1 (antes: a contagem nunca era avaliada). Com
    # limite=1 o primeiro achado bloqueia por contagem, nao por IOC.
    cache_bruto(amb, "{corrompido")
    rodar_lotes(amb, monkeypatch, [f"{IP_A} x\n"], limite=1)
    assert bloqueados(amb)[IP_A]["motivo"].startswith("1 tentativas")
    assert defense.ESTADO_IOC["degradado"] is True


def test_dry_run_mostra_a_linha_ioc_sem_alerta_externo(amb, monkeypatch, capsys):
    # ATUALIZADO NO 4b-1-1 (antes: dry_run tambem levantava). Q2: mostra
    # [IOC], nao emite alerta externo; a falha fica no estado interno.
    cache_bruto(amb, "{corrompido")
    rodar_lotes(amb, monkeypatch, [f"{IP_A} x\n"], limite=1, dry_run=True)
    out = capsys.readouterr().out
    assert "[IOC]" in out and "[DRY-RUN]" in out
    assert amb.alertas_infra.chamadas == []
    assert defense.ESTADO_IOC["degradado"] is True
    assert bloqueados(amb) == {}


# ===================================================================
# rodar_com_reinicio com cache ilegivel
# ===================================================================

def test_cache_ilegivel_nao_provoca_reinicios_do_watchdog(amb, monkeypatch, capsys):
    # ATUALIZADO NO 4b-1-1 (antes: 3 reinicios, nenhum bloqueio, nenhum
    # alerta). Agora: zero reinicios; cada achado bloqueia por contagem
    # (limite=1); um unico alerta e uma unica linha [IOC]; cache intocado.
    cache_bruto(amb, "{corrompido")
    chamadas_ativar = []
    original = defense.ativar
    monkeypatch.setattr(defense, "ativar",
                        lambda: (chamadas_ativar.append(1), original())[1])

    def on_tick(n):
        if n <= 3:
            acrescentar(amb, f"198.51.100.{100 + n} x")
        else:
            raise KeyboardInterrupt

    estado = instalar_relogio(monkeypatch, on_tick)
    watchdog.rodar_com_reinicio(str(amb.log), intervalo=1, limite_alerta=1,
                                espera_reinicio=5)
    out = capsys.readouterr().out
    assert estado.esperas == 0
    assert out.count("[WATCHDOG] Falha inesperada") == 0
    assert len(chamadas_ativar) == 1
    assert set(bloqueados(amb)) == {"198.51.100.101", "198.51.100.102", "198.51.100.103"}
    assert out.count("[IOC]") == 1
    assert len(amb.alertas_infra.chamadas) == 1
    assert defense.ESTADO_IOC["falhas"] == {"json_invalido": 3}
    assert amb.cache.read_text() == "{corrompido"


def test_recuperacao_do_cache_sem_reiniciar_o_watchdog(amb, monkeypatch):
    # ATUALIZADO NO 4b-1-1 (antes: crash, reinicio e linhas perdidas).
    # Agora: o cache e reparado a meio da execucao e a consulta seguinte
    # volta a usar o IOC, sem reinicio; o estado de degradacao fica fixo.
    cache_bruto(amb, "{corrompido")
    chamadas_ativar = []
    original = defense.ativar
    monkeypatch.setattr(defense, "ativar",
                        lambda: (chamadas_ativar.append(1), original())[1])

    def on_tick(n):
        if n == 1:
            acrescentar(amb, f"{IP_A} x\n")
        elif n == 2:
            cache_com(amb, IP_B, True)  # reparo entre dois achados
            acrescentar(amb, f"{IP_B} x\n")
        else:
            raise KeyboardInterrupt

    estado = instalar_relogio(monkeypatch, on_tick)
    watchdog.rodar_com_reinicio(str(amb.log), intervalo=1, limite_alerta=5,
                                espera_reinicio=5)
    assert estado.esperas == 0 and len(chamadas_ativar) == 1
    assert set(bloqueados(amb)) == {IP_B}
    assert bloqueados(amb)[IP_B]["motivo"] == "IOC conhecido malicioso (cache)"
    assert defense.ESTADO_IOC["degradado"] is True
    assert defense.ESTADO_IOC["falhas"] == {"json_invalido": 1}
    assert len(amb.alertas_infra.chamadas) == 1


# ===================================================================
# Escrita atual do cache e primitivas que o 4b-1-1 vai reutilizar
# ===================================================================

def test_guardar_espera_pelo_lock_do_cache(amb):
    # ATUALIZADO NO 4b-1-1 (antes: um lock externo era ignorado). Agora:
    # guardar fica bloqueado enquanto o lock do cache esta ocupado.
    config.carregar()
    caminho = ioc_cache._caminho_cache()
    feito = threading.Event()

    def escrever():
        ioc_cache.guardar("203.0.113.1", {"fonte": "t"}, malicioso=True)
        feito.set()

    with FileLock(caminho, timeout=1):
        th = threading.Thread(target=escrever)
        th.start()
        assert not feito.wait(0.5)  # bloqueado enquanto o lock esta ocupado
    th.join(10)
    assert feito.is_set()
    assert "203.0.113.1" in json.loads(Path(caminho).read_text())


def _lock_ocupado(caminho):
    fd = open(caminho + ".lock", "w")
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    except BlockingIOError:
        return True
    finally:
        fd.close()


def test_leitura_e_escrita_do_cache_ocorrem_sob_o_lock(amb, monkeypatch):
    # ATUALIZADO NO 4b-1-1 (antes: a atualizacao perdida era deterministica
    # porque ler e escrever aconteciam fora de qualquer lock). Agora: tanto
    # a leitura como a escrita atomica correm com o lock ocupado.
    config.carregar()
    caminho = ioc_cache._caminho_cache()
    vistos = []
    ler = atomic_state.ler_json
    escrever = atomic_state._escrever_atomico
    monkeypatch.setattr(atomic_state, "ler_json",
                        lambda c, p=None: (vistos.append(("ler", _lock_ocupado(caminho))), ler(c, p))[1])
    monkeypatch.setattr(atomic_state, "_escrever_atomico",
                        lambda c, t: (vistos.append(("escrever", _lock_ocupado(caminho))), escrever(c, t))[1])
    ioc_cache.guardar("203.0.113.1", {"fonte": "A"}, malicioso=True)
    assert vistos == [("ler", True), ("escrever", True)]


def test_base_inventario_dos_chamadores_de_escrita_do_cache():
    # Inventario (nao regressao): so estes ficheiros chamam guardar,
    # guardar_lote ou _salvar. Se aparecer outro, o contrato do 4b-1 ("todos
    # os caminhos de escrita usam o mesmo lock") tem de o cobrir.
    # ATUALIZADO NO 4b-1-1: o padrao passou a incluir guardar_lote (o
    # ioc_feed grava agora em lote); os ficheiros esperados nao mudam.
    # ATUALIZADO NO 4b-3: o cli.py deixou de chamar o cache diretamente (a
    # gravacao do whois e do ioc-import passa por core/ioc_security.py, com
    # autorizacao e auditoria); todos continuam a usar guardar_lote/guardar
    # (mesmo lock).
    raiz = Path(cli.__file__).resolve().parent
    ignorar = {"tests", ".git", "__pycache__", ".tmp", "node_modules", "venv", ".venv"}
    achados = set()
    for p in raiz.rglob("*.py"):
        if ignorar & set(p.relative_to(raiz).parts):
            continue
        texto = p.read_text(errors="ignore")
        if ("ioc_cache.guardar(" in texto or "ioc_cache.guardar_lote(" in texto
                or "ioc_cache._salvar(" in texto):
            achados.add(p.relative_to(raiz).as_posix())
    assert achados == {"core/ioc_feed.py", "core/ioc_security.py"}


_CODIGO_FILHO = (
    "import sys\n"
    "sys.path.insert(0, sys.argv[1])\n"
    "from core.atomic_state import FileLock\n"
    "try:\n"
    "    with FileLock(sys.argv[2], timeout=0.3):\n"
    "        pass\n"
    "except TimeoutError:\n"
    "    sys.exit(3)\n"
)


def _filho(raiz, alvo):
    return subprocess.run([sys.executable, "-I", "-c", _CODIGO_FILHO, raiz, alvo],
                          capture_output=True, timeout=30).returncode


def test_base_filelock_exclui_outro_processo(tmp_path):
    # Confirmacao pedida: o lock (fcntl.flock num .lock dedicado) e
    # interprocesso, nao so entre threads.
    raiz = str(Path(cli.__file__).resolve().parent)
    alvo = str(tmp_path / "x.json")
    with FileLock(alvo):
        assert _filho(raiz, alvo) == 3  # outro processo nao entra
    assert _filho(raiz, alvo) == 0      # livre depois de libertado


def test_observado_escrita_atomica_faz_fsync_do_ficheiro_mas_nao_do_diretorio(
        tmp_path, monkeypatch):
    # OBSERVADO: durabilidade apos falha de energia NAO inclui o diretorio
    # (o rename pode perder-se; o ficheiro antigo continua consistente).
    # Atomicidade != durabilidade do rename. Ver nota do 4b-1.
    tipos = []
    real = os.fsync

    def espiao(fd):
        tipos.append(stat.S_ISDIR(os.fstat(fd).st_mode))
        return real(fd)

    monkeypatch.setattr(os, "fsync", espiao)
    atomic_state.escrever_json(str(tmp_path / "a.json"), {"a": 1})
    assert tipos == [False]


def test_base_falha_no_fsync_antes_do_replace_preserva_original(tmp_path, monkeypatch):
    alvo = tmp_path / "a.json"
    alvo.write_text('{"a": 1}')
    monkeypatch.setattr(os, "fsync", lambda fd: (_ for _ in ()).throw(OSError("falha")))
    with pytest.raises(OSError):
        atomic_state.escrever_json(str(alvo), {"b": 2})
    assert alvo.read_text() == '{"a": 1}'
    assert [p.name for p in tmp_path.iterdir() if p.name.startswith(".tmp_")] == []


def test_base_falha_no_replace_preserva_original_e_limpa_temporario(tmp_path, monkeypatch):
    alvo = tmp_path / "a.json"
    alvo.write_text('{"a": 1}')
    monkeypatch.setattr(os, "replace", lambda *a, **k: (_ for _ in ()).throw(OSError("falha")))
    with pytest.raises(OSError):
        atomic_state.escrever_json(str(alvo), {"b": 2})
    assert alvo.read_text() == '{"a": 1}'
    assert [p.name for p in tmp_path.iterdir() if p.name.startswith(".tmp_")] == []


# ===================================================================
# Alertador real (Q3: semantica de dedup antes da implementacao)
# ===================================================================

def test_observado_alertador_dedup_por_chave_sem_expiracao_e_prefixo_audit(
        monkeypatch, capsys):
    # OBSERVADO: a dedup e um conjunto em memoria sem tempo: depois do 1.o
    # alerta a mesma chave fica suprimida ate `esquecer`; nao ha mensagem de
    # recuperacao; e o texto em stderr leva sempre o prefixo "[MORACLE AUDIT]"
    # mesmo para um alerta que nao e de auditoria.
    monkeypatch.setattr(notify, "enviar", lambda *a, **k: False)
    a = sa.Alertador()
    chave = ("ioc_cache", "JSONDecodeError")
    assert a.alertar("cache de IOC ilegivel", {"onde": "monitorar"}, chave_dedup=chave) == "stderr"
    assert capsys.readouterr().err.startswith("[MORACLE AUDIT]")
    for _ in range(3):
        assert a.alertar("cache de IOC ilegivel", {}, chave_dedup=chave) == "suprimido"
    assert capsys.readouterr().err == ""
    a.esquecer(chave)
    assert a.alertar("cache de IOC ilegivel", {}, chave_dedup=chave) == "stderr"


def test_observado_chaves_distintas_alertam_cada_uma(monkeypatch):
    monkeypatch.setattr(notify, "enviar", lambda *a, **k: False)
    a = sa.Alertador()
    assert a.alertar("x", {}, chave_dedup=("ioc_cache", "JSONDecodeError")) == "stderr"
    assert a.alertar("x", {}, chave_dedup=("ioc_cache", "KeyError")) == "stderr"


def test_base_alertador_do_runtime_e_unico_no_processo(monkeypatch):
    # A dedup sobrevive aos reinicios do monitorar no mesmo processo.
    monkeypatch.setattr(rt, "_alertador", None)
    assert rt.obter_alertador() is rt.obter_alertador()
