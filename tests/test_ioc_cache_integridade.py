"""
Passo 4b-1-1 - integridade do cache de IOCs (contrato 4b-1 aprovado).

Cobre: escrita atomica sob lock (threads e processos), `guardar_lote`,
`consultar_malicioso` (estados e vocabulario fechado de causas), paridade do
`ioc_feed` e o comportamento do `defense.monitorar` perante cache ilegivel
(tolerancia, alerta unico por causa, ESTADO_IOC, dry_run, recuperacao).

Isolamento: RAIZ_PROJETO, config, PADRAO (deepcopy), estado da defesa,
audit legado, runtime e alertador apontam para tmp_path/espioes. O analisador
de logs e substituido por um falso; o tempo e controlado por um sleep falso
(com rede de seguranca contra ciclos infinitos). Nenhum teste toca no
.state ou no config.json reais.
"""
import copy
import csv
import json
import os
import stat
import subprocess
import sys
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

import cli
from core import atomic_state, audit, config, defense, ioc_cache, ioc_feed, notify
from core import security_audit as sa
from core import security_runtime as rt
from core import security_watchdog
from core.atomic_state import FileLock

IP_A = "198.51.100.7"
IP_B = "198.51.100.8"
CAUSAS = {"json_invalido", "estrutura_invalida", "entrada_invalida",
          "erro_de_leitura", "configuracao_invalida", "erro_inesperado"}


# ------------------------------------------------------------------ apoio

class Parar(BaseException):
    pass


class Excedeu(Parar):
    """Rede de seguranca: o monitorar deixou de terminar."""


class ColetorAlertas:
    def __init__(self):
        self.chamadas = []

    def alertar(self, mensagem, dados=None, chave_dedup=None):
        self.chamadas.append((mensagem, dados, chave_dedup))
        return "stderr"

    def esquecer(self, chave):
        pass


class AnalisadorFalso:
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
    # 4b-2: a 1.a gravacao do config.json passou a usar core.atomic_state;
    # cria-se o ficheiro antes para os espioes de escrita contarem so o cache.
    (tmp_path / "config.json").write_text("{}")
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
        saida=tmp_path / "saida",
        cache=tmp_path / "saida" / "ioc_cache.json",
        blocklist=estado / "blocklist.json",
    )


def cache_bruto(amb, conteudo):
    amb.cache.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(conteudo, bytes):
        amb.cache.write_bytes(conteudo)
    else:
        amb.cache.write_text(conteudo)


def entrada_valida(malicioso=True, horas=0):
    return {"dados": {"fonte": "t"}, "malicioso": malicioso,
            "verificado_em": (datetime.now(timezone.utc) - timedelta(hours=horas)).isoformat()}


def cache_com(amb, ip, malicioso, horas=0):
    cache_bruto(amb, json.dumps({ip: entrada_valida(malicioso, horas)}))


def cache_com_entrada(amb, ip, entrada):
    cache_bruto(amb, json.dumps({ip: entrada}))


def ler_cache(amb):
    return json.loads(amb.cache.read_text())


def temporarios(amb):
    return sorted(p.name for p in amb.saida.iterdir() if p.name.startswith(".tmp_")) \
        if amb.saida.exists() else []


def bloqueados(amb):
    return json.loads(amb.blocklist.read_text()) if amb.blocklist.exists() else {}


def acrescentar(amb, texto):
    with open(amb.log, "a") as f:
        f.write(texto if texto.endswith("\n") else texto + "\n")


def instalar_relogio(monkeypatch, on_tick):
    estado = SimpleNamespace(ticks=0)

    def falso(segundos):
        if estado.ticks > 40:
            raise Excedeu("o monitorar nao terminou")
        if segundos == 1:
            estado.ticks += 1
            on_tick(estado.ticks)

    monkeypatch.setattr(defense.time, "sleep", falso)
    return estado


def rodar_lotes(amb, monkeypatch, lotes, limite=2, dry_run=False):
    def on_tick(n):
        if n <= len(lotes):
            acrescentar(amb, lotes[n - 1])
        else:
            raise KeyboardInterrupt

    instalar_relogio(monkeypatch, on_tick)
    defense.monitorar(str(amb.log), intervalo=1, limite_alerta=limite, dry_run=dry_run)


def falha_no_fsync(monkeypatch):
    monkeypatch.setattr(os, "fsync", lambda fd: (_ for _ in ()).throw(OSError("falha simulada")))


# ===================================================================
# Escrita atomica
# ===================================================================

def test_falha_no_fsync_preserva_o_cache_anterior_em_guardar(amb, monkeypatch):
    cache_com(amb, IP_B, True)
    antes = amb.cache.read_bytes()
    falha_no_fsync(monkeypatch)
    with pytest.raises(OSError):
        ioc_cache.guardar(IP_A, {"fonte": "t"}, True)
    assert amb.cache.read_bytes() == antes
    assert temporarios(amb) == []


def test_falha_no_replace_preserva_o_cache_anterior_em_guardar_lote(amb, monkeypatch):
    cache_com(amb, IP_B, True)
    antes = amb.cache.read_bytes()
    monkeypatch.setattr(os, "replace", lambda *a, **k: (_ for _ in ()).throw(OSError("falha")))
    with pytest.raises(OSError):
        ioc_cache.guardar_lote([(IP_A, {"fonte": "t"}, True)])
    assert amb.cache.read_bytes() == antes
    assert temporarios(amb) == []


def test_falha_de_serializacao_preserva_o_cache_anterior(amb):
    cache_com(amb, IP_B, True)
    antes = amb.cache.read_bytes()
    with pytest.raises(TypeError):
        ioc_cache.guardar(IP_A, {"nao_serializavel": object()}, True)
    assert amb.cache.read_bytes() == antes
    assert temporarios(amb) == []


def test_escrita_bem_sucedida_deixa_json_valido_modo_0600_e_sem_temporarios(amb):
    ioc_cache.guardar(IP_A, {"fonte": "t"}, True)
    assert set(ler_cache(amb)) == {IP_A}
    assert stat.S_IMODE(os.stat(amb.cache).st_mode) == 0o600
    assert temporarios(amb) == []


def test_replace_so_acontece_depois_do_fsync_do_temporario(amb, monkeypatch):
    # Decisao 4b-1: ha fsync do temporario antes do replace e NAO ha fsync do
    # diretorio (limitacao de durabilidade documentada).
    eventos = []
    fsync, replace = os.fsync, os.replace
    monkeypatch.setattr(os, "fsync", lambda fd: (
        eventos.append(("fsync", stat.S_ISDIR(os.fstat(fd).st_mode))), fsync(fd))[1])
    monkeypatch.setattr(os, "replace", lambda a, b: (eventos.append(("replace",)), replace(a, b))[1])
    ioc_cache.guardar(IP_A, {"fonte": "t"}, True)
    assert eventos == [("fsync", False), ("replace",)]


# ===================================================================
# Concorrencia (ausencia de perdas E de corrupcao)
# ===================================================================

def entrada_bem_formada(e):
    assert set(e) == {"dados", "malicioso", "verificado_em"}
    assert isinstance(e["malicioso"], bool)
    datetime.fromisoformat(e["verificado_em"])
    return True


def test_threads_com_ips_distintos_nao_perdem_nem_corrompem(amb):
    config.carregar()
    erros = []

    def trabalhar(n):
        try:
            for i in range(25):
                ioc_cache.guardar(f"10.{n}.0.{i}", {"t": n, "i": i}, True)
        except Exception as exc:  # pragma: no cover
            erros.append(exc)

    ths = [threading.Thread(target=trabalhar, args=(n,)) for n in range(8)]
    for th in ths:
        th.start()
    for th in ths:
        th.join(120)
    assert erros == []
    cache = ler_cache(amb)  # JSON valido
    assert len(cache) == 200
    esperados = {f"10.{n}.0.{i}" for n in range(8) for i in range(25)}
    assert set(cache) == esperados
    assert all(entrada_bem_formada(e) for e in cache.values())
    for n in range(8):
        for i in range(25):
            assert cache[f"10.{n}.0.{i}"]["dados"] == {"t": n, "i": i}
    assert temporarios(amb) == []


def test_threads_a_escrever_o_mesmo_ip_deixam_uma_entrada_integra(amb):
    config.carregar()

    def trabalhar(n):
        for _ in range(10):
            ioc_cache.guardar(IP_A, {"t": n, "marca": "x" * 200}, bool(n % 2))

    ths = [threading.Thread(target=trabalhar, args=(n,)) for n in range(8)]
    for th in ths:
        th.start()
    for th in ths:
        th.join(120)
    cache = ler_cache(amb)
    assert list(cache) == [IP_A]
    e = cache[IP_A]
    assert entrada_bem_formada(e)
    assert e["dados"]["marca"] == "x" * 200 and e["dados"]["t"] in range(8)
    assert e["malicioso"] is bool(e["dados"]["t"] % 2)  # dados e flag da MESMA escrita


_CODIGO_PROCESSO = (
    "import sys\n"
    "sys.path.insert(0, sys.argv[1])\n"
    "from core import config, ioc_cache\n"
    "config.RAIZ_PROJETO = sys.argv[2]\n"
    "config.CONFIG_PATH = sys.argv[2] + '/config.json'\n"
    "config._cache = None\n"
    "n = sys.argv[3]\n"
    "for i in range(25):\n"
    "    ioc_cache.guardar('10.%s.0.%d' % (n, i), {'p': n, 'i': i}, True)\n"
)


def test_processos_concorrentes_nao_perdem_nem_corrompem(amb):
    config.carregar()  # cria o config.json antes (evita corrida na 1.a escrita)
    raiz = str(Path(cli.__file__).resolve().parent)
    procs = [subprocess.Popen([sys.executable, "-I", "-c", _CODIGO_PROCESSO, raiz,
                               str(amb.raiz), str(n)],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
             for n in range(4)]
    for p in procs:
        _, err = p.communicate(timeout=120)
        assert p.returncode == 0, err.decode()
    cache = ler_cache(amb)
    assert set(cache) == {f"10.{n}.0.{i}" for n in range(4) for i in range(25)}
    assert all(entrada_bem_formada(e) for e in cache.values())
    assert temporarios(amb) == []


# ===================================================================
# guardar_lote
# ===================================================================

def lote_de(n):
    return [(f"10.0.{i // 250}.{i % 250 + 1}", {"fonte": "lote"}, True) for i in range(n)]


def test_lote_grava_uma_vez_sob_um_so_lock_com_um_so_timestamp(amb, monkeypatch):
    config.carregar()
    escritas, locks = [], []
    escrever = atomic_state.escrever_json
    monkeypatch.setattr(atomic_state, "escrever_json",
                        lambda c, d: (escritas.append(len(d)), escrever(c, d))[1])
    entrar = FileLock.__enter__
    monkeypatch.setattr(FileLock, "__enter__", lambda self: (locks.append(1), entrar(self))[1])
    assert ioc_cache.guardar_lote(lote_de(500)) == 500
    assert escritas == [500] and len(locks) == 1
    cache = ler_cache(amb)
    assert len(cache) == 500
    assert len({e["verificado_em"] for e in cache.values()}) == 1
    assert all(entrada_bem_formada(e) for e in cache.values())


def test_lote_com_ips_repetidos_a_ultima_ganha_e_devolve_o_numero_recebido(amb):
    n = ioc_cache.guardar_lote([(IP_A, {"v": 1}, False), (IP_B, {"v": 2}, True), (IP_A, {"v": 3}, True)])
    assert n == 3
    cache = ler_cache(amb)
    assert cache[IP_A]["dados"] == {"v": 3} and cache[IP_A]["malicioso"] is True
    assert cache[IP_B]["dados"] == {"v": 2}


def test_lote_vazio_nao_faz_io(amb):
    assert ioc_cache.guardar_lote([]) == 0
    assert not amb.saida.exists()  # nem diretorio, nem cache, nem lock


def test_lote_preserva_entradas_existentes_incluindo_malformadas(amb):
    cache_bruto(amb, json.dumps({"203.0.113.9": "texto", IP_B: entrada_valida(True)}))
    ioc_cache.guardar_lote([(IP_A, {"fonte": "t"}, True)])
    cache = ler_cache(amb)
    assert set(cache) == {"203.0.113.9", IP_B, IP_A}
    assert cache["203.0.113.9"] == "texto"


def test_lote_e_tudo_ou_nada_perante_falha_de_escrita(amb, monkeypatch):
    falha_no_fsync(monkeypatch)
    with pytest.raises(OSError):
        ioc_cache.guardar_lote(lote_de(3))
    assert not amb.cache.exists()
    assert temporarios(amb) == []


def test_lote_sobre_cache_com_json_invalido_recusa_sem_alterar(amb):
    cache_bruto(amb, "{corrompido")
    with pytest.raises(json.JSONDecodeError):
        ioc_cache.guardar_lote(lote_de(3))
    assert amb.cache.read_text() == "{corrompido"


def test_lote_sobre_cache_vazio_ou_truncado_recusa_sem_criar_cache_novo(amb):
    cache_bruto(amb, "")
    with pytest.raises(json.JSONDecodeError):
        ioc_cache.guardar_lote(lote_de(3))
    assert amb.cache.read_text() == ""


def test_lote_sobre_raiz_que_nao_e_dicionario_levanta_valueerror_sem_alterar(amb):
    cache_bruto(amb, "[]")
    with pytest.raises(ValueError):
        ioc_cache.guardar_lote(lote_de(3))
    assert amb.cache.read_text() == "[]"


def test_lote_sobre_cache_que_e_diretorio_levanta_oserror(amb):
    amb.cache.mkdir(parents=True)
    with pytest.raises(OSError):
        ioc_cache.guardar_lote(lote_de(3))


def test_lote_prepara_tudo_antes_de_tocar_no_cache(amb):
    # Se a preparacao do lote falha a meio, nada e persistido e nem sequer
    # se resolve o caminho do cache (nenhuma E/S).
    def gerador():
        yield ("203.0.113.1", {}, True)
        yield ("203.0.113.2", {}, True)
        raise RuntimeError("falha na preparacao")

    with pytest.raises(RuntimeError):
        ioc_cache.guardar_lote(gerador())
    assert not amb.saida.exists()


def test_guardar_mantem_o_formato_da_entrada(amb):
    ioc_cache.guardar(IP_A, {"fonte": "t"}, malicioso=True)
    e = ler_cache(amb)[IP_A]
    assert entrada_bem_formada(e) and e["dados"] == {"fonte": "t"} and e["malicioso"] is True


# ===================================================================
# ioc_feed (paridade e falhas)
# ===================================================================

def feed(amb, nome, texto):
    p = amb.raiz / nome
    p.write_text(texto)
    return str(p)


def test_feed_paridade_de_contagens_e_entradas_texto_e_csv(amb, monkeypatch):
    escritas = []
    escrever = atomic_state.escrever_json
    monkeypatch.setattr(atomic_state, "escrever_json",
                        lambda c, d: (escritas.append(len(d)), escrever(c, d))[1])
    r1 = ioc_feed.importar_arquivo(feed(amb, "a.txt", "# c\n\n203.0.113.1\n203.0.113.2\nlixo\n"))
    assert r1 == {"importados": 2, "ignorados": 1}
    r2 = ioc_feed.importar_arquivo(
        feed(amb, "b.csv", "ip,tipo\n203.0.113.3,x\n203.0.113.3,y\n"), nome_fonte="csv_x")
    assert r2 == {"importados": 2, "ignorados": 1}  # contam linhas, nao IPs unicos
    assert escritas == [2, 3]  # uma escrita por ficheiro
    cache = ler_cache(amb)
    assert cache["203.0.113.1"]["dados"] == {"fonte": "feed_importado"}
    assert cache["203.0.113.3"]["dados"] == {"fonte": "csv_x"}


def test_feed_falha_de_leitura_a_meio_nao_persiste_nada(amb, monkeypatch):
    real = csv.reader

    def leitor(f):
        for i, linha in enumerate(real(f)):
            if i == 2:
                raise csv.Error("falha simulada")
            yield linha

    monkeypatch.setattr(ioc_feed.csv, "reader", leitor)
    f = feed(amb, "b.csv", "ip,tipo\n203.0.113.1,a\n203.0.113.2,b\n203.0.113.3,c\n")
    with pytest.raises(csv.Error):
        ioc_feed.importar_arquivo(f)
    assert not amb.saida.exists()


def test_feed_com_cache_ilegivel_recusa_sem_alterar(amb):
    cache_bruto(amb, "{corrompido")
    with pytest.raises(json.JSONDecodeError):
        ioc_feed.importar_arquivo(feed(amb, "a.txt", "203.0.113.1\n"))
    assert amb.cache.read_text() == "{corrompido"


def test_feed_sem_ips_validos_nao_toca_no_cache_nem_quando_ilegivel(amb):
    cache_bruto(amb, "{corrompido")
    r = ioc_feed.importar_arquivo(feed(amb, "a.txt", "# so comentarios\nlixo\n"))
    assert r == {"importados": 0, "ignorados": 1}
    assert amb.cache.read_text() == "{corrompido"


# ===================================================================
# consultar_malicioso
# ===================================================================

def _json(texto):
    return lambda a: cache_bruto(a, texto)


def _entrada(valor):
    return lambda a: cache_com_entrada(a, IP_A, valor)


def _config_diretorio_5(a):
    (a.raiz / "config.json").write_text(json.dumps({"diretorio_saida": 5}))
    config._cache = None


def _cache_diretorio(a):
    a.cache.mkdir(parents=True)


E_OK = lambda **k: dict(entrada_valida(True), **k)  # noqa: E731

# (nome, preparar, causa, erro_classe)
CENARIOS = [
    ("json invalido", _json("{corrompido"), "json_invalido", "JSONDecodeError"),
    ("ficheiro vazio", _json(""), "json_invalido", "JSONDecodeError"),
    ("utf8 invalido", lambda a: cache_bruto(a, b"\xff\xfe\xfa"), "json_invalido", "UnicodeDecodeError"),
    ("raiz lista", _json("[]"), "estrutura_invalida", None),
    ("raiz texto", _json('"x"'), "estrutura_invalida", None),
    ("raiz null", _json("null"), "estrutura_invalida", None),
    ("raiz numero", _json("5"), "estrutura_invalida", None),
    ("sem verificado_em", _entrada({"dados": {}, "malicioso": True}), "entrada_invalida", "KeyError"),
    ("sem malicioso", _entrada({"dados": {}, "verificado_em": entrada_valida()["verificado_em"]}),
     "entrada_invalida", "KeyError"),
    ("malicioso texto 'false'", _entrada(E_OK(malicioso="false")), "entrada_invalida", "ValueError"),
    ("malicioso inteiro 1", _entrada(E_OK(malicioso=1)), "entrada_invalida", "ValueError"),
    ("data invalida", _entrada(E_OK(verificado_em="ontem")), "entrada_invalida", "ValueError"),
    ("data sem fuso", _entrada(E_OK(verificado_em="2026-01-01T00:00:00")), "entrada_invalida", "TypeError"),
    ("data nao e texto", _entrada(E_OK(verificado_em=5)), "entrada_invalida", "TypeError"),
    ("entrada null", _entrada(None), "entrada_invalida", "TypeError"),
    ("entrada texto", _entrada("texto"), "entrada_invalida", "TypeError"),
    ("entrada lista", _entrada([1, 2]), "entrada_invalida", "TypeError"),
    ("cache e diretorio", _cache_diretorio, "erro_de_leitura", "IsADirectoryError"),
    ("diretorio_saida com tipo errado", _config_diretorio_5, "configuracao_invalida", "TypeError"),
]


def test_estados_encontrado_ausente_e_expirado(amb):
    c = ioc_cache.consultar_malicioso(IP_A)  # sem ficheiro
    assert (c.estado, c.malicioso, c.causa, c.erro_classe) == ("ausente", None, None, None)
    cache_com(amb, IP_B, True)
    c = ioc_cache.consultar_malicioso(IP_A)  # valido, sem correspondencia
    assert (c.estado, c.malicioso) == ("ausente", None)
    cache_com(amb, IP_A, True)
    c = ioc_cache.consultar_malicioso(IP_A)
    assert (c.estado, c.malicioso, c.causa) == ("encontrado", True, None)
    cache_com(amb, IP_A, False)
    c = ioc_cache.consultar_malicioso(IP_A)
    assert (c.estado, c.malicioso) == ("encontrado", False)
    cache_com(amb, IP_A, True, horas=48)
    c = ioc_cache.consultar_malicioso(IP_A)
    assert (c.estado, c.malicioso, c.causa) == ("expirado", None, None)


def test_cada_cenario_ilegivel_tem_causa_estavel_e_nunca_levanta(amb):
    for nome, preparar, causa, classe in CENARIOS:
        if amb.saida.exists():
            import shutil
            shutil.rmtree(amb.saida)
        (amb.raiz / "config.json").unlink(missing_ok=True)
        config._cache = None
        preparar(amb)
        antes = amb.cache.read_bytes() if amb.cache.is_file() else None
        c = ioc_cache.consultar_malicioso(IP_A)
        assert c.estado == "ilegivel", nome
        assert (c.causa, c.erro_classe) == (causa, classe), nome
        assert c.malicioso is None, nome
        assert c.causa in CAUSAS, nome
        texto = repr(c)
        assert str(amb.raiz) not in texto and "corrompido" not in texto and IP_A not in texto, nome
        if antes is not None:
            assert amb.cache.read_bytes() == antes, nome  # consultar nao altera dados


def test_validade_de_config_invalida_e_configuracao_invalida(amb, monkeypatch):
    for validade in (True, "x", 0, -5, None):
        monkeypatch.setattr(config, "carregar", lambda v=validade: {
            "diretorio_saida": "saida", "ioc_cache_validade_horas": v})
        c = ioc_cache.consultar_malicioso(IP_A)
        assert (c.estado, c.causa) == ("ilegivel", "configuracao_invalida"), validade


def test_erro_inesperado_e_ilegivel_e_nao_propaga(amb, monkeypatch):
    cache_com(amb, IP_A, True)
    config.carregar()  # fixa a config antes de falsear json.load
    monkeypatch.setattr(ioc_cache.json, "load",
                        lambda f: (_ for _ in ()).throw(RuntimeError("segredo")))
    c = ioc_cache.consultar_malicioso(IP_A)
    assert (c.estado, c.causa, c.erro_classe) == ("ilegivel", "erro_inesperado", "RuntimeError")
    assert "segredo" not in repr(c)


def test_corrupcao_por_entrada_afeta_so_o_ip_dessa_entrada(amb):
    cache_bruto(amb, json.dumps({IP_A: {"dados": {}, "malicioso": True},
                                 IP_B: entrada_valida(True)}))
    assert ioc_cache.consultar_malicioso(IP_A).estado == "ilegivel"
    assert ioc_cache.consultar_malicioso(IP_B).estado == "encontrado"
    assert ioc_cache.consultar_malicioso("203.0.113.9").estado == "ausente"


def test_obter_e_eh_malicioso_conhecido_mantem_o_comportamento_de_levantar(amb):
    cache_bruto(amb, "{corrompido")
    with pytest.raises(json.JSONDecodeError):
        ioc_cache.obter(IP_A)
    with pytest.raises(json.JSONDecodeError):
        ioc_cache.eh_malicioso_conhecido(IP_A)


# ===================================================================
# defense.monitorar com cache ilegivel
# ===================================================================

CENARIOS_DE_FICHEIRO = [c for c in CENARIOS]


def test_cada_causa_ilegivel_mantem_o_bloqueio_por_contagem_e_alerta_uma_vez(amb, monkeypatch, capsys):
    for nome, preparar, causa, classe in CENARIOS_DE_FICHEIRO:
        if amb.saida.exists():
            import shutil
            shutil.rmtree(amb.saida)
        for p in (amb.raiz / "config.json", amb.blocklist):
            p.unlink(missing_ok=True)
        config._cache = None
        amb.alertas_infra.chamadas.clear()
        preparar(amb)
        antes = amb.cache.read_bytes() if amb.cache.is_file() else None
        capsys.readouterr()
        rodar_lotes(amb, monkeypatch, [f"{IP_A} x\n{IP_A} x\n"], limite=2)
        out = capsys.readouterr().out
        assert bloqueados(amb)[IP_A]["motivo"].startswith("2 tentativas"), nome
        assert defense.ESTADO_IOC["degradado"] is True, nome
        assert defense.ESTADO_IOC["falhas"] == {causa: 2}, nome
        assert out.count("[IOC]") == 1 and f"causa={causa}" in out, nome
        assert [(c[1]["causa"], c[2]) for c in amb.alertas_infra.chamadas] == \
            [(causa, ("ioc_cache", causa))], nome
        dados = amb.alertas_infra.chamadas[0][1]
        assert set(dados) == {"componente", "onde", "causa", "erro_classe"}, nome
        assert dados["erro_classe"] == classe, nome
        assert str(amb.raiz) not in repr(amb.alertas_infra.chamadas), nome
        if antes is not None:
            assert amb.cache.read_bytes() == antes, nome  # o monitorar nunca escreve no cache


def test_n_achados_geram_um_alerta_e_uma_linha_ioc_por_causa(amb, monkeypatch, capsys):
    cache_bruto(amb, "{corrompido")
    rodar_lotes(amb, monkeypatch, [f"{IP_A} x\n" * 5], limite=100)
    out = capsys.readouterr().out
    assert defense.ESTADO_IOC["falhas"] == {"json_invalido": 5}
    assert out.count("[IOC]") == 1
    assert len(amb.alertas_infra.chamadas) == 1
    assert defense.ESTADO_IOC["ultima_falha_em"] is not None
    datetime.fromisoformat(defense.ESTADO_IOC["ultima_falha_em"])


def test_causas_distintas_geram_alertas_distintos(amb, monkeypatch):
    def on_tick(n):
        if n == 1:
            cache_com_entrada(amb, IP_A, {"dados": {}, "malicioso": True})
            acrescentar(amb, f"{IP_A} x\n")
        elif n == 2:
            cache_bruto(amb, "{corrompido")
            acrescentar(amb, f"{IP_B} x\n")
        else:
            raise KeyboardInterrupt

    instalar_relogio(monkeypatch, on_tick)
    defense.monitorar(str(amb.log), intervalo=1, limite_alerta=100)
    assert [c[2] for c in amb.alertas_infra.chamadas] == [
        ("ioc_cache", "entrada_invalida"), ("ioc_cache", "json_invalido")]
    assert defense.ESTADO_IOC["falhas"] == {"entrada_invalida": 1, "json_invalido": 1}


def test_dedup_do_alertador_real_sobrevive_a_nova_execucao_do_monitorar(amb, monkeypatch, capsys):
    # Mesmo processo, dois monitorar (como os reinicios do watchdog): o
    # alertador e unico, logo o alerta da mesma causa nao se repete; a linha
    # [IOC] no ecra repete-se (e por execucao).
    monkeypatch.setattr(notify, "enviar", lambda *a, **k: False)
    monkeypatch.setattr(rt, "_alertador", sa.Alertador())
    cache_bruto(amb, "{corrompido")
    rodar_lotes(amb, monkeypatch, [f"{IP_A} x\n"], limite=100)
    cap1 = capsys.readouterr()
    out1, err1 = cap1.out, cap1.err
    assert "[MORACLE AUDIT]" in err1 and "cache de IOC ilegivel" in err1
    assert "[IOC]" in out1
    rodar_lotes(amb, monkeypatch, [f"{IP_B} x\n"], limite=100)
    cap2 = capsys.readouterr()
    out2, err2 = cap2.out, cap2.err
    assert "cache de IOC ilegivel" not in err2
    assert "[IOC]" in out2


def test_estado_ioc_e_reposto_no_arranque_de_cada_monitorar(amb, monkeypatch):
    cache_bruto(amb, "{corrompido")
    rodar_lotes(amb, monkeypatch, [f"{IP_A} x\n"], limite=100)
    assert defense.ESTADO_IOC["degradado"] is True
    amb.cache.unlink()
    vistos = []

    def on_tick(n):
        vistos.append((defense.ESTADO_IOC["degradado"], dict(defense.ESTADO_IOC["falhas"]),
                       defense.ESTADO_IOC["ultima_falha_em"]))
        raise KeyboardInterrupt

    instalar_relogio(monkeypatch, on_tick)
    defense.monitorar(str(amb.log), intervalo=1, limite_alerta=100)
    assert vistos == [(False, {}, None)]


def test_ip_ja_bloqueado_nao_consulta_o_cache_nem_degrada(amb, monkeypatch):
    defense.bloquear_ip(IP_A, "pre")
    cache_bruto(amb, "{corrompido")
    rodar_lotes(amb, monkeypatch, [f"{IP_A} x\n"], limite=1)
    assert defense.ESTADO_IOC == {"degradado": False, "falhas": {}, "ultima_falha_em": None}
    assert amb.alertas_infra.chamadas == []


def test_cache_ausente_valido_ou_expirado_nao_e_degradacao(amb, monkeypatch):
    preparos = [lambda: None,
                lambda: cache_com(amb, IP_B, True),
                lambda: cache_com(amb, IP_A, True, horas=48)]
    for preparar in preparos:
        if amb.saida.exists():
            import shutil
            shutil.rmtree(amb.saida)
        preparar()
        rodar_lotes(amb, monkeypatch, [f"{IP_A} x\n"], limite=5)
        assert defense.ESTADO_IOC == {"degradado": False, "falhas": {}, "ultima_falha_em": None}
    assert amb.alertas_infra.chamadas == []


def test_o_monitorar_decide_por_consultar_malicioso_e_nao_por_eh_malicioso_conhecido(amb, monkeypatch):
    def proibido(ip):
        raise AssertionError("o monitorar nao deve usar eh_malicioso_conhecido")

    monkeypatch.setattr(ioc_cache, "eh_malicioso_conhecido", proibido)
    cache_com(amb, IP_A, True)
    rodar_lotes(amb, monkeypatch, [f"{IP_A} x\n"], limite=5)
    assert bloqueados(amb)[IP_A]["motivo"] == "IOC conhecido malicioso (cache)"
