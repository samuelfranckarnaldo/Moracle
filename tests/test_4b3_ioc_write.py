"""
Passo 4b-3 - `ioc-import` e `whois` com permissao ioc.write, validacao de IP,
fusao de proveniencia (S1=ii) e evento ioc.imported.

Isolamento: RAIZ_PROJETO, CONFIG_PATH, cache de config, PADRAO, estado, audit,
alertador e Intelligence (falso, sem rede) apontam para tmp_path / falsos.
"""
import copy
import json
import sys
import threading
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

import cli
from core import audit, config, ioc_cache, ioc_feed, ioc_security
from core import security_runtime as rt
from core.identity import KeyStore, RoleStore, ServiceRole, create_api_key


class Coletor:
    def __init__(self):
        self.alertas = []

    def alertar(self, mensagem, dados=None, chave_dedup=None):
        self.alertas.append((mensagem, dict(dados or {})))
        return "stderr"

    def esquecer(self, chave):
        pass


class IntelFalsa:
    vt = None

    def geolocate(self, alvo):
        return {"ip": alvo, "country": "ZZ", "city": "C", "isp": "I"}

    def check_virustotal(self, alvo, chave):
        return IntelFalsa.vt

    def check_abuseipdb(self, alvo, chave):
        return None

    def whois(self, alvo):
        return {"dominio": alvo}


@pytest.fixture
def amb(tmp_path, monkeypatch):
    estado = tmp_path / ".state"
    estado.mkdir()
    monkeypatch.setattr(config, "RAIZ_PROJETO", str(tmp_path))
    monkeypatch.setattr(config, "CONFIG_PATH", str(tmp_path / "config.json"))
    monkeypatch.setattr(config, "_cache", None)
    monkeypatch.setattr(config, "PADRAO", copy.deepcopy(config.PADRAO))
    monkeypatch.setattr(audit, "AUDIT_FILE", str(estado / "audit.log"))
    monkeypatch.setattr(rt, "_alertador", Coletor())
    monkeypatch.setattr(rt, "fabrica_auditor", None)
    monkeypatch.setattr(cli, "Intelligence", IntelFalsa)
    monkeypatch.delenv("MORACLE_API_KEY", raising=False)
    IntelFalsa.vt = None
    (tmp_path / "config.json").write_text("{}")
    return SimpleNamespace(raiz=tmp_path, estado=estado,
                           cache=tmp_path / "saida" / "ioc_cache.json",
                           eventos=estado / "security_events.jsonl")


def credencial(amb, monkeypatch, permissoes=("ioc.write",)):
    RoleStore(amb.estado).upsert(ServiceRole(name="ioc", permissions=frozenset(permissoes)))
    chave, token = create_api_key(KeyStore(amb.estado), name="ioc-key", role_name="ioc")
    monkeypatch.setenv("MORACLE_API_KEY", token)
    return chave, token


def rodar(monkeypatch, *args):
    monkeypatch.setattr(sys, "argv", ["mc", *args])
    return cli.main()


def cache(amb):
    return json.loads(amb.cache.read_text()) if amb.cache.exists() else {}


def eventos(amb):
    if not amb.eventos.exists():
        return []
    return [json.loads(l) for l in amb.eventos.read_text().splitlines() if l.strip()]


def feed(amb, texto, nome="feed.txt"):
    p = amb.raiz / nome
    p.write_text(texto)
    return str(p)


# ------------------------------------------------------------ validacao de IP

def test_ip_importavel_aceita_publicos_e_documentacao():
    for ok in ("8.8.8.8", "1.1.1.1", "203.0.113.5", "198.51.100.7", "192.0.2.1"):
        assert ioc_feed.ip_importavel(ok) == ok, ok


def test_ip_importavel_rejeita_invalidos_e_internos():
    for mau in ("999.999.999.999", "256.1.1.1", "1.2.3.04", "01.02.03.004", "1.2.3", "1.2.3.4.5",
                "127.0.0.1", "0.0.0.0", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.0.1",
                "169.254.169.254", "224.0.0.1", "239.255.255.255", "240.0.0.1", "100.64.0.1", "100.127.255.255",
                " 8.8.8.8", "8.8.8.8 ", "::1", "", None, 5):
        assert ioc_feed.ip_importavel(mau) is None, repr(mau)


def test_ip_fora_das_redes_internas_vizinhas_e_aceite():
    for ok in ("172.15.0.1", "172.32.0.1", "100.63.255.255", "100.128.0.1", "11.0.0.1"):
        assert ioc_feed.ip_importavel(ok) == ok, ok


# ------------------------------------------------------------ fusao (unitaria)

def test_mesclar_entrada_nova_so_aplica_os_dados():
    dados, mal = ioc_cache.mesclar_proveniencia(None, {"fonte": "a"}, True)
    assert (dados, mal) == ({"fonte": "a"}, True)


def test_mesclar_nunca_rebaixa_true_para_false():
    atual = {"dados": {"fonte": "a"}, "malicioso": True, "verificado_em": "x"}
    assert ioc_cache.mesclar_proveniencia(atual, {"geo": 1}, False)[1] is True


def test_mesclar_pode_promover_false_para_true():
    atual = {"dados": {"geo": 1}, "malicioso": False}
    assert ioc_cache.mesclar_proveniencia(atual, {"fonte": "a"}, True)[1] is True


def test_mesclar_preserva_a_primeira_fonte_e_lista_as_outras():
    atual = {"dados": {"fonte": "a"}, "malicioso": True}
    dados, _ = ioc_cache.mesclar_proveniencia(atual, {"fonte": "b"}, True)
    dados, _ = ioc_cache.mesclar_proveniencia({"dados": dados, "malicioso": True}, {"fonte": "c"}, True)
    assert dados["fonte"] == "a" and dados["fontes"] == ["a", "b", "c"]


def test_mesclar_mesma_fonte_nao_cria_lista():
    atual = {"dados": {"fonte": "a"}, "malicioso": True}
    dados, _ = ioc_cache.mesclar_proveniencia(atual, {"fonte": "a"}, True)
    assert dados == {"fonte": "a"}


def test_mesclar_aguenta_entrada_existente_malformada():
    for atual in ({"dados": "texto", "malicioso": True}, {"dados": None}, {}, "x", 5, []):
        dados, mal = ioc_cache.mesclar_proveniencia(atual, {"fonte": "a"}, True)
        assert dados == {"fonte": "a"} and mal is True


def test_lote_com_mesclar_que_falha_nao_persiste_nada(amb):
    ioc_cache.guardar("8.8.8.8", {"fonte": "antigo"}, True)
    antes = amb.cache.read_text()

    def explode(atual, dados, mal):
        raise RuntimeError("falha na fusao")

    with pytest.raises(RuntimeError):
        ioc_cache.guardar_lote([("1.1.1.1", {"fonte": "x"}, True), ("8.8.8.8", {"fonte": "y"}, True)],
                               mesclar=explode)
    assert amb.cache.read_text() == antes


def test_fusao_sob_o_lock_nao_perde_malicioso_em_concorrencia(amb):
    ioc_cache.guardar("8.8.8.8", {"fonte": "feed"}, True)
    erros = []

    def whois_limpo():
        try:
            for _ in range(15):
                ioc_cache.guardar_lote([("8.8.8.8", {"geo": {"n": 1}}, False)],
                                       mesclar=ioc_cache.mesclar_proveniencia)
        except Exception as exc:  # pragma: no cover
            erros.append(exc)

    ths = [threading.Thread(target=whois_limpo) for _ in range(5)]
    [t.start() for t in ths]
    [t.join() for t in ths]
    assert not erros
    e = cache(amb)["8.8.8.8"]
    assert e["malicioso"] is True and e["dados"]["fonte"] == "feed"


# ------------------------------------------------------------------- ioc-import

def test_import_valida_fonte(amb, monkeypatch, capsys):
    credencial(amb, monkeypatch)
    f = feed(amb, "8.8.8.8\n")
    assert rodar(monkeypatch, "forensic", "ioc-import", f, "--source", "linha1\nlinha2") == 1
    assert rodar(monkeypatch, "forensic", "ioc-import", f, "--source", "x" * 101) == 1
    assert rodar(monkeypatch, "forensic", "ioc-import", f, "--source", "") == 1
    assert not amb.cache.exists()
    assert rodar(monkeypatch, "forensic", "ioc-import", f, "--source", "x" * 100) == 0


def test_import_so_ignorados_nao_escreve_nem_emite_evento(amb, monkeypatch, capsys):
    credencial(amb, monkeypatch)
    f = feed(amb, "10.0.0.1\n127.0.0.1\nlixo\n")
    assert rodar(monkeypatch, "forensic", "ioc-import", f) == 0
    assert "0 IOCs importados, 3 linhas ignoradas" in capsys.readouterr().out
    assert not amb.cache.exists()
    assert eventos(amb) == []


def test_import_nao_grava_o_caminho_nem_segredos_no_evento(amb, monkeypatch):
    credencial(amb, monkeypatch)
    f = feed(amb, "8.8.8.8\n", nome="feed_segredo.txt")
    rodar(monkeypatch, "forensic", "ioc-import", f)
    texto = amb.eventos.read_text()
    assert "feed_segredo.txt" in texto and str(amb.raiz) not in texto


def test_import_com_credencial_invalida_ou_revogada_e_negado(amb, monkeypatch):
    chave, _ = credencial(amb, monkeypatch)
    f = feed(amb, "8.8.8.8\n")
    KeyStore(amb.estado).revoke(chave.id)
    assert rodar(monkeypatch, "forensic", "ioc-import", f) == 1
    monkeypatch.setenv("MORACLE_API_KEY", "nao-existe")
    assert rodar(monkeypatch, "forensic", "ioc-import", f) == 1
    assert not amb.cache.exists() and eventos(amb) == []


def test_import_server_admin_pode(amb, monkeypatch):
    credencial(amb, monkeypatch, permissoes=("server.admin",))
    assert rodar(monkeypatch, "forensic", "ioc-import", feed(amb, "8.8.8.8\n")) == 0


def test_import_conta_linhas_como_antes(amb, monkeypatch, capsys):
    credencial(amb, monkeypatch)
    f = feed(amb, "8.8.8.8\n8.8.8.8\n1.1.1.1\nlixo\n")
    rodar(monkeypatch, "forensic", "ioc-import", f)
    assert "3 IOCs importados, 1 linhas ignoradas" in capsys.readouterr().out
    assert set(cache(amb)) == {"8.8.8.8", "1.1.1.1"}


def test_import_repetido_da_mesma_fonte_mantem_forma_estavel(amb, monkeypatch):
    credencial(amb, monkeypatch)
    f = feed(amb, "8.8.8.8\n")
    rodar(monkeypatch, "forensic", "ioc-import", f, "--source", "a")
    rodar(monkeypatch, "forensic", "ioc-import", f, "--source", "a")
    assert cache(amb)["8.8.8.8"]["dados"] == {"fonte": "a"}


def test_import_preserva_dados_ricos_de_um_whois_anterior(amb, monkeypatch):
    credencial(amb, monkeypatch)
    ioc_cache.guardar("8.8.8.8", {"geo": {"country": "US"}, "virustotal": {"x": 1}}, False)
    rodar(monkeypatch, "forensic", "ioc-import", feed(amb, "8.8.8.8\n"), "--source", "feed")
    e = cache(amb)["8.8.8.8"]
    assert e["malicioso"] is True
    assert e["dados"] == {"geo": {"country": "US"}, "virustotal": {"x": 1}, "fonte": "feed"}


# ----------------------------------------------------------------------- whois

def test_whois_nao_grava_chaves_de_api_nos_eventos(amb, monkeypatch):
    credencial(amb, monkeypatch)
    rodar(monkeypatch, "forensic", "whois", "8.8.8.8", "--virustotal", "SEGREDO_VT",
          "--abuseipdb", "SEGREDO_AB")
    assert "SEGREDO" not in amb.eventos.read_text()
    assert "SEGREDO" not in amb.cache.read_text()


def test_whois_cache_hit_nao_pede_nem_usa_permissao(amb, monkeypatch, capsys):
    ioc_cache.guardar("8.8.8.8", {"geo": {"country": "AA"}}, False)
    assert rodar(monkeypatch, "forensic", "whois", "8.8.8.8") == 0
    out = capsys.readouterr().out
    assert "AA" in out and "somente leitura" not in out


def test_whois_novo_ip_malicioso_sem_cache_previo_marca_true(amb, monkeypatch):
    credencial(amb, monkeypatch)
    IntelFalsa.vt = {"data": {"attributes": {"last_analysis_stats": {"malicious": 10, "harmless": 0}}}}
    rodar(monkeypatch, "forensic", "whois", "8.8.8.8", "--virustotal", "K")
    assert cache(amb)["8.8.8.8"]["malicioso"] is True


def test_ioc_security_estados_publicos(amb, monkeypatch):
    # chamada direta ao modulo: sem credencial -> NEGADO (import) / SOMENTE_LEITURA (whois)
    f = feed(amb, "8.8.8.8\n")
    assert ioc_security.executar_ioc_import(f, "x").estado == ioc_security.NEGADO
    assert ioc_security.registrar_whois("8.8.8.8", {"geo": {}}, False).estado == ioc_security.SOMENTE_LEITURA
    credencial(amb, monkeypatch)
    assert ioc_security.executar_ioc_import(f, "x").estado == ioc_security.OK
    assert ioc_security.registrar_whois("1.1.1.1", {"geo": {}}, False).estado == ioc_security.OK
