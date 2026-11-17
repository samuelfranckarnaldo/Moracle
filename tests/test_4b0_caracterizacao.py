"""
Passo 4b-0 - caracterizacao de `config set`, `forensic ioc-import` e
`forensic whois` ANTES de qualquer alteracao de producao.

Regra: estes testes DESCREVEM o comportamento atual, nao o aprovam. Onde o
comportamento parece defeituoso (sem autorizacao, sem validacao, escrita
nao atomica, sem evento de auditoria, perda de proveniencia), o teste leva
o prefixo `test_observado_` e um comentario "OBSERVADO:". No 4b-1..4b-4 cada
um destes testes mudara de semantica de forma declarada (marcado "MUDA NO
4b-x"), nunca em silencio.

Isolamento: RAIZ_PROJETO, CONFIG_PATH, cache de config, PADRAO (deepcopy) e
o estado apontam para tmp_path; nada toca o config.json nem o .state reais.
A rede nunca e usada: `cli.Intelligence` e substituida por um falso.
Suposicoes minimas sobre texto: verifica-se presenca de chave/valor/numeros,
nunca o texto i18n completo.
"""
import copy
import json
import sys
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

import cli
from core import atomic_state, audit, config, ioc_cache
from core import security_runtime as rt
from core.identity import KeyStore, RoleStore, ServiceRole, create_api_key


# ------------------------------------------------------------------ fixture

class _Coletor:
    def __init__(self):
        self.alertas = []

    def alertar(self, mensagem, dados=None, chave_dedup=None):
        self.alertas.append((mensagem, dict(dados or {})))
        return "stderr"

    def esquecer(self, chave):
        pass


@pytest.fixture
def amb(tmp_path, monkeypatch):
    estado = tmp_path / ".state"
    estado.mkdir()
    monkeypatch.setattr(config, "RAIZ_PROJETO", str(tmp_path))
    monkeypatch.setattr(config, "CONFIG_PATH", str(tmp_path / "config.json"))
    monkeypatch.setattr(config, "_cache", None)
    # PADRAO e mutavel e partilhado: isola-o para o teste nao o contaminar.
    monkeypatch.setattr(config, "PADRAO", copy.deepcopy(config.PADRAO))
    # Log legado de comandos (core.audit.registrar corre em TODO comando,
    # antes do despacho): isolado, para nunca tocar o .state real.
    monkeypatch.setattr(audit, "AUDIT_FILE", str(estado / "audit.log"))
    # Sem credencial no ambiente: estes comandos hoje nao a exigem.
    monkeypatch.delenv("MORACLE_API_KEY", raising=False)
    # 4b-2: config set emite eventos de seguranca; alertador e fabrica isolados.
    monkeypatch.setattr(rt, "_alertador", _Coletor())
    monkeypatch.setattr(rt, "fabrica_auditor", None)
    return SimpleNamespace(
        raiz=tmp_path,
        estado=estado,
        audit_log=estado / "audit.log",
        config=tmp_path / "config.json",
        cache=tmp_path / "saida" / "ioc_cache.json",
    )


def rodar(monkeypatch, *args):
    monkeypatch.setattr(sys, "argv", ["mc", *args])
    return cli.main()


def ler_config(amb):
    return json.loads(amb.config.read_text())


def ler_cache(amb):
    if not amb.cache.exists():
        return {}
    return json.loads(amb.cache.read_text())


def sem_estado_de_seguranca(amb):
    """Nenhum evento de SecurityAction nem fila durável foi escrito. O log
    legado de comandos (audit.log) existe sempre e e verificado a parte."""
    return sorted(p.name for p in amb.estado.iterdir()) in ([], ["audit.log"])  # 4b-3: ver tambem eventos


def linhas_audit(amb):
    if not amb.audit_log.exists():
        return []
    return [json.loads(l) for l in amb.audit_log.read_text().splitlines() if l.strip()]


def cfg_existente(amb, **extra):
    """Cria um config.json (evita o ramo 'primeira execucao')."""
    amb.config.write_text(json.dumps(extra))
    config._cache = None


class IntelFalsa:
    """Substituto de cli.Intelligence: regista chamadas, nunca usa rede."""
    chamadas = []
    geo = {"ip": "x", "country": "ZZ", "city": "Cidade", "isp": "ISP"}
    vt = None
    abuse = None
    levanta = None

    def geolocate(self, alvo):
        IntelFalsa.chamadas.append(("geo", alvo))
        if IntelFalsa.levanta:
            raise IntelFalsa.levanta
        return dict(IntelFalsa.geo, ip=alvo)

    def check_virustotal(self, alvo, chave):
        IntelFalsa.chamadas.append(("vt", alvo, chave))
        return IntelFalsa.vt

    def check_abuseipdb(self, alvo, chave):
        IntelFalsa.chamadas.append(("abuse", alvo, chave))
        return IntelFalsa.abuse

    def whois(self, alvo):
        IntelFalsa.chamadas.append(("whois", alvo))
        return {"dominio": alvo}


@pytest.fixture
def intel(monkeypatch):
    IntelFalsa.chamadas = []
    IntelFalsa.geo = {"ip": "x", "country": "ZZ", "city": "Cidade", "isp": "ISP"}
    IntelFalsa.vt = None
    IntelFalsa.abuse = None
    IntelFalsa.levanta = None
    monkeypatch.setattr(cli, "Intelligence", IntelFalsa)
    return IntelFalsa


def vt_limpo():
    return {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 10}}}}


def vt_mau():
    return {"data": {"attributes": {"last_analysis_stats": {"malicious": 10, "harmless": 0}}}}


def entrada_cache(amb, ip, malicioso, dados, horas=0):
    amb.cache.parent.mkdir(parents=True, exist_ok=True)
    cache = ler_cache(amb)
    cache[ip] = {
        "dados": dados,
        "malicioso": malicioso,
        "verificado_em": (datetime.now(timezone.utc) - timedelta(hours=horas)).isoformat(),
    }
    amb.cache.write_text(json.dumps(cache))


# ===================================================================
# config set  (4b-2: reescrito para a semantica nova; cada teste que
# mudou esta marcado "4b-2" e o antigo comportamento esta no historico git)
# ===================================================================

def credencial(amb, monkeypatch, permissoes=("config.security_write",)):
    RoleStore(amb.estado).upsert(ServiceRole(name="cfg", permissions=frozenset(permissoes)))
    chave, token = create_api_key(KeyStore(amb.estado), name="cfg-key", role_name="cfg")
    monkeypatch.setenv("MORACLE_API_KEY", token)
    return chave, token


def eventos_config(amb):
    caminho = amb.estado / "security_events.jsonl"
    if not caminho.exists():
        return []
    return [json.loads(l) for l in caminho.read_text().splitlines() if l.strip()]


def test_config_set_inteiro_e_persistido(amb, monkeypatch, capsys):
    cfg_existente(amb)
    rc = rodar(monkeypatch, "config", "set", "limite_suspeitos_padrao", "7")
    out = capsys.readouterr().out
    assert rc == 0
    assert "limite_suspeitos_padrao" in out and "7" in out
    assert ler_config(amb)["limite_suspeitos_padrao"] == 7  # int, nao "7"


def test_config_set_texto_fica_string(amb, monkeypatch):
    cfg_existente(amb)
    rodar(monkeypatch, "config", "set", "idioma", "en")
    assert ler_config(amb)["idioma"] == "en"


def test_config_set_so_digitos_viram_int_em_chave_desconhecida(amb, monkeypatch):
    # 4b-2: chave desconhecida exige config.security_write; a regra de
    # conversao (so digitos ASCII viram int) mantem-se.
    cfg_existente(amb)
    credencial(amb, monkeypatch)
    for bruto in ["-5", "3.5", "true", "null", "none", " 7"]:
        assert rodar(monkeypatch, "config", "set", "chave_livre", bruto) == 0
        assert ler_config(amb)["chave_livre"] == bruto


def test_config_set_zeros_a_esquerda_viram_int(amb, monkeypatch):
    cfg_existente(amb)
    credencial(amb, monkeypatch)
    rodar(monkeypatch, "config", "set", "chave_livre", "007")
    assert ler_config(amb)["chave_livre"] == 7


def test_config_set_digito_unicode_fica_texto_sem_excecao(amb, monkeypatch):
    # 4b-2: antes levantava ValueError (int("²")); agora so digitos ASCII
    # viram int e o resto fica texto.
    cfg_existente(amb)
    credencial(amb, monkeypatch)
    assert rodar(monkeypatch, "config", "set", "chave_livre", "²") == 0
    assert ler_config(amb)["chave_livre"] == "²"


def test_config_set_chave_pontilhada_atualiza_subchave(amb, monkeypatch):
    cfg_existente(amb)
    credencial(amb, monkeypatch)
    rc = rodar(monkeypatch, "config", "set", "defesa.limite_alerta_padrao", "9")
    assert rc == 0
    d = ler_config(amb)["defesa"]
    assert d["limite_alerta_padrao"] == 9
    assert d["intervalo_padrao"] == 2  # irma preservada


def test_config_set_chave_desconhecida_exige_permissao(amb, monkeypatch):
    # 4b-2: antes qualquer nome era persistido sem credencial.
    cfg_existente(amb)
    antes = amb.config.read_text()
    assert rodar(monkeypatch, "config", "set", "chave_inventada", "x") == 1
    assert amb.config.read_text() == antes
    credencial(amb, monkeypatch)
    assert rodar(monkeypatch, "config", "set", "chave_inventada", "x") == 0
    assert ler_config(amb)["chave_inventada"] == "x"


def test_config_set_chave_protegida_sem_credencial_nao_altera_nem_regista_evento(amb, monkeypatch):
    # 4b-2 (era test_observado_config_set_sem_credencial_e_sem_evento):
    # `limite_suspeitos_padrao` e LIVRE; uma chave PROTEGIDA e negada.
    cfg_existente(amb)
    antes = amb.config.read_text()
    assert rodar(monkeypatch, "config", "set", "defesa.limite_alerta_padrao", "5") == 1
    assert amb.config.read_text() == antes
    assert eventos_config(amb) == []


def test_config_set_chave_livre_sem_credencial_regista_evento(amb, monkeypatch):
    # 4b-2: a alteracao continua livre, mas deixa evento (requested+success).
    cfg_existente(amb)
    assert rodar(monkeypatch, "config", "set", "limite_suspeitos_padrao", "5") == 0
    evs = eventos_config(amb)
    assert [e["outcome"] for e in evs] == ["requested", "success"]
    assert all(e["event_type"] == "config.changed" for e in evs)
    assert "identity" not in evs[0]["actor"]


def test_config_set_idioma_invalido_e_rejeitado_sem_alterar(amb, monkeypatch, capsys):
    # 4b-2 (era: corrigido em silencio mas a mensagem dizia o pedido).
    cfg_existente(amb)
    antes = amb.config.read_text()
    rc = rodar(monkeypatch, "config", "set", "idioma", "xx")
    cap = capsys.readouterr()
    assert rc == 1
    assert amb.config.read_text() == antes
    assert "nada foi alterado" in cap.out


def test_config_set_limite_zero_e_rejeitado(amb, monkeypatch):
    cfg_existente(amb)
    antes = amb.config.read_text()
    assert rodar(monkeypatch, "config", "set", "limite_suspeitos_padrao", "0") == 1
    assert amb.config.read_text() == antes


def test_config_set_validade_zero_e_rejeitada(amb, monkeypatch):
    cfg_existente(amb)
    credencial(amb, monkeypatch)
    antes = amb.config.read_text()
    assert rodar(monkeypatch, "config", "set", "ioc_cache_validade_horas", "0") == 1
    assert amb.config.read_text() == antes


def test_config_set_webhook_sem_http_e_rejeitado(amb, monkeypatch):
    cfg_existente(amb)
    credencial(amb, monkeypatch)
    antes = amb.config.read_text()
    assert rodar(monkeypatch, "config", "set", "webhook_url", "ftp://exemplo") == 1
    assert amb.config.read_text() == antes


def test_config_set_validacao_cobre_as_chaves_protegidas(amb, monkeypatch):
    # 4b-2 (era test_observado_validacao_so_cobre_quatro_campos).
    cfg_existente(amb)
    credencial(amb, monkeypatch)
    antes = amb.config.read_text()
    for chave, valor in [("defesa.intervalo_padrao", "abc"),
                         ("rate_limit.global_max", "abc"),
                         ("bloqueio_expira_horas_padrao", "abc"),
                         ("bloqueio_expira_horas_padrao", "1.5"),
                         ("auditoria.arquivo_eventos", "/dev/null")]:
        assert rodar(monkeypatch, "config", "set", chave, valor) == 1, chave
    assert amb.config.read_text() == antes


def test_config_set_diretorio_saida_so_dentro_da_raiz(amb, monkeypatch):
    # 4b-2 (era test_observado_diretorio_saida_aceita_absoluto_e_ponto_ponto).
    cfg_existente(amb)
    credencial(amb, monkeypatch)
    assert rodar(monkeypatch, "config", "set", "diretorio_saida", "../fora") == 1
    assert rodar(monkeypatch, "config", "set", "diretorio_saida", "/tmp/abs") == 1
    assert rodar(monkeypatch, "config", "set", "diretorio_saida", "outro") == 0
    assert ler_config(amb)["diretorio_saida"] == "outro"


def test_config_set_raiz_estruturada_nao_e_substituida_por_escalar(amb, monkeypatch):
    # 4b-2 (era test_observado_raiz_estruturada_substituida_por_escalar_quebra_carregar).
    cfg_existente(amb)
    credencial(amb, monkeypatch)
    antes = amb.config.read_text()
    assert rodar(monkeypatch, "config", "set", "defesa", "abc") == 1
    assert amb.config.read_text() == antes
    config._cache = None
    assert config.carregar()["defesa"]["limite_alerta_padrao"] == 3  # continua utilizavel


def test_config_set_subchave_sob_escalar_e_rejeitada_sem_excecao(amb, monkeypatch):
    # 4b-2 (era: TypeError sem tratamento).
    cfg_existente(amb)
    antes = amb.config.read_text()
    assert rodar(monkeypatch, "config", "set", "idioma.x", "y") == 1
    assert amb.config.read_text() == antes


def test_config_set_primeira_execucao_nao_contamina_PADRAO(amb, monkeypatch):
    # 4b-2 (era test_observado_primeira_execucao_contamina_PADRAO_em_memoria).
    assert not amb.config.exists()
    credencial(amb, monkeypatch)
    rodar(monkeypatch, "config", "set", "defesa.limite_alerta_padrao", "7")
    assert config.PADRAO["defesa"]["limite_alerta_padrao"] == 3
    assert ler_config(amb)["defesa"]["limite_alerta_padrao"] == 7


def test_config_set_falha_de_escrita_nao_trunca_o_config(amb, monkeypatch):
    # 4b-2 (era test_observado_escrita_nao_atomica_falha_deixa_config_truncado):
    # a escrita e atomica; o ficheiro fica intacto byte a byte.
    cfg_existente(amb, limite_suspeitos_padrao=5)
    antes = amb.config.read_bytes()

    def falha(*a, **k):
        raise OSError("disco cheio simulado")

    monkeypatch.setattr(atomic_state, "_escrever_atomico", falha)
    assert rodar(monkeypatch, "config", "set", "limite_suspeitos_padrao", "6") == 1
    assert amb.config.read_bytes() == antes
    assert [e["outcome"] for e in eventos_config(amb)] == ["requested", "failure"]


def test_config_show_reflete_valor_persistido(amb, monkeypatch, capsys):
    cfg_existente(amb)
    rodar(monkeypatch, "config", "set", "limite_suspeitos_padrao", "8")
    capsys.readouterr()
    config._cache = None
    rodar(monkeypatch, "config", "show")
    assert '"limite_suspeitos_padrao": 8' in capsys.readouterr().out


def test_observado_diretorio_saida_redireciona_cache_e_IOCs_desaparecem(amb, monkeypatch):
    # OBSERVADO (D4): trocar diretorio_saida "esconde" o cache atual:
    # o IOC importado deixa de ser conhecido. 4b-2: agora exige permissao
    # e deixa evento; o redirecionamento em si continua a acontecer.
    cfg_existente(amb)
    credencial(amb, monkeypatch)
    ioc_cache.guardar("203.0.113.9", {"fonte": "t"}, malicioso=True)
    assert ioc_cache.eh_malicioso_conhecido("203.0.113.9") is True
    assert rodar(monkeypatch, "config", "set", "diretorio_saida", "outro") == 0
    assert ioc_cache.eh_malicioso_conhecido("203.0.113.9") is False


# ===================================================================
# forensic ioc-import
# ===================================================================

def _com_ioc(amb, monkeypatch, permissoes=("ioc.write",)):
    return credencial(amb, monkeypatch, permissoes)


def eventos_ioc(amb):
    return [e for e in eventos_config(amb) if e["event_type"] == "ioc.imported"]


def escrever(amb, nome, texto, binario=False):
    p = amb.raiz / nome
    if binario:
        p.write_bytes(texto)
    else:
        p.write_text(texto)
    return str(p)


def test_ioc_import_texto_simples(amb, monkeypatch, capsys):
    _com_ioc(amb, monkeypatch)
    f = escrever(amb, "feed.txt", "# comentario\n\n203.0.113.1\n203.0.113.2\nlixo\n")
    rc = rodar(monkeypatch, "forensic", "ioc-import", f)
    out = capsys.readouterr().out
    assert rc == 0
    assert "2" in out and "1" in out
    c = ler_cache(amb)
    assert set(c) == {"203.0.113.1", "203.0.113.2"}
    e = c["203.0.113.1"]
    assert e["malicioso"] is True
    assert e["dados"] == {"fonte": "feed_importado"}
    datetime.fromisoformat(e["verificado_em"])


def test_ioc_import_source_personalizada(amb, monkeypatch):
    _com_ioc(amb, monkeypatch)
    f = escrever(amb, "feed.txt", "203.0.113.1\n")
    rodar(monkeypatch, "forensic", "ioc-import", f, "--source", "meu_feed")
    assert ler_cache(amb)["203.0.113.1"]["dados"] == {"fonte": "meu_feed"}


def test_ioc_import_csv_primeira_coluna_cabecalho_ignorado(amb, monkeypatch):
    _com_ioc(amb, monkeypatch)
    f = escrever(amb, "feed.csv", "ip,tipo\n203.0.113.1,scanner\n203.0.113.2,bot\n")
    rodar(monkeypatch, "forensic", "ioc-import", f)
    assert set(ler_cache(amb)) == {"203.0.113.1", "203.0.113.2"}


def test_observado_csv_nao_ignora_comentarios_conta_como_ignorados(amb, monkeypatch, capsys):
    _com_ioc(amb, monkeypatch)
    # OBSERVADO: no modo CSV '#' nao e comentario (so no modo texto).
    f = escrever(amb, "feed.csv", "ip,tipo\n# c\n203.0.113.1,x\n")
    rodar(monkeypatch, "forensic", "ioc-import", f)
    assert set(ler_cache(amb)) == {"203.0.113.1"}
    assert "2" in capsys.readouterr().out  # cabecalho + comentario ignorados


def test_observado_modo_decidido_pela_primeira_linha(amb, monkeypatch):
    _com_ioc(amb, monkeypatch)
    # OBSERVADO: 1a linha com virgula => CSV para o ficheiro todo;
    # 1a linha sem virgula => texto, e "ip,tipo" nas seguintes e ignorado.
    f = escrever(amb, "a.txt", "203.0.113.1\n203.0.113.2,scanner\n")
    rodar(monkeypatch, "forensic", "ioc-import", f)
    assert set(ler_cache(amb)) == {"203.0.113.1"}


def test_ioc_import_rejeita_octetos_fora_de_intervalo(amb, monkeypatch, capsys):
    # 4b-3 (era test_observado_regex_aceita_octetos_fora_de_intervalo):
    # "passou na regex" != IP valido; agora so IPv4 validos entram.
    _com_ioc(amb, monkeypatch)
    f = escrever(amb, "feed.txt", "999.999.999.999\n01.02.03.004\n300.1.1.1\n203.0.113.1\n")
    assert rodar(monkeypatch, "forensic", "ioc-import", f) == 0
    assert set(ler_cache(amb)) == {"203.0.113.1"}
    assert "3 linhas ignoradas" in capsys.readouterr().out


def test_ioc_import_rejeita_ips_internos(amb, monkeypatch):
    # 4b-3 (era test_observado_nao_rejeita_ips_privados_nem_loopback): um feed
    # nao pode levar a defesa a bloquear a rede local.
    _com_ioc(amb, monkeypatch)
    f = escrever(amb, "feed.txt", "127.0.0.1\n10.0.0.1\n0.0.0.0\n192.168.1.5\n172.16.0.9\n"
                                  "169.254.1.1\n224.0.0.1\n100.64.0.1\n8.8.8.8\n")
    rodar(monkeypatch, "forensic", "ioc-import", f)
    assert set(ler_cache(amb)) == {"8.8.8.8"}
    assert ioc_cache.eh_malicioso_conhecido("127.0.0.1") is False


def test_ioc_import_preserva_dados_e_proveniencia_da_entrada_existente(amb, monkeypatch):
    # 4b-3 (era test_observado_import_sobrescreve_entrada_existente_e_perde_dados):
    # a entrada existente (geo) e preservada; passa a malicioso e ganha fonte.
    _com_ioc(amb, monkeypatch)
    entrada_cache(amb, "203.0.113.1", False, {"geo": {"country": "ZZ"}})
    f = escrever(amb, "feed.txt", "203.0.113.1\n")
    rodar(monkeypatch, "forensic", "ioc-import", f)
    e = ler_cache(amb)["203.0.113.1"]
    assert e["malicioso"] is True
    assert e["dados"] == {"geo": {"country": "ZZ"}, "fonte": "feed_importado"}


def test_ioc_import_nao_substitui_a_fonte_existente(amb, monkeypatch):
    _com_ioc(amb, monkeypatch)
    entrada_cache(amb, "203.0.113.1", True, {"fonte": "feed_a"})
    f = escrever(amb, "feed.txt", "203.0.113.1\n")
    rodar(monkeypatch, "forensic", "ioc-import", f, "--source", "feed_b")
    d = ler_cache(amb)["203.0.113.1"]["dados"]
    assert d["fonte"] == "feed_a"
    assert d["fontes"] == ["feed_a", "feed_b"]


def test_observado_import_mantem_outras_entradas(amb, monkeypatch):
    _com_ioc(amb, monkeypatch)
    entrada_cache(amb, "198.51.100.7", False, {"geo": {}})
    f = escrever(amb, "feed.txt", "203.0.113.1\n")
    rodar(monkeypatch, "forensic", "ioc-import", f)
    assert set(ler_cache(amb)) == {"198.51.100.7", "203.0.113.1"}


def test_ioc_import_torna_ip_conhecido_para_a_defesa(amb, monkeypatch):
    _com_ioc(amb, monkeypatch)
    f = escrever(amb, "feed.txt", "203.0.113.1\n")
    rodar(monkeypatch, "forensic", "ioc-import", f)
    assert ioc_cache.eh_malicioso_conhecido("203.0.113.1") is True


def test_entrada_importada_expira_apos_validade(amb, monkeypatch):
    _com_ioc(amb, monkeypatch)
    f = escrever(amb, "feed.txt", "203.0.113.1\n")
    rodar(monkeypatch, "forensic", "ioc-import", f)
    c = ler_cache(amb)
    c["203.0.113.1"]["verificado_em"] = (
        datetime.now(timezone.utc) - timedelta(hours=25)).isoformat()
    amb.cache.write_text(json.dumps(c))
    assert ioc_cache.eh_malicioso_conhecido("203.0.113.1") is False


def test_ioc_import_ficheiro_vazio_nao_cria_cache(amb, monkeypatch, capsys):
    _com_ioc(amb, monkeypatch)
    f = escrever(amb, "vazio.txt", "")
    rc = rodar(monkeypatch, "forensic", "ioc-import", f)
    assert rc == 0
    assert "0" in capsys.readouterr().out
    assert not amb.cache.exists()


def test_ioc_import_bytes_invalidos_sao_ignorados(amb, monkeypatch):
    _com_ioc(amb, monkeypatch)
    f = escrever(amb, "feed.txt", b"203.0.113.1\n\xff\xfe\n203.0.113.2\n", binario=True)
    rc = rodar(monkeypatch, "forensic", "ioc-import", f)
    assert rc == 0
    assert set(ler_cache(amb)) == {"203.0.113.1", "203.0.113.2"}


def test_ioc_import_ficheiro_inexistente_falha_com_mensagem(amb, monkeypatch, capsys):
    # 4b-3 (era: excecao sem tratamento): rc 1, nada escrito, sem evento.
    _com_ioc(amb, monkeypatch)
    rc = rodar(monkeypatch, "forensic", "ioc-import", str(amb.raiz / "nao_existe.txt"))
    assert rc == 1
    assert "nada foi importado" in capsys.readouterr().out
    assert not amb.cache.exists()
    assert eventos_ioc(amb) == []


def test_ioc_import_sem_credencial_e_negado_sem_escrever(amb, monkeypatch, capsys):
    # 4b-3 (era test_observado_import_sem_credencial_e_sem_evento).
    f = escrever(amb, "feed.txt", "203.0.113.1\n")
    assert rodar(monkeypatch, "forensic", "ioc-import", f) == 1
    assert not amb.cache.exists()
    assert eventos_ioc(amb) == []
    assert "ioc.write" in capsys.readouterr().out


def test_ioc_import_com_role_sem_ioc_write_e_negado(amb, monkeypatch):
    _com_ioc(amb, monkeypatch, permissoes=("defense.block",))
    f = escrever(amb, "feed.txt", "203.0.113.1\n")
    assert rodar(monkeypatch, "forensic", "ioc-import", f) == 1
    assert not amb.cache.exists()


def test_ioc_import_emite_requested_e_success(amb, monkeypatch):
    chave, _ = _com_ioc(amb, monkeypatch)
    f = escrever(amb, "feed.txt", "203.0.113.1\n203.0.113.2\nlixo\n")
    assert rodar(monkeypatch, "forensic", "ioc-import", f, "--source", "feed_x") == 0
    evs = eventos_ioc(amb)
    assert [e["outcome"] for e in evs] == ["requested", "success"]
    assert evs[0]["payload"] == {"command": "ioc-import", "file": "feed.txt", "source": "feed_x",
                                 "valid_ips": 2, "ignored": 1}
    assert evs[1]["payload"]["imported"] == 2
    assert evs[0]["actor"]["identity"]["key_id"] == chave.id
    assert evs[1]["correlation_id"] == evs[0]["event_id"]
    assert str(amb.raiz) not in json.dumps(evs)      # so o nome do ficheiro, nunca o caminho


def test_importacao_escreve_o_cache_uma_so_vez(amb, monkeypatch):
    _com_ioc(amb, monkeypatch)
    # ATUALIZADO NO 4b-1-1 (antes: uma reescrita completa do cache por IP,
    # chamadas == [1, 2, 3]). Agora: lote unico, uma escrita atomica.
    cfg_existente(amb)
    chamadas = []
    original = atomic_state.escrever_json
    # (a autenticacao tambem grava keys.json: so contam as escritas do cache)
    monkeypatch.setattr(atomic_state, "escrever_json",
                        lambda c, d: (chamadas.append(len(d)) if "ioc_cache" in str(c) else None,
                                      original(c, d))[1])
    f = escrever(amb, "feed.txt", "203.0.113.1\n203.0.113.2\n203.0.113.3\n")
    rodar(monkeypatch, "forensic", "ioc-import", f)
    assert chamadas == [3]
    assert len(ler_cache(amb)) == 3


def test_falha_na_escrita_nao_deixa_importacao_parcial(amb, monkeypatch, capsys):
    # ATUALIZADO NO 4b-3 (era: a OSError subia a main()). Agora: rc 1 com
    # mensagem, tudo ou nada, evento requested+failure, sem temporarios.
    cfg_existente(amb)
    _com_ioc(amb, monkeypatch)
    original = atomic_state._escrever_atomico

    def falha_no_cache(caminho, texto):
        if "ioc_cache" in str(caminho):
            raise OSError("falha simulada")
        return original(caminho, texto)

    monkeypatch.setattr(atomic_state, "_escrever_atomico", falha_no_cache)
    f = escrever(amb, "feed.txt", "203.0.113.1\n203.0.113.2\n203.0.113.3\n")
    assert rodar(monkeypatch, "forensic", "ioc-import", f) == 1
    assert not amb.cache.exists()
    assert "importados" not in capsys.readouterr().out
    assert [e["outcome"] for e in eventos_ioc(amb)] == ["requested", "failure"]


def test_falha_na_escrita_preserva_cache_existente(amb, monkeypatch):
    # ATUALIZADO NO 4b-3: o ficheiro anterior fica byte a byte igual e a
    # CLI devolve 1 em vez de propagar a excecao.
    cfg_existente(amb)
    _com_ioc(amb, monkeypatch)
    entrada_cache(amb, "198.51.100.7", True, {"fonte": "antigo"})
    antes = amb.cache.read_text()
    original = atomic_state._escrever_atomico

    def falha_no_cache(caminho, texto):
        if "ioc_cache" in str(caminho):
            raise OSError("falha")
        return original(caminho, texto)

    monkeypatch.setattr(atomic_state, "_escrever_atomico", falha_no_cache)
    f = escrever(amb, "feed.txt", "203.0.113.1\n")
    assert rodar(monkeypatch, "forensic", "ioc-import", f) == 1
    assert amb.cache.read_text() == antes


def test_import_sobre_cache_corrompido_recusa_sem_alterar(amb, monkeypatch, capsys):
    # 4b-3 (era: JSONDecodeError sem tratamento): rc 1, ficheiro intacto,
    # sem cache vazio criado, evento requested+failure.
    _com_ioc(amb, monkeypatch)
    amb.cache.parent.mkdir(parents=True)
    amb.cache.write_text("{corrompido")
    f = escrever(amb, "feed.txt", "203.0.113.1\n")
    assert rodar(monkeypatch, "forensic", "ioc-import", f) == 1
    assert amb.cache.read_text() == "{corrompido"
    assert [e["outcome"] for e in eventos_ioc(amb)] == ["requested", "failure"]


def test_observado_diretorio_saida_absoluto_escreve_fora_da_raiz(amb, monkeypatch, tmp_path):
    _com_ioc(amb, monkeypatch)
    # OBSERVADO (D4): cache escrito em caminho absoluto fora da raiz.
    fora = tmp_path.parent / (tmp_path.name + "_fora")
    cfg_existente(amb, diretorio_saida=str(fora))
    f = escrever(amb, "feed.txt", "203.0.113.1\n")
    rodar(monkeypatch, "forensic", "ioc-import", f)
    assert (fora / "ioc_cache.json").exists()
    assert not amb.cache.exists()


# ===================================================================
# forensic whois
# ===================================================================

def test_whois_ip_sem_chaves_grava_cache_nao_malicioso(amb, monkeypatch, intel, capsys):
    _com_ioc(amb, monkeypatch)
    rc = rodar(monkeypatch, "forensic", "whois", "203.0.113.5")
    out = capsys.readouterr().out
    assert rc == 0
    assert "GEOLOCATION" in out and "Cidade" in out
    assert "Threat score" not in out  # sem fontes -> score None
    e = ler_cache(amb)["203.0.113.5"]
    assert e["malicioso"] is False
    assert e["dados"]["geo"]["country"] == "ZZ"
    assert ("vt", "203.0.113.5", None) not in intel.chamadas


def test_whois_ip_com_vt_e_abuse_maus_marca_malicioso(amb, monkeypatch, intel, capsys):
    _com_ioc(amb, monkeypatch)
    intel.vt = vt_mau()
    intel.abuse = {"data": {"abuseConfidenceScore": 90}}
    rc = rodar(monkeypatch, "forensic", "whois", "203.0.113.5",
               "--virustotal", "CHAVE_VT", "--abuseipdb", "CHAVE_AB")
    out = capsys.readouterr().out
    assert rc == 0
    assert "Threat score" in out
    e = ler_cache(amb)["203.0.113.5"]
    assert e["malicioso"] is True
    assert set(e["dados"]) == {"geo", "virustotal", "abuseipdb"}
    # a chave de API nao e gravada no cache (so as respostas)
    assert "CHAVE_VT" not in amb.cache.read_text()
    assert "CHAVE_AB" not in amb.cache.read_text()


def test_whois_cache_hit_nao_consulta_nem_regrava(amb, monkeypatch, intel, capsys):
    entrada_cache(amb, "203.0.113.5", False, {"geo": {"country": "AA"}}, horas=1)
    antes = amb.cache.read_text()
    rc = rodar(monkeypatch, "forensic", "whois", "203.0.113.5")
    out = capsys.readouterr().out
    assert rc == 0
    assert "AA" in out
    assert intel.chamadas == []
    assert amb.cache.read_text() == antes


def test_whois_entrada_expirada_e_tratada_como_ausente(amb, monkeypatch, intel):
    _com_ioc(amb, monkeypatch)
    entrada_cache(amb, "203.0.113.5", True, {"fonte": "feed"}, horas=48)
    rodar(monkeypatch, "forensic", "whois", "203.0.113.5")
    assert ("geo", "203.0.113.5") in intel.chamadas


def test_whois_com_ioc_write_nunca_rebaixa_malicioso(amb, monkeypatch, intel):
    # 4b-3 / S1=ii (era ..._rebaixa_para_nao_malicioso): o score da consulta
    # (33.3) seria < 50, mas a gravacao nao rebaixa True para False e a
    # fonte e preservada.
    _com_ioc(amb, monkeypatch)
    entrada_cache(amb, "203.0.113.5", True, {"fonte": "feed_x"})
    intel.vt = vt_limpo()
    rc = rodar(monkeypatch, "forensic", "whois", "203.0.113.5",
               "--no-cache", "--virustotal", "K")
    assert rc == 0
    e = ler_cache(amb)["203.0.113.5"]
    assert e["malicioso"] is True
    assert e["dados"]["fonte"] == "feed_x"
    assert "virustotal" in e["dados"] and "geo" in e["dados"]
    assert ioc_cache.eh_malicioso_conhecido("203.0.113.5") is True


def test_whois_sem_ioc_write_nao_altera_o_cache_existente(amb, monkeypatch, intel, capsys):
    # S1=ii: sem permissao o whois e so leitura; nada muda, nem o rebaixamento.
    entrada_cache(amb, "203.0.113.5", True, {"fonte": "feed_x"})
    antes = amb.cache.read_text()
    intel.vt = vt_limpo()
    rc = rodar(monkeypatch, "forensic", "whois", "203.0.113.5",
               "--no-cache", "--virustotal", "K")
    assert rc == 0
    assert amb.cache.read_text() == antes
    assert "somente leitura" in capsys.readouterr().out


def test_whois_com_ioc_write_preserva_a_fonte(amb, monkeypatch, intel):
    # 4b-3 (era ..._mantem_malicioso_mas_perde_fonte).
    _com_ioc(amb, monkeypatch)
    entrada_cache(amb, "203.0.113.5", True, {"fonte": "feed_x"})
    rodar(monkeypatch, "forensic", "whois", "203.0.113.5", "--no-cache")
    e = ler_cache(amb)["203.0.113.5"]
    assert e["malicioso"] is True
    assert e["dados"]["fonte"] == "feed_x" and "geo" in e["dados"]


def test_observado_no_cache_anterior_nao_malicioso_mantem_falso(amb, monkeypatch, intel):
    _com_ioc(amb, monkeypatch)
    entrada_cache(amb, "203.0.113.5", False, {"geo": {}})
    rodar(monkeypatch, "forensic", "whois", "203.0.113.5", "--no-cache")
    assert ler_cache(amb)["203.0.113.5"]["malicioso"] is False


def test_observado_octetos_fora_de_intervalo_tratados_como_ip(amb, monkeypatch, intel):
    _com_ioc(amb, monkeypatch)
    # OBSERVADO: regex frouxa tambem no whois; grava cache sob a chave crua.
    rodar(monkeypatch, "forensic", "whois", "999.1.1.1")
    assert ("geo", "999.1.1.1") in intel.chamadas
    assert "999.1.1.1" in ler_cache(amb)


def test_whois_dominio_nao_usa_nem_grava_cache(amb, monkeypatch, intel, capsys):
    rc = rodar(monkeypatch, "forensic", "whois", "exemplo.org")
    out = capsys.readouterr().out
    assert rc == 0
    assert "exemplo.org" in out
    assert intel.chamadas == [("whois", "exemplo.org")]
    assert not amb.cache.exists()


def test_whois_sem_credencial_e_somente_leitura_sem_evento(amb, monkeypatch, intel, capsys):
    # 4b-3 (era test_observado_whois_sem_credencial_grava_cache_sem_evento).
    rc = rodar(monkeypatch, "forensic", "whois", "203.0.113.5")
    out = capsys.readouterr().out
    assert rc == 0
    assert "GEOLOCATION" in out          # a consulta funciona
    assert not amb.cache.exists()        # nada gravado
    assert eventos_ioc(amb) == []


def test_whois_com_ioc_write_grava_e_emite_evento(amb, monkeypatch, intel):
    chave, _ = _com_ioc(amb, monkeypatch)
    assert rodar(monkeypatch, "forensic", "whois", "203.0.113.5") == 0
    assert "203.0.113.5" in ler_cache(amb)
    evs = eventos_ioc(amb)
    assert [e["outcome"] for e in evs] == ["requested", "success"]
    assert evs[0]["payload"]["command"] == "whois" and evs[0]["payload"]["ip"] == "203.0.113.5"
    assert evs[0]["actor"]["identity"]["key_id"] == chave.id


def test_whois_com_credencial_invalida_continua_somente_leitura(amb, monkeypatch, intel):
    _com_ioc(amb, monkeypatch)
    monkeypatch.setenv("MORACLE_API_KEY", "token-invalido")
    assert rodar(monkeypatch, "forensic", "whois", "203.0.113.5") == 0
    assert not amb.cache.exists()


def test_whois_com_audit_indisponivel_nao_grava(amb, monkeypatch, intel, capsys):
    from core import security_audit as sa

    class Falha:
        ultimo_erro = "OSError"

        def gravar(self, e):
            return False

        def ids_existentes(self):
            return set()

    _com_ioc(amb, monkeypatch)
    monkeypatch.setattr(rt, "fabrica_auditor", lambda: sa.Auditor(Falha(), Falha(), alertador=_Coletor()))
    assert rodar(monkeypatch, "forensic", "whois", "203.0.113.5") == 1
    assert not amb.cache.exists()
    assert "auditoria indisponivel" in capsys.readouterr().out


def test_ioc_import_com_audit_indisponivel_nao_grava(amb, monkeypatch, capsys):
    from core import security_audit as sa

    class Falha:
        ultimo_erro = "OSError"

        def gravar(self, e):
            return False

        def ids_existentes(self):
            return set()

    _com_ioc(amb, monkeypatch)
    monkeypatch.setattr(rt, "fabrica_auditor", lambda: sa.Auditor(Falha(), Falha(), alertador=_Coletor()))
    f = escrever(amb, "feed.txt", "203.0.113.1\n")
    assert rodar(monkeypatch, "forensic", "ioc-import", f) == 1
    assert not amb.cache.exists()


def test_observado_falha_da_geolocalizacao_levanta_e_nao_grava(amb, monkeypatch, intel):
    intel.levanta = RuntimeError("rede indisponivel")
    with pytest.raises(RuntimeError):
        rodar(monkeypatch, "forensic", "whois", "203.0.113.5")
    assert not amb.cache.exists()


def test_observado_cache_corrompido_quebra_whois_antes_de_consultar(amb, monkeypatch, intel):
    # OBSERVADO: sem --no-cache o obter() levanta antes de qualquer consulta.
    amb.cache.parent.mkdir(parents=True)
    amb.cache.write_text("{corrompido")
    with pytest.raises(json.JSONDecodeError):
        rodar(monkeypatch, "forensic", "whois", "203.0.113.5")
    assert intel.chamadas == []


def test_observado_cache_corrompido_com_no_cache_consulta_e_depois_levanta(
        amb, monkeypatch, intel, capsys):
    # OBSERVADO: o resultado da consulta e impresso e depois perde-se.
    amb.cache.parent.mkdir(parents=True)
    amb.cache.write_text("{corrompido")
    with pytest.raises(json.JSONDecodeError):
        rodar(monkeypatch, "forensic", "whois", "203.0.113.5", "--no-cache")
    assert ("geo", "203.0.113.5") in intel.chamadas
    assert "GEOLOCATION" in capsys.readouterr().out
    assert amb.cache.read_text() == "{corrompido"


# ===================================================================
# Log legado de comandos (core.audit.registrar) - o que ja existe hoje
# ===================================================================

def test_audit_legado_regista_config_set_com_valor_visivel(amb, monkeypatch):
    cfg_existente(amb)
    rodar(monkeypatch, "config", "set", "limite_suspeitos_padrao", "5")
    ult = linhas_audit(amb)[-1]
    assert (ult["grupo"], ult["comando"]) == ("config", "set")
    assert ult["argumentos"]["key"] == "limite_suspeitos_padrao"
    assert ult["argumentos"]["value"] == "5"
    assert "usuario" in ult and "timestamp" in ult


def test_audit_legado_mascara_valor_de_webhook_e_chave_desconhecida(amb, monkeypatch):
    cfg_existente(amb)
    rodar(monkeypatch, "config", "set", "webhook_url", "https://exemplo/segredo")
    rodar(monkeypatch, "config", "set", "chave_inventada", "valor")
    a, b = linhas_audit(amb)[-2:]
    assert a["argumentos"]["value"] == "***"
    assert b["argumentos"]["value"] == "***"
    assert "segredo" not in amb.audit_log.read_text()


def test_audit_legado_mascara_chaves_de_api_no_whois(amb, monkeypatch, intel):
    rodar(monkeypatch, "forensic", "whois", "203.0.113.5",
          "--virustotal", "CHAVE_VT", "--abuseipdb", "CHAVE_AB")
    ult = linhas_audit(amb)[-1]
    assert ult["argumentos"]["virustotal"] == "***"
    assert ult["argumentos"]["abuseipdb"] == "***"
    assert "CHAVE_VT" not in amb.audit_log.read_text()


def test_audit_legado_regista_ioc_import_com_ficheiro_e_fonte(amb, monkeypatch):
    f = escrever(amb, "feed.txt", "203.0.113.1\n")
    rodar(monkeypatch, "forensic", "ioc-import", f, "--source", "feed_x")
    ult = linhas_audit(amb)[-1]
    assert ult["comando"] == "ioc-import"
    assert ult["argumentos"]["file"] == f
    assert ult["argumentos"]["source"] == "feed_x"


def test_observado_audit_legado_regista_tentativa_mesmo_quando_o_comando_falha(
        amb, monkeypatch):
    # OBSERVADO: a linha e escrita ANTES do despacho; nao ha resultado,
    # nem valor persistido, nem identidade alem do utilizador do SO.
    # Uma tentativa falhada e um sucesso sao indistinguiveis neste log.
    # (4b-3: o comando falha com rc 1 em vez de levantar a excecao.)
    _com_ioc(amb, monkeypatch)
    assert rodar(monkeypatch, "forensic", "ioc-import", str(amb.raiz / "nao_existe.txt")) == 1
    assert linhas_audit(amb)[-1]["comando"] == "ioc-import"
    assert set(linhas_audit(amb)[-1]) == {"timestamp", "usuario", "grupo", "comando", "argumentos"}


def test_audit_legado_regista_pedido_rejeitado_sem_alterar_o_config(amb, monkeypatch):
    # 4b-2 (era test_observado_..._valor_pedido_nao_o_persistido): `idioma xx`
    # e rejeitado; o log legado regista o PEDIDO e o config nao muda.
    cfg_existente(amb)
    antes = amb.config.read_text()
    rodar(monkeypatch, "config", "set", "idioma", "xx")
    assert linhas_audit(amb)[-1]["argumentos"]["value"] == "xx"
    assert amb.config.read_text() == antes
