"""
Endurecimento para a primeira versao publica:
  - chave legada api_key.txt criada ja com 0600 (sem janela) e permissoes
    largas de versoes antigas corrigidas na leitura;
  - cliente da Admin API: TLS verificado fora de loopback;
  - aviso de HTTP simples fora de loopback.
"""
import os
import ssl
import stat
import threading

import pytest

from admin_api import client
from core import api_key


@pytest.fixture
def chave_tmp(tmp_path, monkeypatch):
    caminho = tmp_path / ".state" / "api_key.txt"
    monkeypatch.setattr(api_key, "KEY_PATH", str(caminho))
    return caminho


def modo(p):
    return stat.S_IMODE(os.stat(p).st_mode)


def test_chave_e_criada_com_0600_mesmo_com_umask_aberta(chave_tmp):
    antigo = os.umask(0)
    try:
        valor = api_key.obter_ou_criar()
    finally:
        os.umask(antigo)
    assert modo(chave_tmp) == 0o600
    assert len(valor) == 64


def test_chave_e_estavel_entre_chamadas(chave_tmp):
    assert api_key.obter_ou_criar() == api_key.obter_ou_criar()


def test_permissoes_largas_de_versao_antiga_sao_fechadas(chave_tmp):
    chave_tmp.parent.mkdir(parents=True)
    chave_tmp.write_text("abc")
    os.chmod(chave_tmp, 0o644)
    assert api_key.obter_ou_criar() == "abc"
    assert modo(chave_tmp) == 0o600


def test_criacao_concorrente_converge_na_mesma_chave(chave_tmp):
    resultados = []

    def criar():
        resultados.append(api_key.obter_ou_criar())

    ths = [threading.Thread(target=criar) for _ in range(8)]
    [t.start() for t in ths]
    [t.join() for t in ths]
    assert len(set(resultados)) == 1
    assert chave_tmp.read_text().strip() == resultados[0]


def test_validar_continua_a_funcionar(chave_tmp):
    k = api_key.obter_ou_criar()
    assert api_key.validar(k) is True
    assert api_key.validar("x") is False and api_key.validar("") is False


def test_loopback_nao_verifica_certificado():
    for host in ("127.0.0.1", "localhost", "::1", "127.1.2.3"):
        ctx = client._contexto_tls(host)
        assert ctx.verify_mode == ssl.CERT_NONE and ctx.check_hostname is False, host


def test_host_remoto_verifica_cadeia_e_nome():
    for host in ("exemplo.org", "203.0.113.5", "10.0.0.5", "moracle.interno"):
        ctx = client._contexto_tls(host)
        assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname is True, host


def test_host_vazio_ou_estranho_nao_e_tratado_como_loopback():
    for host in (None, "", "127.0.0.1.exemplo.org", "localhost.exemplo.org"):
        assert client._eh_loopback(host) is False, host


def test_ca_propria_via_variavel_de_ambiente(monkeypatch, tmp_path):
    monkeypatch.setenv("MORACLE_CA_FILE", str(tmp_path / "nao_existe.pem"))
    with pytest.raises((FileNotFoundError, ssl.SSLError, OSError)):
        client._contexto_tls("exemplo.org")   # o ficheiro e mesmo usado
