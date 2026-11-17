import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import socket
import time

from server.server import Server, ServerConfig
from core.moracle_adapter import build_router
from core.moracle_middleware import auth_middleware
from core.api_key import obter_ou_criar
from core.identity import migrate_legacy_admin_key
from core import config as core_config


import pytest

pytestmark = pytest.mark.usefixtures("estado_isolado")

def _porta_livre():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    porta = s.getsockname()[1]
    s.close()
    return porta


def _subir():
    obter_ou_criar()
    migrate_legacy_admin_key(os.path.join(core_config.RAIZ_PROJETO, '.state'))
    porta = _porta_livre()
    config = ServerConfig(host="127.0.0.1", port=porta, max_workers=5)
    router = build_router()
    servidor = Server(config, router, middlewares=[auth_middleware])
    servidor.start(block=False)
    time.sleep(0.2)
    return servidor, porta


def _http(porta, metodo, path, corpo=None, headers=None, timeout=3):
    headers = headers or {}
    corpo_bytes = json.dumps(corpo).encode() if corpo is not None else b""
    linhas = [f"{metodo} {path} HTTP/1.1", "Host: x", "Connection: close"]
    if corpo is not None:
        linhas.append(f"Content-Length: {len(corpo_bytes)}")
        linhas.append("Content-Type: application/json")
    for nome, valor in headers.items():
        linhas.append(f"{nome}: {valor}")
    requisicao = ("\r\n".join(linhas) + "\r\n\r\n").encode() + corpo_bytes

    with socket.create_connection(("127.0.0.1", porta), timeout=timeout) as sock:
        sock.sendall(requisicao)
        sock.settimeout(timeout)
        resposta = b""
        try:
            while True:
                pedaco = sock.recv(4096)
                if not pedaco:
                    break
                resposta += pedaco
        except socket.timeout:
            pass
        return resposta


def test_health_no_auth_required():
    servidor, porta = _subir()
    try:
        resposta = _http(porta, "GET", "/health")
        assert b"200 OK" in resposta
        assert b'"status": "ok"' in resposta
    finally:
        servidor.stop()


def test_status_requires_auth_401_without_key():
    servidor, porta = _subir()
    try:
        resposta = _http(porta, "GET", "/status")
        assert b"401" in resposta
    finally:
        servidor.stop()


def test_status_with_valid_key():
    servidor, porta = _subir()
    chave = obter_ou_criar()
    try:
        resposta = _http(porta, "GET", "/status", headers={"Authorization": f"Bearer {chave}"})
        assert b"200 OK" in resposta
        assert b'"ativo"' in resposta
    finally:
        servidor.stop()


def test_ingest_detects_sql_injection_and_blocks():
    servidor, porta = _subir()
    chave = obter_ou_criar()
    try:
        payload = {
            "ip": "198.51.100.77",
            "method": "GET",
            "path": "/product?id=1 UNION SELECT NULL--",
            "user_agent": "curl/8.0",
            "status_code": 200,
        }
        resposta = _http(porta, "POST", "/ingest", corpo=payload, headers={"Authorization": f"Bearer {chave}"})
        assert b"200 OK" in resposta
        assert b'"detected": true' in resposta
        assert b"sql_injection" in resposta

        status_resp = _http(porta, "GET", "/blocklist", headers={"Authorization": f"Bearer {chave}"})
        assert b"198.51.100.77" in status_resp
    finally:
        servidor.stop()


def test_ingest_clean_request_not_detected():
    servidor, porta = _subir()
    chave = obter_ou_criar()
    try:
        payload = {"ip": "203.0.113.1", "method": "GET", "path": "/index.html", "user_agent": "Mozilla", "status_code": 200}
        resposta = _http(porta, "POST", "/ingest", corpo=payload, headers={"Authorization": f"Bearer {chave}"})
        assert b'"detected": false' in resposta
    finally:
        servidor.stop()


def test_block_manual():
    servidor, porta = _subir()
    chave = obter_ou_criar()
    try:
        resposta = _http(porta, "POST", "/block", corpo={"ip": "192.0.2.50", "reason": "teste manual"}, headers={"Authorization": f"Bearer {chave}"})
        assert b"200 OK" in resposta
        assert b"192.0.2.50" in resposta
    finally:
        servidor.stop()


def test_invalid_key_rejected():
    servidor, porta = _subir()
    try:
        resposta = _http(porta, "GET", "/status", headers={"Authorization": "Bearer chave-errada"})
        assert b"401" in resposta
    finally:
        servidor.stop()


# ---------------------------------------------------------------------------
# Autorização por permissão nas rotas de defesa (Pacote 1)
# ---------------------------------------------------------------------------

def _subir_com_admin():
    from admin_api.router import registrar_rotas_admin
    obter_ou_criar()
    migrate_legacy_admin_key(os.path.join(core_config.RAIZ_PROJETO, '.state'))
    porta = _porta_livre()
    router = build_router()
    registrar_rotas_admin(router)
    servidor = Server(ServerConfig(host="127.0.0.1", port=porta, max_workers=5), router, middlewares=[auth_middleware])
    servidor.start(block=False)
    time.sleep(0.2)
    return servidor, porta


def _chave_com_permissoes(porta, nome, permissoes):
    admin = {"Authorization": f"Bearer {obter_ou_criar()}"}
    r = _http(porta, "POST", "/admin/roles", corpo={"name": nome, "permissions": permissoes}, headers=admin)
    assert b" 201 " in r, r
    r = _http(porta, "POST", "/admin/keys", corpo={"name": f"chave-{nome}", "role": nome}, headers=admin)
    assert b" 201 " in r, r
    return {"Authorization": "Bearer " + json.loads(r.split(b"\r\n\r\n", 1)[1])["secret"]}


def test_chave_ingest_nao_bloqueia_403():
    servidor, porta = _subir_com_admin()
    try:
        ingest = _chave_com_permissoes(porta, "so-ingest", ["ingest.write"])
        r = _http(porta, "POST", "/block", corpo={"ip": "203.0.113.50"}, headers=ingest)
        assert b" 403 " in r
        admin = {"Authorization": f"Bearer {obter_ou_criar()}"}
        assert b"203.0.113.50" not in _http(porta, "GET", "/blocklist", headers=admin)
    finally:
        servidor.stop()


def test_chave_ingest_nao_le_rotas_de_defesa_403():
    servidor, porta = _subir_com_admin()
    try:
        ingest = _chave_com_permissoes(porta, "so-ingest", ["ingest.write"])
        for rota in ("/status", "/blocklist", "/alerts"):
            assert b" 403 " in _http(porta, "GET", rota, headers=ingest), rota
    finally:
        servidor.stop()


def test_chave_ingest_pode_ingerir_200():
    servidor, porta = _subir_com_admin()
    try:
        ingest = _chave_com_permissoes(porta, "so-ingest", ["ingest.write"])
        payload = {"ip": "203.0.113.1", "method": "GET", "path": "/index.html", "user_agent": "Mozilla", "status_code": 200}
        r = _http(porta, "POST", "/ingest", corpo=payload, headers=ingest)
        assert b" 200 " in r
        assert b'"detected": false' in r
    finally:
        servidor.stop()


def test_chave_defense_read_nao_ingere_nem_bloqueia_403():
    servidor, porta = _subir_com_admin()
    try:
        leitura = _chave_com_permissoes(porta, "so-leitura", ["defense.read"])
        payload = {"ip": "203.0.113.1", "method": "GET", "path": "/", "user_agent": "x", "status_code": 200}
        assert b" 403 " in _http(porta, "POST", "/ingest", corpo=payload, headers=leitura)
        assert b" 403 " in _http(porta, "POST", "/block", corpo={"ip": "203.0.113.50"}, headers=leitura)
    finally:
        servidor.stop()


def test_chave_defense_read_le_rotas_de_defesa_200():
    servidor, porta = _subir_com_admin()
    try:
        leitura = _chave_com_permissoes(porta, "so-leitura", ["defense.read"])
        for rota in ("/status", "/blocklist", "/alerts"):
            assert b" 200 " in _http(porta, "GET", rota, headers=leitura), rota
    finally:
        servidor.stop()


def test_chave_defense_block_bloqueia_mas_nao_le():
    servidor, porta = _subir_com_admin()
    try:
        bloqueio = _chave_com_permissoes(porta, "so-bloqueio", ["defense.block"])
        r = _http(porta, "POST", "/block", corpo={"ip": "203.0.113.60"}, headers=bloqueio)
        assert b" 200 " in r
        assert b" 403 " in _http(porta, "GET", "/blocklist", headers=bloqueio)
    finally:
        servidor.stop()


def test_wrapper_sem_api_key_no_context_devolve_401():
    from core.http_authz import requer_permissao
    handler = requer_permissao("defense.block")(lambda request, context: "chamado")
    resposta = handler(None, {})
    assert resposta != "chamado"
    assert 401 in (getattr(resposta, "status", None), getattr(resposta, "status_code", None))


def test_requer_permissao_rejeita_permissao_desconhecida():
    from core.http_authz import requer_permissao
    with pytest.raises(ValueError):
        requer_permissao("defense.blok")


# ---------------------------------------------------------------------------
# Autorização por permissão nas rotas de defesa (Pacote 1)
# ---------------------------------------------------------------------------

def _subir_com_admin():
    from admin_api.router import registrar_rotas_admin
    obter_ou_criar()
    migrate_legacy_admin_key(os.path.join(core_config.RAIZ_PROJETO, '.state'))
    porta = _porta_livre()
    router = build_router()
    registrar_rotas_admin(router)
    servidor = Server(ServerConfig(host="127.0.0.1", port=porta, max_workers=5), router, middlewares=[auth_middleware])
    servidor.start(block=False)
    time.sleep(0.2)
    return servidor, porta


def _chave_com_permissoes(porta, nome, permissoes):
    admin = {"Authorization": f"Bearer {obter_ou_criar()}"}
    r = _http(porta, "POST", "/admin/roles", corpo={"name": nome, "permissions": permissoes}, headers=admin)
    assert b" 201 " in r, r
    r = _http(porta, "POST", "/admin/keys", corpo={"name": f"chave-{nome}", "role": nome}, headers=admin)
    assert b" 201 " in r, r
    return {"Authorization": "Bearer " + json.loads(r.split(b"\r\n\r\n", 1)[1])["secret"]}


def test_chave_ingest_nao_bloqueia_403():
    servidor, porta = _subir_com_admin()
    try:
        ingest = _chave_com_permissoes(porta, "so-ingest", ["ingest.write"])
        r = _http(porta, "POST", "/block", corpo={"ip": "203.0.113.50"}, headers=ingest)
        assert b" 403 " in r
        admin = {"Authorization": f"Bearer {obter_ou_criar()}"}
        assert b"203.0.113.50" not in _http(porta, "GET", "/blocklist", headers=admin)
    finally:
        servidor.stop()


def test_chave_ingest_nao_le_rotas_de_defesa_403():
    servidor, porta = _subir_com_admin()
    try:
        ingest = _chave_com_permissoes(porta, "so-ingest", ["ingest.write"])
        for rota in ("/status", "/blocklist", "/alerts"):
            assert b" 403 " in _http(porta, "GET", rota, headers=ingest), rota
    finally:
        servidor.stop()


def test_chave_ingest_pode_ingerir_200():
    servidor, porta = _subir_com_admin()
    try:
        ingest = _chave_com_permissoes(porta, "so-ingest", ["ingest.write"])
        payload = {"ip": "203.0.113.1", "method": "GET", "path": "/index.html", "user_agent": "Mozilla", "status_code": 200}
        r = _http(porta, "POST", "/ingest", corpo=payload, headers=ingest)
        assert b" 200 " in r
        assert b'"detected": false' in r
    finally:
        servidor.stop()


def test_chave_defense_read_nao_ingere_nem_bloqueia_403():
    servidor, porta = _subir_com_admin()
    try:
        leitura = _chave_com_permissoes(porta, "so-leitura", ["defense.read"])
        payload = {"ip": "203.0.113.1", "method": "GET", "path": "/", "user_agent": "x", "status_code": 200}
        assert b" 403 " in _http(porta, "POST", "/ingest", corpo=payload, headers=leitura)
        assert b" 403 " in _http(porta, "POST", "/block", corpo={"ip": "203.0.113.50"}, headers=leitura)
    finally:
        servidor.stop()


def test_chave_defense_read_le_rotas_de_defesa_200():
    servidor, porta = _subir_com_admin()
    try:
        leitura = _chave_com_permissoes(porta, "so-leitura", ["defense.read"])
        for rota in ("/status", "/blocklist", "/alerts"):
            assert b" 200 " in _http(porta, "GET", rota, headers=leitura), rota
    finally:
        servidor.stop()


def test_chave_defense_block_bloqueia_mas_nao_le():
    servidor, porta = _subir_com_admin()
    try:
        bloqueio = _chave_com_permissoes(porta, "so-bloqueio", ["defense.block"])
        r = _http(porta, "POST", "/block", corpo={"ip": "203.0.113.60"}, headers=bloqueio)
        assert b" 200 " in r
        assert b" 403 " in _http(porta, "GET", "/blocklist", headers=bloqueio)
    finally:
        servidor.stop()


def test_wrapper_sem_api_key_no_context_devolve_401():
    from core.http_authz import requer_permissao
    handler = requer_permissao("defense.block")(lambda request, context: "chamado")
    resposta = handler(None, {})
    assert resposta != "chamado"
    assert 401 in (getattr(resposta, "status", None), getattr(resposta, "status_code", None))


def test_requer_permissao_rejeita_permissao_desconhecida():
    from core.http_authz import requer_permissao
    with pytest.raises(ValueError):
        requer_permissao("defense.blok")


# ---------------------------------------------------------------------------
# Validação de entrada da defesa (Pacote 2)
# ---------------------------------------------------------------------------

def _auth():
    return {"Authorization": f"Bearer {obter_ou_criar()}"}


_SQLI = {"method": "GET", "path": "/product?id=1 UNION SELECT NULL--", "user_agent": "curl/8.0", "status_code": 200}


def test_block_expires_hours_invalido_400_e_nao_grava():
    servidor, porta = _subir()
    try:
        for ruim in ("x", "5", True, -1, 10**9):
            r = _http(porta, "POST", "/block", corpo={"ip": "203.0.113.70", "expires_hours": ruim}, headers=_auth())
            assert b" 400 " in r, ruim
        assert b"203.0.113.70" not in _http(porta, "GET", "/blocklist", headers=_auth())
    finally:
        servidor.stop()


def test_block_ip_invalido_ou_nao_bloqueavel_400():
    servidor, porta = _subir()
    try:
        for ruim in ("999.1.1.1", "127.0.0.1", "::1", "0.0.0.0", "abc", 5, ["1.1.1.1"]):
            r = _http(porta, "POST", "/block", corpo={"ip": ruim}, headers=_auth())
            assert b" 400 " in r, ruim
    finally:
        servidor.stop()


def test_block_corpo_nao_objeto_400():
    servidor, porta = _subir()
    try:
        assert b" 400 " in _http(porta, "POST", "/block", corpo=[1, 2], headers=_auth())
    finally:
        servidor.stop()


def test_block_ipv6_valido_200():
    servidor, porta = _subir()
    try:
        r = _http(porta, "POST", "/block", corpo={"ip": "2001:db8::1", "expires_hours": 1}, headers=_auth())
        assert b" 200 " in r
        assert b"2001:db8::1" in _http(porta, "GET", "/blocklist", headers=_auth())
    finally:
        servidor.stop()


def test_ingest_loopback_detecta_mas_nao_bloqueia():
    servidor, porta = _subir()
    try:
        r = _http(porta, "POST", "/ingest", corpo=dict(_SQLI, ip="127.0.0.1"), headers=_auth())
        assert b" 200 " in r and b'"detected": true' in r
        assert b"127.0.0.1" not in _http(porta, "GET", "/blocklist", headers=_auth())
    finally:
        servidor.stop()


def test_ingest_ip_nao_texto_nao_da_erro():
    servidor, porta = _subir()
    try:
        r = _http(porta, "POST", "/ingest", corpo=dict(_SQLI, ip=5), headers=_auth())
        assert b" 200 " in r and b'"detected": true' in r
    finally:
        servidor.stop()


def test_ingest_ipv6_bloqueia():
    servidor, porta = _subir()
    try:
        r = _http(porta, "POST", "/ingest", corpo=dict(_SQLI, ip="2001:db8::77"), headers=_auth())
        assert b'"detected": true' in r
        assert b"2001:db8::77" in _http(porta, "GET", "/blocklist", headers=_auth())
    finally:
        servidor.stop()


def test_alerts_limit_fora_da_faixa_nao_quebra():
    servidor, porta = _subir()
    try:
        for lim in ("0", "-5", "99999", "abc"):
            assert b" 200 " in _http(porta, "GET", f"/alerts?limit={lim}", headers=_auth()), lim
    finally:
        servidor.stop()
