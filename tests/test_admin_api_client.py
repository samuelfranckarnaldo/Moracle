"""
tests/test_admin_api_client.py

Prova mínima e objetiva do contrato de autenticacao do AdminAPIClient
(admin_api/client.py): o cliente deve enviar

    Authorization: Bearer <api_key>

e NUNCA o header legado

    X-Moracle-Key

Nao testa o cliente HTTP como um todo (isso e dívida de cobertura
preexistente, registrada separadamente) - apenas fecha a lacuna
especifica que a migracao do Passo 4A expos: nenhum teste existente
provava qual header o cliente de fato envia.

Intercepta http.client.HTTPConnection via unittest.mock para capturar
os headers reais montados por _request(), sem depender de rede.
"""

import json
from unittest.mock import patch, MagicMock

from admin_api.client import AdminAPIClient


def _mock_connection(status=200, body_json=None):
    """Constroi um mock de http.client.HTTPConnection cuja getresponse()
    devolve o status/corpo fornecidos."""
    conn = MagicMock()
    resposta = MagicMock()
    resposta.status = status
    resposta.read.return_value = json.dumps(body_json or {}).encode()
    conn.getresponse.return_value = resposta
    return conn


def test_client_envia_authorization_bearer():
    client = AdminAPIClient(base_url="http://127.0.0.1:9999", api_key="segredo-do-cliente")
    conn = _mock_connection(status=200, body_json={"applications": []})

    with patch("http.client.HTTPConnection", return_value=conn):
        client.list_apps()

    headers_enviados = conn.request.call_args.kwargs["headers"]

    assert headers_enviados.get("Authorization") == "Bearer segredo-do-cliente"


def test_client_nao_envia_x_moracle_key():
    client = AdminAPIClient(base_url="http://127.0.0.1:9999", api_key="segredo-do-cliente")
    conn = _mock_connection(status=200, body_json={"applications": []})

    with patch("http.client.HTTPConnection", return_value=conn):
        client.list_apps()

    headers_enviados = conn.request.call_args.kwargs["headers"]

    assert "X-Moracle-Key" not in headers_enviados
    assert "x-moracle-key" not in {h.lower() for h in headers_enviados}
