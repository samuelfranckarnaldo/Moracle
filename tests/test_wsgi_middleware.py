"""
tests/test_wsgi_middleware.py

Prova minima e objetiva do contrato de autenticacao de
integrations/wsgi_middleware.py — superficie de integracao PUBLICA
(consumida por aplicacoes de terceiros, ex. Flask, via
app.wsgi_app = MoracleMiddleware(...)).

O middleware deve enviar:

    Authorization: Bearer <api_key>

e NUNCA o header legado:

    X-Moracle-Key

Sem suporte a compatibilidade dupla — apenas o novo contrato e aceito.

_post() roda em thread daemon separada (disparada por _enviar_async),
entao o teste precisa aguardar essa thread terminar antes de inspecionar
a requisicao capturada pelo mock, evitando race entre o assert e o
envio assincrono.
"""

import threading
from unittest.mock import patch, MagicMock

from integrations.wsgi_middleware import MoracleMiddleware


def _wsgi_environ():
    return {
        "REMOTE_ADDR": "203.0.113.5",
        "REQUEST_METHOD": "GET",
        "PATH_INFO": "/produto",
        "QUERY_STRING": "id=1",
        "HTTP_USER_AGENT": "pytest-client/1.0",
    }


def _app_wsgi_fake(environ, start_response):
    start_response("200 OK", [("Content-Type", "text/plain")])
    return [b"ok"]


def _disparar_e_aguardar(api_key):
    """Constroi o middleware, dispara uma requisicao WSGI e aguarda a
    thread daemon interna terminar antes de retornar."""
    threads_antes = set(threading.enumerate())

    middleware = MoracleMiddleware(_app_wsgi_fake, url="http://localhost:7331", api_key=api_key)
    middleware(_wsgi_environ(), lambda status, headers: None)

    threads_novas = set(threading.enumerate()) - threads_antes
    for t in threads_novas:
        t.join(timeout=2)


def test_wsgi_middleware_envia_authorization_bearer():
    mock_urlopen = MagicMock()

    with patch("urllib.request.urlopen", mock_urlopen):
        _disparar_e_aguardar(api_key="segredo-wsgi")

    assert mock_urlopen.called
    req_enviado = mock_urlopen.call_args[0][0]

    assert req_enviado.get_header("Authorization") == "Bearer segredo-wsgi"


def test_wsgi_middleware_nao_envia_x_moracle_key():
    mock_urlopen = MagicMock()

    with patch("urllib.request.urlopen", mock_urlopen):
        _disparar_e_aguardar(api_key="segredo-wsgi")

    assert mock_urlopen.called
    req_enviado = mock_urlopen.call_args[0][0]

    # urllib.request.Request normaliza nomes de header (capitaliza),
    # entao checamos por qualquer variante de X-Moracle-Key.
    todos_headers = {k.lower(): v for k, v in req_enviado.header_items()}
    assert "x-moracle-key" not in todos_headers
