import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tempfile
from server.router import Router
from server.request import Context
from admin_api.static_files import criar_handler_estatico


def test_serves_index_file():
    with tempfile.TemporaryDirectory() as diretorio:
        with open(os.path.join(diretorio, "index.html"), "w") as f:
            f.write("<html>ok</html>")

        handler = criar_handler_estatico(diretorio)
        context = Context(request_id="x")
        context.route_params = {}

        resposta = handler(None, context)
        assert resposta.status == 200
        assert b"ok" in resposta.body


def test_blocks_path_traversal():
    with tempfile.TemporaryDirectory() as diretorio:
        with open(os.path.join(diretorio, "index.html"), "w") as f:
            f.write("ok")

        handler = criar_handler_estatico(diretorio)
        context = Context(request_id="x")
        context.route_params = {"path": "../../../etc/passwd"}

        resposta = handler(None, context)
        assert resposta.status in (403, 404)


def test_404_for_missing_file():
    with tempfile.TemporaryDirectory() as diretorio:
        handler = criar_handler_estatico(diretorio)
        context = Context(request_id="x")
        context.route_params = {"path": "nao-existe.js"}

        resposta = handler(None, context)
        assert resposta.status == 404


def test_correct_mime_type_for_html():
    with tempfile.TemporaryDirectory() as diretorio:
        with open(os.path.join(diretorio, "pagina.html"), "w") as f:
            f.write("<html></html>")

        handler = criar_handler_estatico(diretorio)
        context = Context(request_id="x")
        context.route_params = {"path": "pagina.html"}

        resposta = handler(None, context)
        assert resposta.headers["Content-Type"] == "text/html"


def test_spa_fallback_serves_index_for_route_without_extension():
    with tempfile.TemporaryDirectory() as diretorio:
        with open(os.path.join(diretorio, "index.html"), "w") as f:
            f.write("<html>spa-shell</html>")

        handler = criar_handler_estatico(diretorio, spa_fallback=True)
        context = Context(request_id="x")
        context.route_params = {"path": "apps/app-a"}

        resposta = handler(None, context)
        assert resposta.status == 200
        assert b"spa-shell" in resposta.body


def test_spa_fallback_still_404_for_missing_file_with_extension():
    with tempfile.TemporaryDirectory() as diretorio:
        with open(os.path.join(diretorio, "index.html"), "w") as f:
            f.write("<html>spa-shell</html>")

        handler = criar_handler_estatico(diretorio, spa_fallback=True)
        context = Context(request_id="x")
        context.route_params = {"path": "nao-existe.js"}

        resposta = handler(None, context)
        assert resposta.status == 404


def test_spa_fallback_serves_real_asset_normally():
    with tempfile.TemporaryDirectory() as diretorio:
        with open(os.path.join(diretorio, "index.html"), "w") as f:
            f.write("<html>spa-shell</html>")
        with open(os.path.join(diretorio, "style.css"), "w") as f:
            f.write("body { color: green; }")

        handler = criar_handler_estatico(diretorio, spa_fallback=True)
        context = Context(request_id="x")
        context.route_params = {"path": "style.css"}

        resposta = handler(None, context)
        assert resposta.status == 200
        assert b"color: green" in resposta.body


def test_spa_fallback_disabled_by_default_returns_404_for_route():
    """Garante que o default (False) preserva o comportamento antigo:
    sem spa_fallback, uma rota sem arquivo fisico correspondente
    continua sendo 404, nao index.html."""
    with tempfile.TemporaryDirectory() as diretorio:
        with open(os.path.join(diretorio, "index.html"), "w") as f:
            f.write("<html>ok</html>")

        handler = criar_handler_estatico(diretorio)  # spa_fallback nao passado
        context = Context(request_id="x")
        context.route_params = {"path": "apps/app-a"}

        resposta = handler(None, context)
        assert resposta.status == 404
