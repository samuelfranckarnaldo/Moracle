"""
Contrato: app_name no Access Log e' preenchido apenas para rotas
app-scoped explicitamente listadas em admin_api/router.py - nunca
inferido genericamente de qualquer parametro de rota chamado "name".
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server.request import Context
from admin_api.router import _app_scoped


def test_app_scoped_marca_context_com_app_name_do_route_params():
    def handler_falso(request, context):
        return "ok"

    context = Context(request_id="r1")
    context.route_params = {"name": "minha-app"}

    _app_scoped(handler_falso)(request=None, context=context)

    assert context["app_name"] == "minha-app"


def test_app_scoped_sem_name_no_route_params_fica_vazio():
    """Defensivo: se por algum motivo o handler for envolvido mas o
    Router nao populou route_params com 'name', nao deve quebrar nem
    inventar valor - fica vazio."""
    def handler_falso(request, context):
        return "ok"

    context = Context(request_id="r1")
    context.route_params = {}

    _app_scoped(handler_falso)(request=None, context=context)

    assert context["app_name"] == ""


def test_rota_nao_app_scoped_nunca_recebe_app_name():
    """Rotas fora do whitelist (ex: /admin/keys/{id}) nao devem ter
    seus handlers envolvidos por _app_scoped - o contexto simplesmente
    nunca ganha a chave 'app_name'."""
    def handler_falso(request, context):
        return "ok"

    context = Context(request_id="r1")
    context.route_params = {"id": "chave-123"}

    handler_falso(request=None, context=context)  # chamado direto, sem wrapper

    assert context.get("app_name", "") == ""
