"""
Testes de HostRouter: resolucao por dominio + identidade de
aplicacao como parte inseparavel da mesma associacao (invariantes
1-5 do contrato de Access Log Estruturado).
"""
import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from deploy_platform.host_router import HostRouter
from server.errors import NotFoundError


class _RouterFalso:
    """Substituto simples - HostRouter nao precisa saber o que e um
    Router de verdade, so precisa devolver o objeto associado."""
    def __init__(self, nome):
        self.nome = nome

    def __repr__(self):
        return f"_RouterFalso({self.nome!r})"


def test_registrar_e_resolver_router_por_dominio():
    hr = HostRouter()
    router_a = _RouterFalso("a")
    hr.registrar_dominio("app-a.local", router_a, "app_a")

    assert hr.resolver_router("app-a.local") is router_a


def test_resolver_app_name_por_dominio():
    hr = HostRouter()
    hr.registrar_dominio("app-a.local", _RouterFalso("a"), "app_a")

    assert hr.resolver_app_name("app-a.local") == "app_a"


def test_dois_dominios_duas_identidades_nao_vazam_entre_si():
    """Teste explicitamente exigido: dominio A -> app_a, dominio B ->
    app_b, resolucoes nao podem se misturar."""
    hr = HostRouter()
    router_a, router_b = _RouterFalso("a"), _RouterFalso("b")
    hr.registrar_dominio("a.local", router_a, "app_a")
    hr.registrar_dominio("b.local", router_b, "app_b")

    assert hr.resolver_router("a.local") is router_a
    assert hr.resolver_app_name("a.local") == "app_a"
    assert hr.resolver_router("b.local") is router_b
    assert hr.resolver_app_name("b.local") == "app_b"


def test_host_header_com_porta_ignora_porta():
    hr = HostRouter()
    hr.registrar_dominio("app-a.local", _RouterFalso("a"), "app_a")

    assert hr.resolver_app_name("app-a.local:8443") == "app_a"


def test_dominio_nao_registrado_sem_padrao_levanta_not_found():
    hr = HostRouter()
    with pytest.raises(NotFoundError):
        hr.resolver_router("desconhecido.local")
    with pytest.raises(NotFoundError):
        hr.resolver_app_name("desconhecido.local")


def test_dominio_nao_registrado_com_padrao_cai_no_padrao():
    """Nao deve atribuir aplicacao incorreta - cai explicitamente no
    padrao configurado, nunca inventa um app_name."""
    hr = HostRouter()
    router_padrao = _RouterFalso("padrao")
    hr.definir_padrao(router_padrao, "app_padrao")

    assert hr.resolver_router("desconhecido.local") is router_padrao
    assert hr.resolver_app_name("desconhecido.local") == "app_padrao"


def test_sem_host_header_sem_padrao_levanta_not_found():
    hr = HostRouter()
    with pytest.raises(NotFoundError):
        hr.resolver_router(None)
    with pytest.raises(NotFoundError):
        hr.resolver_router("")


def test_sem_host_header_com_padrao_resolve_padrao():
    hr = HostRouter()
    router_padrao = _RouterFalso("padrao")
    hr.definir_padrao(router_padrao, "app_padrao")

    assert hr.resolver_router(None) is router_padrao
    assert hr.resolver_app_name(None) == "app_padrao"


def test_registrar_dominio_com_app_name_vazio_rejeitado():
    hr = HostRouter()
    with pytest.raises(ValueError):
        hr.registrar_dominio("a.local", _RouterFalso("a"), "")


def test_registrar_dominio_com_app_name_none_rejeitado():
    hr = HostRouter()
    with pytest.raises(ValueError):
        hr.registrar_dominio("a.local", _RouterFalso("a"), None)


def test_definir_padrao_com_app_name_vazio_rejeitado():
    hr = HostRouter()
    with pytest.raises(ValueError):
        hr.definir_padrao(_RouterFalso("a"), "")


def test_remover_dominio_remove_router_e_app_name_juntos():
    """Invariante 3: remocao de dominio remove tambem sua identidade -
    nenhum dos dois pode sobreviver sozinho."""
    hr = HostRouter()
    hr.registrar_dominio("a.local", _RouterFalso("a"), "app_a")

    hr.remover_dominio("a.local")

    with pytest.raises(NotFoundError):
        hr.resolver_router("a.local")
    with pytest.raises(NotFoundError):
        hr.resolver_app_name("a.local")


def test_remover_dominio_nao_registrado_nao_levanta_erro():
    hr = HostRouter()
    hr.remover_dominio("nunca-existiu.local")  # nao deve levantar


def test_reregistrar_dominio_atualiza_router_e_app_name_atomicamente():
    """Invariante 4: re-registrar atualiza os dois de forma
    consistente - nunca router novo com app_name antigo ou vice-versa."""
    hr = HostRouter()
    router_v1, router_v2 = _RouterFalso("v1"), _RouterFalso("v2")
    hr.registrar_dominio("a.local", router_v1, "app_a_v1")

    hr.registrar_dominio("a.local", router_v2, "app_a_v2")

    assert hr.resolver_router("a.local") is router_v2
    assert hr.resolver_app_name("a.local") == "app_a_v2"
