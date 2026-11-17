"""
Roteamento por dominio (Host header) - camada da Platform, NAO do
nucleo server/. Cada Application tem seu proprio server.router.Router
interno; este componente decide QUAL router usar com base no Host,
antes de delegar para o Router real daquele app.

server/router.py permanece intocado - isso e' composicao, nao
modificacao do nucleo.

Identidade de aplicacao (app_name) e parte inseparavel da associacao
dominio->router: nao existem dois mapas paralelos que podem divergir.
Todo dominio registrado - incluindo o padrao - possui app_name
obrigatorio e nao-vazio. Isso torna a identidade de aplicacao um dado
confiavel para access log/auditoria, nao uma inferencia posterior.
"""
from dataclasses import dataclass

from server.errors import NotFoundError


@dataclass(frozen=True)
class _AssociacaoDominio:
    router: object
    app_name: str


def _validar_app_name(app_name):
    if not app_name or not isinstance(app_name, str):
        raise ValueError("app_name e obrigatorio e nao pode ser vazio")


class HostRouter:
    def __init__(self):
        self._associacoes = {}
        self._padrao = None

    def registrar_dominio(self, dominio, router, app_name):
        _validar_app_name(app_name)
        self._associacoes[dominio] = _AssociacaoDominio(router=router, app_name=app_name)

    def definir_padrao(self, router, app_name):
        _validar_app_name(app_name)
        self._padrao = _AssociacaoDominio(router=router, app_name=app_name)

    def remover_dominio(self, dominio):
        self._associacoes.pop(dominio, None)

    def _resolver_associacao(self, host_header):
        if not host_header:
            if self._padrao:
                return self._padrao
            raise NotFoundError("no Host header and no default router configured")

        dominio = host_header.split(":")[0].strip().lower()

        if dominio in self._associacoes:
            return self._associacoes[dominio]

        if self._padrao:
            return self._padrao

        raise NotFoundError(f"no application registered for host {dominio!r}")

    def resolver_router(self, host_header):
        return self._resolver_associacao(host_header).router

    def resolver_app_name(self, host_header):
        return self._resolver_associacao(host_header).app_name
