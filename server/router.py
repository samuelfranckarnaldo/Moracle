"""
Resolve (method, path) -> handler. Nao conhece a aplicacao Moracle.
"""
import re


def _compilar(padrao_path):
    partes = []
    for segmento in padrao_path.strip("/").split("/"):
        if segmento.startswith("{") and segmento.endswith("}"):
            nome = segmento[1:-1]
            partes.append(f"(?P<{nome}>[^/]+)")
        else:
            partes.append(re.escape(segmento))
    corpo = "/".join(partes)
    return re.compile(f"^/{corpo}$" if corpo else "^/$")


class Router:
    def __init__(self):
        self._rotas = []

    def add_route(self, method, path_pattern, handler):
        regex = _compilar(path_pattern)
        self._rotas.append((method.upper(), regex, handler))

    def match(self, method, path):
        from server.errors import NotFoundError, MethodNotAllowedError

        path_bateu = False
        metodos_permitidos = set()
        for rota_method, regex, handler in self._rotas:
            mo = regex.match(path)
            if mo:
                path_bateu = True
                metodos_permitidos.add(rota_method)
                if rota_method == method.upper():
                    return handler, mo.groupdict()
                if method.upper() == "HEAD" and rota_method == "GET":
                    return handler, mo.groupdict()

        if not path_bateu:
            raise NotFoundError(path)
        raise MethodNotAllowedError(path, metodos_permitidos)

    def allowed_methods(self, path):
        metodos = set()
        for rota_method, regex, _ in self._rotas:
            if regex.match(path):
                metodos.add(rota_method)
        if "GET" in metodos:
            metodos.add("HEAD")
        metodos.add("OPTIONS")
        return metodos
