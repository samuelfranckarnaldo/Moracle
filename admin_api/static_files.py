"""
Serve arquivos estaticos do Console a partir de um diretorio fixo -
protegido contra path traversal (normaliza o path resolvido e
confirma que continua dentro do diretorio raiz antes de servir).
Nao e' um static file server completo (sem ETag/Range/cache) - o
suficiente para servir HTML/JS/CSS de uma pagina local.
"""
import os
import mimetypes

from server.response import Response

MIME_PADRAO = "application/octet-stream"


def criar_handler_estatico(diretorio_raiz, arquivo_index="index.html", spa_fallback=False):
    """
    spa_fallback (opt-in, default False -- comportamento anterior
    preservado para todo consumidor existente): quando um subpath nao
    corresponde a um arquivo real E nao possui extensao, serve
    arquivo_index em vez de 404. Permite URLs de roteamento
    client-side (history.pushState) como /console/apps/app-a
    funcionarem tanto na navegacao via JS quanto em reload direto do
    navegador.

    Um subpath COM extensao que nao existe (ex.: nao-existe.js)
    continua retornando 404 normalmente, mesmo com spa_fallback=True
    -- o fallback nunca mascara um asset estatico realmente ausente,
    so rotas de aplicacao sem arquivo fisico correspondente.
    """
    diretorio_raiz = os.path.abspath(diretorio_raiz)

    def handler(request, context):
        subpath = context.route_params.get("path", "") or arquivo_index
        candidato = os.path.abspath(os.path.join(diretorio_raiz, subpath))

        if not (candidato == diretorio_raiz or candidato.startswith(diretorio_raiz + os.sep)):
            return Response.text("Forbidden", status=403)

        if not os.path.isfile(candidato):
            sem_extensao = os.path.splitext(subpath)[1] == ""
            if spa_fallback and sem_extensao:
                candidato = os.path.join(diretorio_raiz, arquivo_index)
                if not os.path.isfile(candidato):
                    return Response.text("Not Found", status=404)
            else:
                return Response.text("Not Found", status=404)

        tipo_mime, _ = mimetypes.guess_type(candidato)
        with open(candidato, "rb") as f:
            corpo = f.read()

        return Response(status=200, headers={"Content-Type": tipo_mime or MIME_PADRAO}, body=corpo)

    return handler
