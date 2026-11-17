"""
Whitelist de rotas/padroes conhecidos como legitimos - evita gastar
analise de payload em ativos estaticos e endpoints obvios de saude.
"""
import re
import os
import json

from core import config

WHITELIST_PATH = os.path.join(config.RAIZ_PROJETO, "whitelist.json")

PADRAO = [
    r"\.(js|css|png|jpg|jpeg|svg|woff2?|ico|webp|map)(\?.*)?$",
    r"^/api/health$",
    r"^/favicon\.ico$",
]


def carregar():
    if not os.path.exists(WHITELIST_PATH):
        with open(WHITELIST_PATH, "w") as f:
            json.dump({"padroes": PADRAO}, f, indent=2)
        return list(PADRAO)
    with open(WHITELIST_PATH) as f:
        dados = json.load(f)
    return dados.get("padroes", PADRAO)


_compilados = None


def esta_na_whitelist(linha):
    global _compilados
    if _compilados is None:
        _compilados = [re.compile(p, re.I) for p in carregar()]
    return any(p.search(linha) for p in _compilados)
