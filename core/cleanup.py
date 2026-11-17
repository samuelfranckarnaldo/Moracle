"""
Rotação de arquivos em saida/ — remove relatórios e dados mais antigos
que um limite configurável, evitando crescimento indefinido.
"""
import os
import time

from core import config


def limpar_saida(dias_retencao=30, simular=False):
    cfg = config.carregar()
    base = os.path.join(config.RAIZ_PROJETO, cfg["diretorio_saida"])
    if not os.path.isdir(base):
        return {"removidos": [], "total_liberado_bytes": 0}

    limite_segundos = dias_retencao * 86400
    agora = time.time()
    removidos = []
    total_bytes = 0

    for raiz, _, arquivos in os.walk(base):
        for nome in arquivos:
            caminho = os.path.join(raiz, nome)
            idade = agora - os.path.getmtime(caminho)
            if idade > limite_segundos:
                tamanho = os.path.getsize(caminho)
                if not simular:
                    os.remove(caminho)
                removidos.append(caminho)
                total_bytes += tamanho

    return {"removidos": removidos, "total_liberado_bytes": total_bytes}
