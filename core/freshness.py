"""
Deteta se um arquivo ainda esta sendo escrito ativamente - evidencia
'em movimento' nao deveria virar custodia sem aviso, porque o hash
capturado agora ja nao representa o estado final do arquivo.
"""
import os
import time


def esta_em_escrita_ativa(caminho, janela_segundos=5):
    if not os.path.exists(caminho):
        return False
    mtime_inicial = os.path.getmtime(caminho)
    idade_desde_ultima_escrita = time.time() - mtime_inicial
    if idade_desde_ultima_escrita < janela_segundos:
        return True
    return False
