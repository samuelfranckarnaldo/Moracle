"""
Rotacao de log gerenciada pelo Moracle - fecha o arquivo atual, gera
custodia sobre ele (evidencia congelada de verdade, nao em escrita
ativa), e prepara um novo arquivo vazio no lugar.
"""
import os
import shutil
from datetime import datetime, timezone

from core.custody import coletar_evidencia


def rotacionar(caminho_log, diretorio_arquivo=None):
    if not os.path.exists(caminho_log):
        raise FileNotFoundError(f"Log nao encontrado: {caminho_log}")

    if diretorio_arquivo is None:
        diretorio_arquivo = os.path.join(os.path.dirname(os.path.abspath(caminho_log)), "arquivados")
    os.makedirs(diretorio_arquivo, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    nome_base = os.path.basename(caminho_log)
    caminho_arquivado = os.path.join(diretorio_arquivo, f"{nome_base}.{timestamp}")

    shutil.move(caminho_log, caminho_arquivado)
    open(caminho_log, "a").close()  # recria vazio para a aplicacao continuar escrevendo

    registro = coletar_evidencia(caminho_arquivado, coletor="moracle-rotation",
                                  motivo="rotacao automatica de log")

    return {"arquivo_arquivado": caminho_arquivado, "hash": registro.hash_sha256,
            "novo_log_vazio": caminho_log}
