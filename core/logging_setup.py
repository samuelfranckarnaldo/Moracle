"""
Configura tres destinos de log completamente separados, conforme a
arquitetura definiu: access logging (HTTP), application logging
(comportamento do Moracle), e security audit (ja existente via
core/audit.py e defense.registrar_alerta). Nao misturar os tres num
unico arquivo.
"""
import logging
import os

from core import config

LOG_DIR = os.path.join(config.RAIZ_PROJETO, ".state", "logs")

_configurado = False


def resetar_para_teste():
    """Usado apenas em testes - forca reconfiguracao completa do
    logging, incluindo recriar handlers de arquivo. Sem isso, chamar
    configurar_logging() de novo apos apagar LOG_DIR nao recria nada,
    porque o singleton ja se considera configurado."""
    global _configurado
    _configurado = False
    for nome_logger in ("moracle.access", "moracle.application"):
        logger = logging.getLogger(nome_logger)
        for handler in list(logger.handlers):
            logger.removeHandler(handler)
            handler.close()


def configurar_logging():
    global _configurado
    if _configurado:
        return
    os.makedirs(LOG_DIR, exist_ok=True)

    _configurar_logger_arquivo("moracle.access", os.path.join(LOG_DIR, "access.log"))
    _configurar_logger_arquivo("moracle.application", os.path.join(LOG_DIR, "application.log"))

    _configurado = True


def _configurar_logger_arquivo(nome_logger, caminho_arquivo):
    logger = logging.getLogger(nome_logger)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    if logger.handlers:
        return

    handler = logging.FileHandler(caminho_arquivo)
    handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
    logger.addHandler(handler)


def application_logger():
    configurar_logging()
    return logging.getLogger("moracle.application")
