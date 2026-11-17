"""
Testes de AccessLogRecord e JsonlSink - cobre serializacao JSON Lines
e garante que o sink de texto existente nao regride (usado pelo
Kontaki Console via morgan, nao pode mudar de comportamento).
"""
import json
import logging
import os
import sys
import tempfile
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from server.access_log import AccessLogRecord, AccessLogger, JsonlSink


def _record(**overrides):
    base = dict(
        request_id="req-1",
        timestamp="2026-09-09T12:00:00Z",
        remote_address="10.0.0.1",
        method="GET",
        path="/api/health",
        protocol_version="HTTP/1.1",
        status=200,
        bytes_sent=128,
        latency_ms=12.5,
        app_name="minha-app",
    )
    base.update(overrides)
    return AccessLogRecord(**base)


@pytest.fixture
def arquivo_temp():
    fd, caminho = tempfile.mkstemp(suffix=".jsonl")
    os.close(fd)
    os.remove(caminho)  # JsonlSink cria o arquivo ao escrever a 1a linha
    yield caminho
    if os.path.exists(caminho):
        os.remove(caminho)


def test_jsonl_sink_grava_uma_linha_por_registro(arquivo_temp):
    sink = JsonlSink(arquivo_temp)
    sink(_record())
    sink(_record(request_id="req-2"))

    with open(arquivo_temp, "r", encoding="utf-8") as f:
        linhas = f.readlines()
    assert len(linhas) == 2
    assert json.loads(linhas[0])["request_id"] == "req-1"


def test_jsonl_sink_serializa_todos_os_campos(arquivo_temp):
    JsonlSink(arquivo_temp)(_record())
    with open(arquivo_temp, "r", encoding="utf-8") as f:
        dados = json.loads(f.readline())

    esperados = {"request_id", "timestamp", "remote_address", "method", "path",
                 "protocol_version", "status", "bytes_sent", "latency_ms", "app_name"}
    assert set(dados.keys()) == esperados


def test_access_logger_sem_jsonl_sink_nao_cria_arquivo(arquivo_temp):
    """Regressao: AccessLogger() sem jsonl_sink continua so-texto, como antes."""
    chamadas = []
    logger = AccessLogger(sink=chamadas.append)
    logger.log(_record())

    assert len(chamadas) == 1
    assert not os.path.exists(arquivo_temp)


def test_access_logger_com_jsonl_sink_grava_nos_dois(arquivo_temp):
    chamadas_texto = []
    logger = AccessLogger(sink=chamadas_texto.append, jsonl_sink=JsonlSink(arquivo_temp))
    logger.log(_record())

    assert len(chamadas_texto) == 1
    with open(arquivo_temp, "r", encoding="utf-8") as f:
        assert len(f.readlines()) == 1


def test_sink_padrao_texto_continua_identico(caplog):
    """Regressao: formato humano-legivel inalterado sem jsonl_sink."""
    logger = AccessLogger()
    with caplog.at_level(logging.INFO, logger="moracle.access"):
        logger.log(_record())
    assert "GET" in caplog.text
    assert "/api/health" in caplog.text
