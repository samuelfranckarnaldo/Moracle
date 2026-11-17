"""
Confirma que ServerConfig invalido falha CEDO, com mensagem clara,
antes de qualquer bind de socket - nao gera erro obscuro depois.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from server.server import Server, ServerConfig
from server.router import Router
from server.limits import Limits
from server.errors import ConfigurationError
from server.lifecycle import ServerState


def test_valid_config_passes():
    config = ServerConfig(host="127.0.0.1", port=7000, max_workers=10, backlog=128)
    erros = config.validate()
    assert erros == []


def test_invalid_port_rejected():
    config = ServerConfig(port=99999)
    erros = config.validate()
    assert any("port" in e for e in erros)


def test_invalid_port_zero_rejected():
    config = ServerConfig(port=0)
    erros = config.validate()
    assert any("port" in e for e in erros)


def test_empty_host_rejected():
    config = ServerConfig(host="")
    erros = config.validate()
    assert any("host" in e for e in erros)


def test_zero_max_workers_rejected():
    config = ServerConfig(max_workers=0)
    erros = config.validate()
    assert any("max_workers" in e for e in erros)


def test_negative_backlog_rejected():
    config = ServerConfig(backlog=-1)
    erros = config.validate()
    assert any("backlog" in e for e in erros)


def test_negative_drain_timeout_rejected():
    config = ServerConfig(drain_timeout=-5)
    erros = config.validate()
    assert any("drain_timeout" in e for e in erros)


def test_keep_alive_true_rejected_as_unsupported():
    config = ServerConfig(keep_alive=True)
    erros = config.validate()
    assert any("keep_alive" in e for e in erros)


def test_invalid_limits_body_size_rejected():
    config = ServerConfig(limits=Limits(max_body_size=0))
    erros = config.validate()
    assert any("max_body_size" in e for e in erros)


def test_invalid_limits_timeout_rejected():
    config = ServerConfig(limits=Limits(read_timeout=-1))
    erros = config.validate()
    assert any("read_timeout" in e for e in erros)


def test_invalid_tls_context_type_rejected():
    config = ServerConfig(tls_context="nao e um SSLContext")
    erros = config.validate()
    assert any("tls_context" in e for e in erros)


def test_server_start_raises_configuration_error_before_bind():
    router = Router()
    config = ServerConfig(port=-1)

    with pytest.raises(ConfigurationError) as exc:
        Server(config, router)

    assert "port" in str(exc.value)


def test_server_start_multiple_errors_all_reported():
    router = Router()
    config = ServerConfig(port=-1, max_workers=0, backlog=-5)

    with pytest.raises(ConfigurationError) as exc:
        Server(config, router)

    mensagem = str(exc.value)
    assert "port" in mensagem
    assert "max_workers" in mensagem
    assert "backlog" in mensagem
