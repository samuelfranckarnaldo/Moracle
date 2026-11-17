"""
tests/test_auth.py

Cobre os invariantes obrigatórios do Passo 2 (core/auth.py):
    - token correto       -> ApiKey
    - token incorreto      -> None
    - token revogado       -> None
    - token expirado       -> None
    - token válido         -> last_used_at atualizado
    - nenhuma verificação de permissão/escopo é feita aqui (fora de escopo)
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from core.identity import KeyStore, create_api_key
from core.auth import autenticar


def test_autenticar_token_correto_retorna_api_key(tmp_path: Path):
    store = KeyStore(tmp_path)
    key, raw_token = create_api_key(store, name="teste", role_name="admin")

    resultado = autenticar(raw_token, store)

    assert resultado is not None
    assert resultado.id == key.id


def test_autenticar_token_incorreto_retorna_none(tmp_path: Path):
    store = KeyStore(tmp_path)
    create_api_key(store, name="teste", role_name="admin")

    resultado = autenticar("mk_token-totalmente-errado", store)

    assert resultado is None


def test_autenticar_token_vazio_retorna_none(tmp_path: Path):
    store = KeyStore(tmp_path)
    assert autenticar("", store) is None
    assert autenticar(None, store) is None


def test_autenticar_chave_revogada_retorna_none(tmp_path: Path):
    store = KeyStore(tmp_path)
    key, raw_token = create_api_key(store, name="teste", role_name="admin")
    store.revoke(key.id)

    resultado = autenticar(raw_token, store)

    assert resultado is None


def test_autenticar_chave_expirada_retorna_none(tmp_path: Path):
    store = KeyStore(tmp_path)
    passado = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    key, raw_token = create_api_key(
        store, name="teste", role_name="admin", expires_at=passado
    )

    resultado = autenticar(raw_token, store)

    assert resultado is None


def test_autenticar_chave_com_expiracao_futura_autentica(tmp_path: Path):
    store = KeyStore(tmp_path)
    futuro = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    key, raw_token = create_api_key(
        store, name="teste", role_name="admin", expires_at=futuro
    )

    resultado = autenticar(raw_token, store)

    assert resultado is not None
    assert resultado.id == key.id


def test_autenticar_sem_expires_at_nunca_expira(tmp_path: Path):
    store = KeyStore(tmp_path)
    key, raw_token = create_api_key(
        store, name="teste", role_name="admin", expires_at=None
    )

    resultado = autenticar(raw_token, store)

    assert resultado is not None


def test_autenticar_expires_at_malformado_falha_fechado(tmp_path: Path):
    store = KeyStore(tmp_path)
    key, raw_token = create_api_key(
        store, name="teste", role_name="admin", expires_at="nao-e-uma-data"
    )

    resultado = autenticar(raw_token, store)

    assert resultado is None


def test_autenticar_atualiza_last_used_at(tmp_path: Path):
    store = KeyStore(tmp_path)
    key, raw_token = create_api_key(store, name="teste", role_name="admin")
    assert store.get(key.id).last_used_at is None

    resultado = autenticar(raw_token, store)

    assert resultado.last_used_at is not None
    # E o valor persistido bate com o retornado (sem divergência).
    assert store.get(key.id).last_used_at == resultado.last_used_at


def test_autenticar_nao_revela_diferenca_entre_nao_encontrada_e_revogada(tmp_path: Path):
    """Ambas as falhas devem produzir exatamente o mesmo tipo de retorno
    (None), sem nenhum sinal adicional que distinga os casos."""
    store = KeyStore(tmp_path)
    key, raw_token = create_api_key(store, name="teste", role_name="admin")
    store.revoke(key.id)

    resultado_revogada = autenticar(raw_token, store)
    resultado_inexistente = autenticar("mk_nao-existe-nunca-existiu", store)

    assert resultado_revogada is None
    assert resultado_inexistente is None
    assert type(resultado_revogada) == type(resultado_inexistente)


def test_autenticar_nao_verifica_permissoes_ou_escopo(tmp_path: Path):
    """Confirma que autenticar() é agnóstico a permissions/scoped_app_names
    — uma chave sem NENHUMA permissão e escopo restrito ainda autentica
    normalmente, pois autorização é responsabilidade de outra camada."""
    store = KeyStore(tmp_path)
    key, raw_token = create_api_key(
        store,
        name="chave-limitada",
        role_name="algum-role-sem-permissoes",
        scoped_app_names=["app-a"],
    )

    resultado = autenticar(raw_token, store)

    assert resultado is not None
    assert resultado.id == key.id
