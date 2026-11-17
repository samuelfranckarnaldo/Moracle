"""
tests/test_identity.py

Cobre os invariantes do Passo 1 (core/identity.py):
    - Contrato de permissões (rejeição de permissões desconhecidas).
    - server.admin como propriedade explícita (is_wildcard), sem
      curto-circuito de autorização embutido aqui.
    - scoped_app_names == [] significa "todas as aplicações".
    - Nenhum segredo em texto plano é persistido.
    - Hash SHA-256 correto e determinístico.
    - Persistência atômica (round-trip).
    - Migração idempotente da chave legada.
"""

import json
from pathlib import Path

import pytest

from core.identity import (
    ServiceRole,
    ApiKey,
    KeyStore,
    RoleStore,
    UnknownPermissionError,
    DuplicateApiKeyError,
    IdentityError,
    SERVER_ADMIN_PERMISSION,
    generate_token,
    hash_token,
    create_api_key,
    migrate_legacy_admin_key,
)


# ---------------------------------------------------------------------------
# ServiceRole
# ---------------------------------------------------------------------------

def test_service_role_rejects_unknown_permission():
    with pytest.raises(UnknownPermissionError):
        ServiceRole(name="quebrado", permissions=frozenset({"app.voar"}))


def test_service_role_accepts_known_permissions():
    role = ServiceRole(
        name="deploy",
        permissions=frozenset({"app.deploy", "app.read"}),
    )
    assert role.permissions == {"app.deploy", "app.read"}


def test_service_role_is_wildcard_true_with_server_admin():
    role = ServiceRole(name="admin", permissions=frozenset({SERVER_ADMIN_PERMISSION}))
    assert role.is_wildcard is True


def test_service_role_is_wildcard_false_without_server_admin():
    role = ServiceRole(name="deploy", permissions=frozenset({"app.deploy"}))
    assert role.is_wildcard is False


def test_service_role_roundtrip_dict():
    role = ServiceRole(
        name="deploy",
        permissions=frozenset({"app.deploy", "app.read"}),
        description="CI/CD",
    )
    restored = ServiceRole.from_dict(role.to_dict())
    assert restored == role


# ---------------------------------------------------------------------------
# ApiKey
# ---------------------------------------------------------------------------

def test_api_key_empty_scope_means_all_apps():
    key = ApiKey(
        id="k1", key_hash="x", name="admin key", role_name="admin",
        created_at="now", scoped_app_names=[],
    )
    assert key.is_globally_scoped is True


def test_api_key_nonempty_scope_is_not_global():
    key = ApiKey(
        id="k1", key_hash="x", name="ci key", role_name="deploy",
        created_at="now", scoped_app_names=["app-a"],
    )
    assert key.is_globally_scoped is False


# ---------------------------------------------------------------------------
# Token generation / hashing
# ---------------------------------------------------------------------------

def test_generate_token_is_unique_and_prefixed():
    t1 = generate_token()
    t2 = generate_token()
    assert t1 != t2
    assert t1.startswith("mk_")
    assert t2.startswith("mk_")


def test_hash_token_is_deterministic_sha256():
    token = "mk_exemplo"
    import hashlib
    expected = hashlib.sha256(token.encode("utf-8")).hexdigest()
    assert hash_token(token) == expected
    assert hash_token(token) == hash_token(token)


def test_hash_token_differs_for_different_tokens():
    assert hash_token("mk_a") != hash_token("mk_b")


# ---------------------------------------------------------------------------
# KeyStore / RoleStore — persistência atômica
# ---------------------------------------------------------------------------

def test_keystore_roundtrip(tmp_path: Path):
    store = KeyStore(tmp_path)
    key, raw_token = create_api_key(store, name="teste", role_name="admin")

    reloaded = KeyStore(tmp_path)
    fetched = reloaded.get(key.id)
    assert fetched is not None
    assert fetched.key_hash == key.key_hash
    assert fetched.key_hash == hash_token(raw_token)


def test_keystore_never_persists_plaintext_token(tmp_path: Path):
    store = KeyStore(tmp_path)
    _, raw_token = create_api_key(store, name="teste", role_name="admin")

    raw_file_content = (tmp_path / "keys.json").read_text(encoding="utf-8")
    assert raw_token not in raw_file_content


def test_keystore_add_duplicate_id_raises(tmp_path: Path):
    store = KeyStore(tmp_path)
    key = ApiKey(id="dup", key_hash="h", name="a", role_name="admin", created_at="now")
    store.add(key)
    with pytest.raises(DuplicateApiKeyError):
        store.add(key)


def test_keystore_revoke_preserves_record(tmp_path: Path):
    store = KeyStore(tmp_path)
    key = ApiKey(id="k1", key_hash="h", name="a", role_name="admin", created_at="now")
    store.add(key)
    store.revoke("k1")

    fetched = store.get("k1")
    assert fetched is not None          # não foi apagada
    assert fetched.revoked is True      # apenas marcada


def test_keystore_revoke_missing_key_raises(tmp_path: Path):
    store = KeyStore(tmp_path)
    with pytest.raises(IdentityError):
        store.revoke("nao-existe")


def test_rolestore_ensure_admin_role_is_idempotent(tmp_path: Path):
    store = RoleStore(tmp_path)
    role1 = store.ensure_admin_role_exists()
    role2 = store.ensure_admin_role_exists()
    assert role1 == role2
    assert len(store.load_all()) == 1


def test_rolestore_ensure_admin_role_does_not_overwrite_custom(tmp_path: Path):
    store = RoleStore(tmp_path)
    custom = ServiceRole(
        name="admin",
        permissions=frozenset({SERVER_ADMIN_PERMISSION}),
        description="customizado",
    )
    store.upsert(custom)
    result = store.ensure_admin_role_exists()
    assert result.description == "customizado"


# ---------------------------------------------------------------------------
# Migração da chave legada
# ---------------------------------------------------------------------------

def test_migrate_legacy_admin_key_creates_admin_key(tmp_path: Path):
    (tmp_path / "api_key.txt").write_text("token-legado-secreto\n", encoding="utf-8")

    migrated = migrate_legacy_admin_key(tmp_path)

    assert migrated is not None
    assert migrated.role_name == "admin"
    assert migrated.revoked is False
    assert migrated.scoped_app_names == []
    assert migrated.key_hash == hash_token("token-legado-secreto")


def test_migrate_legacy_admin_key_creates_admin_role(tmp_path: Path):
    (tmp_path / "api_key.txt").write_text("token-legado\n", encoding="utf-8")
    migrate_legacy_admin_key(tmp_path)

    role_store = RoleStore(tmp_path)
    admin_role = role_store.get("admin")
    assert admin_role is not None
    assert admin_role.is_wildcard is True


def test_migrate_legacy_admin_key_is_idempotent(tmp_path: Path):
    (tmp_path / "api_key.txt").write_text("token-legado\n", encoding="utf-8")

    first = migrate_legacy_admin_key(tmp_path)
    second = migrate_legacy_admin_key(tmp_path)

    assert first is not None
    assert second is None  # segunda chamada não cria nada

    store = KeyStore(tmp_path)
    all_keys = store.load_all()
    admin_keys = [k for k in all_keys.values() if k.role_name == "admin"]
    assert len(admin_keys) == 1  # nunca duas chaves admin


def test_migrate_legacy_admin_key_survives_restart_simulation(tmp_path: Path):
    """Simula reiniciar o Moracle: nova instância de KeyStore/RoleStore,
    mesmo diretório de estado."""
    (tmp_path / "api_key.txt").write_text("token-legado\n", encoding="utf-8")

    migrate_legacy_admin_key(tmp_path, KeyStore(tmp_path), RoleStore(tmp_path))
    # "reinício": instâncias novas, mesmo tmp_path
    migrate_legacy_admin_key(tmp_path, KeyStore(tmp_path), RoleStore(tmp_path))

    store = KeyStore(tmp_path)
    admin_keys = [k for k in store.load_all().values() if k.role_name == "admin"]
    assert len(admin_keys) == 1


def test_migrate_legacy_admin_key_no_file_returns_none(tmp_path: Path):
    result = migrate_legacy_admin_key(tmp_path)
    assert result is None
    assert (tmp_path / "keys.json").exists() is False


def test_migrate_legacy_admin_key_does_not_persist_plaintext(tmp_path: Path):
    (tmp_path / "api_key.txt").write_text("segredo-super-secreto\n", encoding="utf-8")
    migrate_legacy_admin_key(tmp_path)

    keys_json = (tmp_path / "keys.json").read_text(encoding="utf-8")
    assert "segredo-super-secreto" not in keys_json


def test_migrate_legacy_admin_key_does_not_delete_legacy_file(tmp_path: Path):
    legacy = tmp_path / "api_key.txt"
    legacy.write_text("token-legado\n", encoding="utf-8")
    migrate_legacy_admin_key(tmp_path)
    assert legacy.exists()  # decisão de remover fica com o usuário
