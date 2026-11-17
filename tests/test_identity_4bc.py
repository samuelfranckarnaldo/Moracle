"""
tests/test_identity_4bc.py

Cobre as operacoes novas do Passo 4B-C (core/identity.py):
    - KeyStore.add(): unicidade de name (alem de id, ja coberta em
      test_identity.py)
    - RoleStore.add(): criacao sem sobrescrita (distinto de upsert())
    - KeyStore.revoke_safely(): protecao de ultima credencial
      server.admin valida, idempotencia, chave nao-admin, role
      inexistente (fail-closed), expiracao
    - is_expired(): regra publica reutilizavel (ja teve seu
      comportamento coberto indiretamente via test_auth.py, mas aqui
      testamos a funcao em si, nao mais via _is_expired privada)
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from core.identity import (
    ApiKey,
    ServiceRole,
    KeyStore,
    RoleStore,
    SERVER_ADMIN_PERMISSION,
    DuplicateApiKeyNameError,
    DuplicateRoleNameError,
    LastAdminKeyError,
    IdentityError,
    is_expired,
    create_api_key,
)


# ---------------------------------------------------------------------------
# is_expired() — regra publica e reutilizavel
# ---------------------------------------------------------------------------

def test_is_expired_sem_expires_at_nunca_expira():
    key = ApiKey(id="k", key_hash="h", name="n", role_name="r", created_at="now", expires_at=None)
    assert is_expired(key) is False


def test_is_expired_no_passado_e_verdadeiro():
    passado = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    key = ApiKey(id="k", key_hash="h", name="n", role_name="r", created_at="now", expires_at=passado)
    assert is_expired(key) is True


def test_is_expired_no_futuro_e_falso():
    futuro = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    key = ApiKey(id="k", key_hash="h", name="n", role_name="r", created_at="now", expires_at=futuro)
    assert is_expired(key) is False


def test_is_expired_malformado_falha_fechado():
    key = ApiKey(id="k", key_hash="h", name="n", role_name="r", created_at="now", expires_at="nao-e-data")
    assert is_expired(key) is True


# ---------------------------------------------------------------------------
# KeyStore.add() — unicidade de name
# ---------------------------------------------------------------------------

def test_keystore_add_name_duplicado_rejeita(tmp_path: Path):
    store = KeyStore(tmp_path)
    k1 = ApiKey(id="id-1", key_hash="h1", name="mesmo-nome", role_name="admin", created_at="now")
    k2 = ApiKey(id="id-2", key_hash="h2", name="mesmo-nome", role_name="admin", created_at="now")

    store.add(k1)
    with pytest.raises(DuplicateApiKeyNameError):
        store.add(k2)

    # garante que k2 nao foi persistida parcialmente
    assert store.get("id-2") is None


def test_keystore_add_name_case_sensitive(tmp_path: Path):
    """'deploy-prod' e 'Deploy-Prod' sao nomes DIFERENTES — sem
    normalizacao implicita, conforme decisao do 4B-B."""
    store = KeyStore(tmp_path)
    k1 = ApiKey(id="id-1", key_hash="h1", name="deploy-prod", role_name="admin", created_at="now")
    k2 = ApiKey(id="id-2", key_hash="h2", name="Deploy-Prod", role_name="admin", created_at="now")

    store.add(k1)
    store.add(k2)  # nao deve levantar

    assert store.get("id-1") is not None
    assert store.get("id-2") is not None


def test_keystore_add_id_e_name_diferentes_convivem(tmp_path: Path):
    store = KeyStore(tmp_path)
    k1 = ApiKey(id="id-1", key_hash="h1", name="nome-a", role_name="admin", created_at="now")
    k2 = ApiKey(id="id-2", key_hash="h2", name="nome-b", role_name="admin", created_at="now")

    store.add(k1)
    store.add(k2)  # nao deve levantar

    assert len(store.load_all()) == 2


# ---------------------------------------------------------------------------
# RoleStore.add() — criacao sem sobrescrita
# ---------------------------------------------------------------------------

def test_rolestore_add_cria_role_nova(tmp_path: Path):
    store = RoleStore(tmp_path)
    role = ServiceRole(name="deploy", permissions=frozenset({"app.deploy"}))

    store.add(role)

    fetched = store.get("deploy")
    assert fetched is not None
    assert fetched.permissions == {"app.deploy"}


def test_rolestore_add_nome_duplicado_rejeita_sem_sobrescrever(tmp_path: Path):
    store = RoleStore(tmp_path)
    original = ServiceRole(name="deploy", permissions=frozenset({"app.deploy"}), description="original")
    store.add(original)

    tentativa = ServiceRole(name="deploy", permissions=frozenset({SERVER_ADMIN_PERMISSION}), description="maliciosa")
    with pytest.raises(DuplicateRoleNameError):
        store.add(tentativa)

    # a role original NAO foi sobrescrita — prova central contra
    # escalada de privilegio via recriacao de role existente
    fetched = store.get("deploy")
    assert fetched.description == "original"
    assert fetched.permissions == {"app.deploy"}


def test_rolestore_add_distinto_de_upsert(tmp_path: Path):
    """upsert() continua sobrescrevendo (comportamento preservado por
    compatibilidade); add() nunca sobrescreve. Os dois metodos tem
    semantica DIFERENTE e devem continuar assim."""
    store = RoleStore(tmp_path)
    original = ServiceRole(name="deploy", permissions=frozenset({"app.deploy"}))
    store.add(original)

    # upsert() ainda sobrescreve livremente — nao e o metodo usado
    # pelo endpoint novo, mas seu comportamento antigo nao muda
    substituta = ServiceRole(name="deploy", permissions=frozenset({"app.read"}))
    store.upsert(substituta)
    assert store.get("deploy").permissions == {"app.read"}


# ---------------------------------------------------------------------------
# KeyStore.revoke_safely() — protecao de ultima admin valida
# ---------------------------------------------------------------------------

def _preparar_admin_role(role_store: RoleStore) -> None:
    role_store.add(ServiceRole(name="admin", permissions=frozenset({SERVER_ADMIN_PERMISSION})))


def _preparar_deploy_role(role_store: RoleStore) -> None:
    role_store.add(ServiceRole(name="deploy", permissions=frozenset({"app.deploy"})))


def test_revoke_safely_chave_nao_admin_revoga_livremente(tmp_path: Path):
    key_store = KeyStore(tmp_path)
    role_store = RoleStore(tmp_path)
    _preparar_admin_role(role_store)
    _preparar_deploy_role(role_store)

    admin_key = ApiKey(id="admin-1", key_hash="h", name="admin-key", role_name="admin", created_at="now")
    deploy_key = ApiKey(id="deploy-1", key_hash="h2", name="deploy-key", role_name="deploy", created_at="now")
    key_store.add(admin_key)
    key_store.add(deploy_key)

    key_store.revoke_safely("deploy-1", role_store)

    assert key_store.get("deploy-1").revoked is True
    assert key_store.get("admin-1").revoked is False


def test_revoke_safely_admin_com_outra_admin_disponivel_revoga(tmp_path: Path):
    key_store = KeyStore(tmp_path)
    role_store = RoleStore(tmp_path)
    _preparar_admin_role(role_store)

    admin_a = ApiKey(id="admin-a", key_hash="ha", name="admin-a", role_name="admin", created_at="now")
    admin_b = ApiKey(id="admin-b", key_hash="hb", name="admin-b", role_name="admin", created_at="now")
    key_store.add(admin_a)
    key_store.add(admin_b)

    key_store.revoke_safely("admin-b", role_store)

    assert key_store.get("admin-b").revoked is True
    assert key_store.get("admin-a").revoked is False


def test_revoke_safely_ultima_admin_rejeitada(tmp_path: Path):
    key_store = KeyStore(tmp_path)
    role_store = RoleStore(tmp_path)
    _preparar_admin_role(role_store)

    unica_admin = ApiKey(id="admin-1", key_hash="h", name="unica-admin", role_name="admin", created_at="now")
    key_store.add(unica_admin)

    with pytest.raises(LastAdminKeyError):
        key_store.revoke_safely("admin-1", role_store)

    # nao foi revogada
    assert key_store.get("admin-1").revoked is False


def test_revoke_safely_admin_expirada_nao_conta_como_admin_restante(tmp_path: Path):
    """Chave admin-B expirada NAO impede a rejeicao ao revogar
    admin-A — uma credencial que nao pode mais autenticar nao e
    'admin restante' valida."""
    key_store = KeyStore(tmp_path)
    role_store = RoleStore(tmp_path)
    _preparar_admin_role(role_store)

    passado = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    admin_a = ApiKey(id="admin-a", key_hash="ha", name="admin-a", role_name="admin", created_at="now")
    admin_b_expirada = ApiKey(
        id="admin-b", key_hash="hb", name="admin-b-expirada", role_name="admin",
        created_at="now", expires_at=passado,
    )
    key_store.add(admin_a)
    key_store.add(admin_b_expirada)

    with pytest.raises(LastAdminKeyError):
        key_store.revoke_safely("admin-a", role_store)

    assert key_store.get("admin-a").revoked is False


def test_revoke_safely_admin_ja_revogada_nao_conta_como_admin_restante(tmp_path: Path):
    key_store = KeyStore(tmp_path)
    role_store = RoleStore(tmp_path)
    _preparar_admin_role(role_store)

    admin_a = ApiKey(id="admin-a", key_hash="ha", name="admin-a", role_name="admin", created_at="now")
    admin_b = ApiKey(id="admin-b", key_hash="hb", name="admin-b", role_name="admin", created_at="now")
    key_store.add(admin_a)
    key_store.add(admin_b)

    key_store.revoke_safely("admin-b", role_store)  # revoga B primeiro
    assert key_store.get("admin-b").revoked is True

    with pytest.raises(LastAdminKeyError):
        key_store.revoke_safely("admin-a", role_store)  # agora A e a ultima


def test_revoke_safely_e_idempotente(tmp_path: Path):
    key_store = KeyStore(tmp_path)
    role_store = RoleStore(tmp_path)
    _preparar_admin_role(role_store)

    admin_a = ApiKey(id="admin-a", key_hash="ha", name="admin-a", role_name="admin", created_at="now")
    admin_b = ApiKey(id="admin-b", key_hash="hb", name="admin-b", role_name="admin", created_at="now")
    key_store.add(admin_a)
    key_store.add(admin_b)

    key_store.revoke_safely("admin-b", role_store)
    assert key_store.get("admin-b").revoked is True

    # segunda chamada: idempotente, nao reavalia a invariante
    key_store.revoke_safely("admin-b", role_store)
    assert key_store.get("admin-b").revoked is True


def test_revoke_safely_idempotente_mesmo_sendo_ultima_admin(tmp_path: Path):
    """Se admin-A ja esta revogada (por algum meio), revogar de novo
    e sucesso idempotente, mesmo que ela fosse tecnicamente a 'ultima'
    — a invariante so e avaliada na transicao nao-revogada -> revogada."""
    key_store = KeyStore(tmp_path)
    role_store = RoleStore(tmp_path)
    _preparar_admin_role(role_store)

    unica_admin = ApiKey(
        id="admin-1", key_hash="h", name="unica-admin", role_name="admin",
        created_at="now", revoked=True,  # ja revogada por construcao
    )
    key_store.add(unica_admin)

    key_store.revoke_safely("admin-1", role_store)  # nao deve levantar
    assert key_store.get("admin-1").revoked is True


def test_revoke_safely_chave_inexistente_levanta_identity_error(tmp_path: Path):
    key_store = KeyStore(tmp_path)
    role_store = RoleStore(tmp_path)  # garante .state/ existe, sem precisar de role

    with pytest.raises(IdentityError):
        key_store.revoke_safely("nao-existe", role_store)


def test_revoke_safely_role_inexistente_fail_closed(tmp_path: Path):
    """Se a role referenciada pela chave nao existe mais (referencia
    quebrada), a chave NAO conta como admin valida — e revogada
    livremente, sem bloquear por 'ultima admin' (porque nao ha como
    provar que ela e admin)."""
    key_store = KeyStore(tmp_path)
    role_store = RoleStore(tmp_path)  # roles.json fica vazio — nenhuma role existe

    orfa = ApiKey(id="orfa-1", key_hash="h", name="orfa", role_name="role-que-nao-existe", created_at="now")
    key_store.add(orfa)

    key_store.revoke_safely("orfa-1", role_store)  # nao deve levantar LastAdminKeyError
    assert key_store.get("orfa-1").revoked is True


def test_revoke_safely_nao_persiste_nada_quando_rejeitada(tmp_path: Path):
    """Garante que a rejeicao por LastAdminKeyError e verdadeiramente
    atomica: nenhuma escrita parcial ocorre."""
    key_store = KeyStore(tmp_path)
    role_store = RoleStore(tmp_path)
    _preparar_admin_role(role_store)

    unica_admin = ApiKey(id="admin-1", key_hash="h", name="unica-admin", role_name="admin", created_at="now")
    key_store.add(unica_admin)

    estado_antes = key_store.load_all()

    with pytest.raises(LastAdminKeyError):
        key_store.revoke_safely("admin-1", role_store)

    estado_depois = key_store.load_all()
    assert estado_antes["admin-1"].revoked == estado_depois["admin-1"].revoked == False
    assert estado_antes["admin-1"].to_dict() == estado_depois["admin-1"].to_dict()
