"""
core/auth.py

Fronteira entre credencial apresentada (token bruto) e identidade
autenticada (ApiKey). Este módulo cobre apenas AUTENTICAÇÃO.

Autorização (permissões, escopo por aplicação, server.admin como coringa)
é responsabilidade de um módulo/etapa futura (Passo 6 — exigir_permissao)
e não deve ser implementada aqui.

Fora de escopo deste módulo (Passo 2):
    - Verificação de permissions.
    - Verificação de scoped_app_names.
    - Middleware, rotas, CLI.
    - server/.
"""

from __future__ import annotations

import secrets
from datetime import datetime
from typing import Optional

from core.identity import ApiKey, KeyStore, hash_token, is_expired


def autenticar(
    token: Optional[str],
    key_store: KeyStore,
    now: Optional[datetime] = None,
) -> Optional[ApiKey]:
    """
    token apresentado
           |
           v
       hash SHA-256
           |
           v
    procurar ApiKey (comparação em tempo constante do hash)
           |
    nao encontrada -------> None
           |
        revoked? ----------> None
           |
        expired? ----------> None
           |
    touch_last_used()
           |
           v
        ApiKey (atualizada)

    Nunca revela, por timing ou por mensagem, se um token "quase certo"
    corresponde a alguma chave existente: qualquer falha (nao encontrada,
    revogada, expirada) retorna o mesmo None, sem distinção observável
    pelo chamador.
    """
    if not token:
        return None

    presented_hash = hash_token(token)

    matched: Optional[ApiKey] = None
    for candidate in key_store.load_all().values():
        if secrets.compare_digest(candidate.key_hash, presented_hash):
            matched = candidate
            break

    if matched is None:
        return None

    if matched.revoked:
        return None

    if is_expired(matched, now=now):
        return None

    key_store.touch_last_used(matched.id)

    # Recarrega para devolver o registro com last_used_at já persistido,
    # em vez de reconstruir o timestamp em memória (evita divergência
    # entre o que foi de fato gravado e o que é retornado ao chamador).
    return key_store.get(matched.id)
