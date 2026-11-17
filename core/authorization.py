"""
core/authorization.py

Camada de autorização: decide se uma ApiKey autenticada pode executar uma
operação. Separada de core/auth.py (que decide apenas SE a credencial é
válida) — autenticação e autorização são perguntas diferentes:

    "quem é você?"           -> core/auth.py     (autenticar)
    "você pode fazer isso?"  -> core/authorization.py (exigir_permissao)

Escopo deste módulo (Passo 3):
    - autorizar(): função pura de decisão (permission + scope).
    - exigir_permissao(): wrapper que resolve o ServiceRole da ApiKey via
      RoleStore e delega a decisão para autorizar().

Fora de escopo deste módulo (passos futuros):
    - Middleware, rotas, Admin API, CLI, Console.
    - Resolução de deployment_id -> application_id (isso é
      responsabilidade de quem CHAMA exigir_permissao() a partir da rota;
      este módulo recebe app_name já resolvido, nunca resolve sozinho a
      partir de uma URL ou de um deployment_id).

Contrato de decisão:

    ApiKey
       |
       +-- role.is_wildcard (server.admin)? --> AUTORIZADO (ignora tudo)
       |
       +-- permission em role.permissions?
       |     nao --> NEGADO
       |     sim, e app_name is None (operacao sem alvo de app)
       |          --> AUTORIZADO
       |     sim, e app_name fornecido
       |          +-- api_key.is_globally_scoped (scoped_app_names == [])?
       |          |     sim --> AUTORIZADO
       |          +-- app_name in api_key.scoped_app_names?
       |                sim --> AUTORIZADO
       |                nao --> NEGADO

Scope nunca concede permissão por si só: a checagem de permission ocorre
sempre primeiro (exceto para server.admin, que ignora ambas por definicao
de wildcard).
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from core.identity import (
    ApiKey,
    ServiceRole,
    RoleStore,
    IdentityError,
    UnknownPermissionError,
    KNOWN_PERMISSIONS,
)


class ResolucaoAcesso(Enum):
    """
    Resultado granular de resolver_acesso() — distingue as duas
    dimensões de negação (escopo vs. permissão), necessário para
    políticas HTTP que precisam responder 404 (fora do universo da
    chave) vs. 403 (visível, mas sem permissão) sem duplicar a regra
    de autorização em duas implementações (Passo Console-A).
    """
    AUTORIZADO = "autorizado"
    SEM_ESCOPO = "sem_escopo"
    SEM_PERMISSAO = "sem_permissao"


def resolver_acesso(
    api_key: ApiKey,
    role: ServiceRole,
    permission: str,
    app_name: Optional[str] = None,
) -> ResolucaoAcesso:
    """
    Implementação ÚNICA da regra de autorização — fonte de verdade
    da qual autorizar() deriva seu booleano. Distingue granularmente
    qual dimensão (escopo ou permissão) causou uma negação.

    A ordem de avaliação (escopo antes de permissão) é diferente da
    formulação original deste módulo (permissão antes de escopo), mas
    matematicamente equivalente para o resultado booleano — provado
    por análise de equivalência exaustiva antes da implementação:
    fora do wildcard, o resultado sempre se reduz a
    "permission válida E scope permitido", uma conjunção cujo valor
    não depende da ordem de avaliação dos operandos.

    app_name, quando fornecido, deve já estar resolvido para o nome
    real da Application alvo da operação (nunca um deployment_id ou
    qualquer outro identificador indireto — resolução é
    responsabilidade de quem chama).

    Levanta UnknownPermissionError se `permission` não pertence ao
    contrato (erro de programação, não decisão de negócio).
    """
    if permission not in KNOWN_PERMISSIONS:
        raise UnknownPermissionError(
            f"Permissão fora do contrato: {permission!r}"
        )

    if role.is_wildcard:
        return ResolucaoAcesso.AUTORIZADO

    if app_name is not None:
        dentro_do_escopo = api_key.is_globally_scoped or app_name in api_key.scoped_app_names
        if not dentro_do_escopo:
            return ResolucaoAcesso.SEM_ESCOPO

    if permission not in role.permissions:
        return ResolucaoAcesso.SEM_PERMISSAO

    return ResolucaoAcesso.AUTORIZADO


def autorizar(
    api_key: ApiKey,
    role: ServiceRole,
    permission: str,
    app_name: Optional[str] = None,
) -> bool:
    """
    Decisão pura de autorização, sem I/O. Recebe a ApiKey e o ServiceRole
    já resolvidos (chamador é responsável por essa resolução — ver
    exigir_permissao() para o caso comum via RoleStore).

    Delega inteiramente para resolver_acesso() — nenhuma lógica de
    decisão própria, apenas colapsa o resultado granular em booleano
    para consumidores que não precisam distinguir a causa da negação.
    """
    return resolver_acesso(api_key, role, permission, app_name=app_name) == ResolucaoAcesso.AUTORIZADO


def exigir_permissao(
    api_key: ApiKey,
    role_store: RoleStore,
    permission: str,
    app_name: Optional[str] = None,
) -> bool:
    """
    Wrapper de conveniência: resolve o ServiceRole da ApiKey via
    role_store e delega a decisão para autorizar().

    Falha fechada: se o role referenciado por api_key.role_name não
    existir mais no RoleStore (ex.: renomeado ou removido depois que a
    chave foi criada), a operação é NEGADA — nunca autorizada sobre uma
    referência quebrada.
    """
    role = role_store.get(api_key.role_name)
    if role is None:
        return False

    return autorizar(api_key, role, permission, app_name=app_name)
