"""
Chave de API do servidor Moracle - gerada uma vez na instalacao,
usada para autenticar quem envia eventos ou consulta o status.
"""
import os
import secrets

from core import config

KEY_PATH = os.path.join(config.RAIZ_PROJETO, ".state", "api_key.txt")


def obter_ou_criar():
    os.makedirs(os.path.dirname(KEY_PATH), exist_ok=True)
    if os.path.exists(KEY_PATH):
        _restringir_permissoes()
        with open(KEY_PATH) as f:
            return f.read().strip()
    chave = secrets.token_hex(32)
    # Criado ja com 0600 (O_EXCL): nunca existe uma janela em que o ficheiro
    # com o segredo seja legivel por outros utilizadores. Se outro processo
    # o criar entretanto, usa-se o dele.
    try:
        fd = os.open(KEY_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        with open(KEY_PATH) as f:
            return f.read().strip()
    with os.fdopen(fd, "w") as f:
        f.write(chave)
    return chave


def _restringir_permissoes():
    """Chave legada criada por versoes antigas com permissoes largas: fecha-as."""
    try:
        if os.stat(KEY_PATH).st_mode & 0o077:
            os.chmod(KEY_PATH, 0o600)
    except OSError:
        pass


def validar(chave_recebida):
    if not chave_recebida:
        return False
    esperada = obter_ou_criar()
    return secrets.compare_digest(chave_recebida, esperada)
