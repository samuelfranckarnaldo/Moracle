"""
tests/test_state_isolation_audit.py

Teste de auditoria estatica (Passo 4C): garante que o mapa
CAMINHOS_DE_ESTADO em conftest.py permanece exaustivo em relacao a
qualquer constante de NIVEL DE MODULO, em core/, deploy_platform/,
admin_api/ e server/, derivada (direta ou transitivamente, via
fechamento ate ponto fixo) de config.RAIZ_PROJETO atraves de
os.path.join().

Se este teste falhar, um caminho de estado persistente novo foi
introduzido em producao sem ser registrado no mapa de isolamento — a
fixture estado_isolado NAO o cobre, e testes que o exercitem podem
escrever no .state/ real. Adicione a constante faltante a
CAMINHOS_DE_ESTADO em conftest.py antes de prosseguir.

Detecta tanto:
    from core.config import RAIZ_PROJETO      (alias de nome direto)
    from core import config; config.RAIZ_PROJETO   (acesso por atributo)

LIMITACOES CONHECIDAS DESTE DETECTOR (documentadas, nao resolvidas):
  - So detecta atribuicoes de NIVEL DE MODULO (globais). Constantes
    calculadas DENTRO do corpo de uma funcao (ex.: core/ioc_cache.py,
    core/cleanup.py) nao sao a mesma classe de risco: como recalculam
    a partir de config.RAIZ_PROJETO a cada chamada, o patch de
    RAIZ_PROJETO sozinho ja as cobre automaticamente — nao precisam
    de entrada no mapa, e por isso nao sao sinalizadas por este teste.
  - So reconhece o padrao os.path.join(...). NAO detecta pathlib
    (Path(x) / "y"), concatenacao com "+", f-strings, nem
    os.environ.get(...) como fonte alternativa de caminho.
  - Nao detecta construcao via setattr, exec, ou metaprogramacao.
  - O conjunto de diretorios escaneados e FIXO (DIRETORIOS_PRODUCAO
    abaixo). Um pacote de producao novo fora dessa lista nao seria
    escaneado — quem criar um pacote novo com estado persistente
    precisa lembrar de adiciona-lo aqui.
"""
import ast
import importlib
import os

from tests.conftest import CAMINHOS_DE_ESTADO


RAIZ_DO_PROJETO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DIRETORIOS_PRODUCAO = ["core", "deploy_platform", "admin_api", "server"]

# Excecoes documentadas: constantes que o detector encontraria
# corretamente, mas que sao divida ja registrada e conscientemente
# fora do escopo do 4C (config.json permanece fora desta etapa).
EXCECOES_DOCUMENTADAS = {
    ("core.config", "CONFIG_PATH"),  # config.json - divida separada
}


def _caminho_para_modulo_dotted(caminho_py, raiz):
    relativo = os.path.relpath(caminho_py, raiz)
    sem_extensao = relativo[:-3] if relativo.endswith(".py") else relativo
    return sem_extensao.replace(os.sep, ".")


def _listar_arquivos_py(diretorio):
    for dirpath, _, filenames in os.walk(diretorio):
        if "__pycache__" in dirpath:
            continue
        for nome in filenames:
            if nome.endswith(".py"):
                yield os.path.join(dirpath, nome)


def _analisar_modulo(caminho_py):
    """
    Retorna o conjunto de nomes de constantes de nivel de modulo que
    sao derivadas de RAIZ_PROJETO via os.path.join(), com fechamento
    transitivo ate ponto fixo (A deriva de RAIZ, B deriva de A, C
    deriva de B -> A, B e C sao todas marcadas).
    """
    with open(caminho_py, encoding="utf-8") as f:
        arvore = ast.parse(f.read(), filename=caminho_py)

    aliases_diretos = set()        # nomes locais que SAO RAIZ_PROJETO
    aliases_modulo_config = set()  # nomes locais que SAO o modulo core.config

    for node in ast.walk(arvore):
        if isinstance(node, ast.ImportFrom):
            modulo_origem = node.module or ""
            for alias in node.names:
                nome_importado = alias.name
                nome_local = alias.asname or alias.name
                if modulo_origem in ("core.config", "config") and nome_importado == "RAIZ_PROJETO":
                    aliases_diretos.add(nome_local)
                if modulo_origem == "core" and nome_importado == "config":
                    aliases_modulo_config.add(nome_local)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "core.config":
                    aliases_modulo_config.add(alias.asname or "config")

    # Caso especial: core/config.py define RAIZ_PROJETO localmente
    # (nao importa) — precisa ser reconhecido como origem para que
    # CONFIG_PATH (derivada dela, no mesmo arquivo) seja detectada.
    for node in arvore.body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id == "RAIZ_PROJETO"):
            aliases_diretos.add("RAIZ_PROJETO")

    def _expr_e_raiz_projeto(expr):
        if isinstance(expr, ast.Name) and expr.id in aliases_diretos:
            return True
        if isinstance(expr, ast.Attribute) and expr.attr == "RAIZ_PROJETO":
            if isinstance(expr.value, ast.Name) and expr.value.id in aliases_modulo_config:
                return True
        return False

    atribuicoes_modulo = [
        node for node in arvore.body
        if isinstance(node, ast.Assign) and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
    ]

    derivadas = set()
    mudou = True
    while mudou:
        mudou = False
        for node in atribuicoes_modulo:
            nome_alvo = node.targets[0].id
            if nome_alvo in derivadas:
                continue
            valor = node.value
            if not (isinstance(valor, ast.Call) and isinstance(valor.func, ast.Attribute)
                    and valor.func.attr == "join"):
                continue
            if not valor.args:
                continue
            primeiro_arg = valor.args[0]

            e_derivada = (
                _expr_e_raiz_projeto(primeiro_arg)
                or (isinstance(primeiro_arg, ast.Name) and primeiro_arg.id in derivadas)
            )

            if e_derivada:
                derivadas.add(nome_alvo)
                mudou = True

    return derivadas


def test_mapa_de_estado_permanece_exaustivo():
    nao_mapeadas = []

    for diretorio_nome in DIRETORIOS_PRODUCAO:
        diretorio = os.path.join(RAIZ_DO_PROJETO, diretorio_nome)
        if not os.path.isdir(diretorio):
            continue
        for caminho_py in _listar_arquivos_py(diretorio):
            modulo_dotted = _caminho_para_modulo_dotted(caminho_py, RAIZ_DO_PROJETO)
            derivadas = _analisar_modulo(caminho_py)
            for nome_constante in derivadas:
                chave = (modulo_dotted, nome_constante)
                if chave in EXCECOES_DOCUMENTADAS:
                    continue
                mapeadas_do_modulo = CAMINHOS_DE_ESTADO.get(modulo_dotted, [])
                if nome_constante not in mapeadas_do_modulo:
                    nao_mapeadas.append(chave)

    assert not nao_mapeadas, (
        "Constantes de estado derivadas de RAIZ_PROJETO encontradas em "
        "producao mas AUSENTES do mapa CAMINHOS_DE_ESTADO (tests/conftest.py): "
        f"{nao_mapeadas}. A fixture estado_isolado nao as isola — "
        "adicione-as ao mapa antes de prosseguir."
    )


def test_mapa_nao_contem_entradas_fantasmas():
    """Protege contra entradas obsoletas: modulo/constante removidos
    ou renomeados em producao sem atualizar o mapa."""
    problemas = []
    for modulo_nome, constantes in CAMINHOS_DE_ESTADO.items():
        try:
            modulo = importlib.import_module(modulo_nome)
        except ImportError as e:
            problemas.append(f"{modulo_nome}: nao importavel ({e})")
            continue
        for nome_constante in constantes:
            if not hasattr(modulo, nome_constante):
                problemas.append(f"{modulo_nome}.{nome_constante}: nao existe mais")

    assert not problemas, f"Entradas obsoletas em CAMINHOS_DE_ESTADO: {problemas}"
