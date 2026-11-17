#!/usr/bin/env python3
"""
Varredura de segredos e dados pessoais num repositorio git (so leitura).

Uso (a partir da raiz do repositorio, ou passando o caminho):
    python3 varrer_segredos.py [CAMINHO_DO_REPO]

O que faz (nunca altera nada):
  1. Ficheiros sensiveis que ALGUMA VEZ entraram no historico (todas as
     branches, tags e stash): config.json, .state/*, *.key, *.pem, api_key.txt,
     caches, logs de auditoria, etc. Diz em que commits e se hoje ainda estao
     versionados.
  2. Conteudo que parece segredo em TODAS as linhas adicionadas no historico
     (tokens, chaves privadas, webhooks, atribuicoes api_key=... etc).
  3. E-mails de autor/committer e caminhos pessoais (para decidir o que expor).
  4. Ficheiros sensiveis presentes na pasta que o .gitignore NAO cobre.

A SAIDA NUNCA TEM VALORES COMPLETOS: so um excerto mascarado (inicio e fim) e
o comprimento. E seguro colar o resultado numa conversa.
"""
import re
import subprocess
import sys
from collections import defaultdict

SENSIVEIS = [
    (r"(^|/)config\.json$", "configuracao local (pode ter webhook/chaves)"),
    (r"(^|/)\.state/", "estado local (.state/)"),
    (r"(^|/)api_key\.txt$", "chave de API legada"),
    (r"\.key$", "ficheiro de chave"),
    (r"\.pem$", "certificado/chave PEM"),
    (r"\.(p12|pfx|jks|keystore)$", "keystore"),
    (r"(^|/)id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$", "chave SSH"),
    (r"(^|/)\.env(\.|$)", "ficheiro .env"),
    (r"(^|/)(keys|roles)\.json$", "store de chaves/roles"),
    (r"(^|/)ioc_cache\.json", "cache de IOC"),
    (r"(^|/)(audit\.log|alerts\.log|access_log\.jsonl|security_events\.jsonl|"
     r"fila_eventos\.jsonl|blocklist\.json|defesa_state\.json)$", "estado/logs"),
    (r"chave_assinatura", "chave de assinatura"),
    (r"\.(sqlite|sqlite3|db)$", "base de dados"),
]

PADROES = [
    ("chave privada", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY")),
    ("token GitHub", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b")),
    ("token GitHub (fine-grained)", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{30,}\b")),
    ("chave AWS", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("token Slack", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("webhook Slack", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]{20,}")),
    ("webhook Discord", re.compile(r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]{20,}")),
    ("chave estilo sk-", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("cabecalho Bearer", re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]{20,}")),
    ("atribuicao de segredo", re.compile(
        r"""(?ix)\b(api[_-]?key|apikey|secret|token|passw(?:or)?d|senha|webhook[_-]?(?:url|secret)|
        virustotal|abuseipdb)\b["']?\s*[:=]\s*["']([^"'\s]{8,})["']""")),
    ("hex longo (token/hash)", re.compile(r"\b[0-9a-f]{64}\b")),
]

# valores obviamente de exemplo/vazios nao sao reportados
IGNORAR_VALOR = re.compile(
    r"(?i)^(null|none|true|false|\*+|x{4,}|<.*>|\$\{.*\}|exemplo|example|changeme|"
    r"your[_-].*|chave_vt|chave_ab|token[_-]?(?:aqui|de[_-].*)|\.\.\.+)$")

CAMINHOS_PESSOAIS = re.compile(r"(/data/data/com\.termux/files/home|/home/[A-Za-z0-9_.-]+|/Users/[A-Za-z0-9_.-]+|C:\\Users\\[A-Za-z0-9_.-]+)")


def git(repo, *args, check=True):
    r = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True,
                       errors="replace")
    if check and r.returncode != 0:
        sys.exit("erro de git: " + r.stderr.strip()[:300])
    return r.stdout


def mascarar(valor):
    v = valor.strip()
    if len(v) <= 8:
        return "*" * len(v) + " (len=%d)" % len(v)
    return "%s...%s (len=%d)" % (v[:3], v[-2:], len(v))


def sensivel(caminho):
    for rx, motivo in SENSIVEIS:
        if re.search(rx, caminho):
            return motivo
    return None


def varrer_nomes(repo):
    print("== 1. Ficheiros sensiveis alguma vez no historico ==")
    saida = git(repo, "log", "--all", "--name-only", "--format=@@%h")
    por_caminho = defaultdict(list)
    commit = None
    for linha in saida.splitlines():
        if linha.startswith("@@"):
            commit = linha[2:]
        elif linha.strip() and commit:
            por_caminho[linha.strip()].append(commit)
    versionados = set(git(repo, "ls-files").splitlines())
    achados = 0
    for caminho in sorted(por_caminho):
        motivo = sensivel(caminho)
        if not motivo:
            continue
        achados += 1
        cs = por_caminho[caminho]
        estado = "AINDA VERSIONADO" if caminho in versionados else "removido depois (mas continua no historico)"
        print("  %-44s %s | %d commit(s), ex.: %s | %s" % (caminho[:44], motivo, len(cs), ", ".join(cs[:3]), estado))
    if not achados:
        print("  nenhum")
    return achados


def varrer_conteudo(repo):
    print("\n== 2. Conteudo com aspeto de segredo nas linhas adicionadas (todo o historico) ==")
    proc = subprocess.Popen(
        ["git", "-C", repo, "log", "--all", "-p", "--no-color", "-U0", "--format=@@C %h", "--diff-filter=AMR"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, errors="replace")
    commit, ficheiro = "?", "?"
    vistos = set()
    resultados = defaultdict(list)
    binarios = 0
    for linha in proc.stdout:
        if linha.startswith("@@C "):
            commit = linha[4:].strip()
            continue
        if linha.startswith("+++ "):
            ficheiro = linha[4:].strip()
            ficheiro = ficheiro[2:] if ficheiro.startswith("b/") else ficheiro
            continue
        if linha.startswith("Binary files"):
            binarios += 1
            continue
        if not linha.startswith("+") or linha.startswith("+++"):
            continue
        texto = linha[1:]
        if len(texto) > 4000:       # linhas enormes (minificados): ignora
            continue
        for nome, rx in PADROES:
            for m in rx.finditer(texto):
                valor = m.group(m.lastindex) if m.lastindex else m.group(0)
                if IGNORAR_VALOR.match(valor.strip()):
                    continue
                rotulo = nome
                if nome.startswith("hex longo") and re.search(r"(?i)hash|sha|digest|checksum|commit", texto):
                    rotulo = "hex longo (provavel hash)"
                chave = (commit, ficheiro, rotulo, mascarar(valor))
                if chave in vistos:
                    continue
                vistos.add(chave)
                resultados[rotulo].append(chave)
    proc.wait()
    total = 0
    for rotulo in sorted(resultados, key=lambda r: (r.startswith("hex longo"), r)):
        itens = resultados[rotulo]
        total += len(itens)
        print("  [%s] %d ocorrencia(s)" % (rotulo, len(itens)))
        for commit, ficheiro, _, masc in itens[:12]:
            print("      commit %-8s %-40s %s" % (commit, ficheiro[:40], masc))
        if len(itens) > 12:
            print("      ... mais %d" % (len(itens) - 12))
    if not total:
        print("  nenhum")
    if binarios:
        print("  (%d alteracao(oes) binaria(s) nao inspecionadas)" % binarios)
    return total


def varrer_pessoal(repo):
    print("\n== 3. Identidade e caminhos pessoais expostos pelo historico ==")
    autores = git(repo, "log", "--all", "--format=%an <%ae>%n%cn <%ce>")
    distintos = sorted(set(l for l in autores.splitlines() if l.strip()))
    for a in distintos:
        nome, _, email = a.partition(" <")
        email = email.rstrip(">")
        user, _, dom = email.partition("@")
        print("  autor/committer: %s <%s***@%s>" % (nome, user[:2], dom))
    contagem = 0
    amostra = set()
    saida = git(repo, "grep", "-I", "-n", "-E", r"/data/data/com\.termux|/home/[a-zA-Z0-9_.-]+|/Users/[a-zA-Z0-9_.-]+",
                "HEAD", check=False)
    for linha in saida.splitlines():
        contagem += 1
        m = CAMINHOS_PESSOAIS.search(linha)
        if m:
            amostra.add(linha.split(":", 2)[1] if linha.count(":") >= 2 else linha[:40])
    print("  caminhos pessoais na versao atual (HEAD): %d linha(s)%s"
          % (contagem, " em " + ", ".join(sorted(amostra)[:6]) if amostra else ""))
    if not distintos:
        print("  (sem commits)")


def varrer_arvore(repo):
    print("\n== 4. Ficheiros sensiveis presentes na pasta e NAO ignorados ==")
    saida = git(repo, "ls-files", "--cached", "--others", "--exclude-standard")
    problemas = 0
    for caminho in sorted(set(saida.splitlines())):
        motivo = sensivel(caminho)
        if motivo:
            problemas += 1
            print("  %-44s %s" % (caminho[:44], motivo))
    if not problemas:
        print("  nenhum (o .gitignore cobre o que existe)")
    return problemas


def main():
    repo = sys.argv[1] if len(sys.argv) > 1 else "."
    git(repo, "rev-parse", "--git-dir")
    n_commits = git(repo, "rev-list", "--all", "--count").strip()
    print("Repositorio: %s | commits (todas as refs): %s\n" % (repo, n_commits))
    a = varrer_nomes(repo)
    b = varrer_conteudo(repo)
    varrer_pessoal(repo)
    c = varrer_arvore(repo)
    print("\n== Resumo ==")
    print("  ficheiros sensiveis no historico: %d | linhas com aspeto de segredo: %d | por ignorar: %d" % (a, b, c))
    print("  Nota: 'hex longo' tambem apanha hashes sha256 legitimos; os marcados como 'provavel hash' sao menos urgentes.")


if __name__ == "__main__":
    main()
