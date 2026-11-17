"""
Testes dos padrões de deteção — protege contra regressão silenciosa
quando alguém ajustar um regex em core/logs.py.
"""
import os
import sys
import tempfile
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.logs import LogAnalyzer


def _escrever_log_temp(conteudo):
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False)
    f.write(conteudo)
    f.close()
    return f.name


@pytest.fixture
def limpar_arquivo():
    arquivos = []
    yield arquivos
    for caminho in arquivos:
        if os.path.exists(caminho):
            os.chmod(caminho, 0o644)  # custody.py trava como somente-leitura
            os.remove(caminho)
        custodia = caminho + ".custodia.json"
        if os.path.exists(custodia):
            os.remove(custodia)


def _analisar(conteudo, limpar_arquivo):
    caminho = _escrever_log_temp(conteudo)
    limpar_arquivo.append(caminho)
    analyzer = LogAnalyzer(caminho)
    analyzer.load()
    findings = analyzer.analyze()
    return findings


def test_detecta_sql_injection(limpar_arquivo):
    findings = _analisar('192.168.1.1 - - "GET /login?user=admin\' OR \'1\'=\'1" 200\n', limpar_arquivo)
    tipos = [f["attack_type"] for f in findings]
    assert "sql_injection" in tipos


def test_detecta_path_traversal(limpar_arquivo):
    findings = _analisar('10.0.0.5 - - "GET /etc/passwd HTTP/1.1" 404\n', limpar_arquivo)
    tipos = [f["attack_type"] for f in findings]
    assert "path_traversal" in tipos


def test_detecta_xss(limpar_arquivo):
    findings = _analisar('10.0.0.1 - - "GET /search?q=<script>alert(1)</script>" 200\n', limpar_arquivo)
    tipos = [f["attack_type"] for f in findings]
    assert "xss" in tipos


def test_detecta_scanner(limpar_arquivo):
    findings = _analisar('10.0.0.1 - - "GET /wp-admin/ HTTP/1.1" 404\n', limpar_arquivo)
    tipos = [f["attack_type"] for f in findings]
    assert "scanner" in tipos


def test_linha_limpa_nao_gera_falso_positivo(limpar_arquivo):
    findings = _analisar('10.0.0.1 - - "GET /index.html HTTP/1.1" 200\n', limpar_arquivo)
    assert len(findings) == 0


def test_extrai_ip_corretamente(limpar_arquivo):
    findings = _analisar('203.0.113.9 - - "GET /etc/passwd HTTP/1.1" 404\n', limpar_arquivo)
    assert findings[0]["ip"] == "203.0.113.9"


def test_custodia_gera_hash(limpar_arquivo):
    caminho = _escrever_log_temp("linha de teste\n")
    limpar_arquivo.append(caminho)
    analyzer = LogAnalyzer(caminho)
    analyzer.load()
    assert analyzer.custodia is not None
    assert analyzer.custodia.hash_sha256 is not None
    assert len(analyzer.custodia.hash_sha256) == 64


def test_verificar_integridade_apos_load(limpar_arquivo):
    caminho = _escrever_log_temp("linha estável\n")
    limpar_arquivo.append(caminho)
    analyzer = LogAnalyzer(caminho)
    analyzer.load()
    assert analyzer.verificar_integridade() is True
