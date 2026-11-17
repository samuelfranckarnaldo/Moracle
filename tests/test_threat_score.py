import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.threat_score import calcular_confianca


def test_sem_fontes_retorna_desconhecido():
    resultado = calcular_confianca()
    assert resultado["score"] is None
    assert resultado["nivel"] == "desconhecido"


def test_ioc_cache_malicioso_gera_score_alto():
    resultado = calcular_confianca(entrada_ioc_cache={"malicioso": True})
    assert resultado["score"] == 100.0
    assert resultado["nivel"] == "critico"


def test_ioc_cache_limpo_gera_score_baixo():
    resultado = calcular_confianca(entrada_ioc_cache={"malicioso": False})
    assert resultado["score"] == 0.0
    assert resultado["nivel"] == "baixo"


def test_abuseipdb_score_alto():
    resultado = calcular_confianca(abuseipdb={"data": {"abuseConfidenceScore": 90}})
    assert resultado["score"] == 90.0
    assert resultado["nivel"] == "critico"


def test_fonte_com_erro_e_ignorada():
    resultado = calcular_confianca(virustotal={"error": "falha"}, entrada_ioc_cache={"malicioso": True})
    assert resultado["score"] == 100.0  # só ioc_cache contou
