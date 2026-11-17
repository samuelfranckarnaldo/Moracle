"""
Deteção de WAF, CMS, Framework e Linguagem (para forense).
"""

import re
import requests

WAF_SIGNATURES = {
    "cloudflare": ["cf-ray", "cf-cache-status", "__cfduid"],
    "aws_waf": ["x-amzn-requestid", "x-amzn-trace-id"],
    "modsecurity": ["modsecurity", "sec-ch-ua"],
    "sucuri": ["x-sucuri-id", "x-sucuri-cache"],
}

CMS_SIGNATURES = {
    "wordpress": ["wp-content", "wp-admin", "wp-includes"],
    "joomla": ["administrator", "media/system"],
    "drupal": ["sites/default", "drupal"],
}

FRAMEWORK_SIGNATURES = {
    "laravel": ["Laravel", "X-Powered-By"],
    "django": ["django", "csrftoken"],
    "flask": ["werkzeug", "flask"],
    "spring": ["spring", "x-application-context"],
}

def detect_tech(url):
    """Deteta tecnologias num target."""
    result = {
        "waf": [],
        "cms": [],
        "framework": [],
        "language": None,
        "server": None,
        "headers": {}
    }
    
    try:
        response = requests.get(url, timeout=10, verify=False)
        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        result["headers"] = dict(response.headers)
        
        # Detetar servidor
        result["server"] = response.headers.get("Server", "desconhecido")
        
        # Detetar WAF
        for waf, patterns in WAF_SIGNATURES.items():
            for pattern in patterns:
                if pattern in str(response.headers).lower():
                    result["waf"].append(waf)
                    break
        
        # Detetar CMS
        for cms, patterns in CMS_SIGNATURES.items():
            for pattern in patterns:
                if pattern in response.text.lower():
                    result["cms"].append(cms)
                    break
        
        # Detetar Framework
        for framework, patterns in FRAMEWORK_SIGNATURES.items():
            for pattern in patterns:
                if pattern.lower() in response.text.lower() or pattern in str(response.headers):
                    result["framework"].append(framework)
                    break
        
        # Detetar linguagem
        language_patterns = {
            "php": ["php", ".php", "PHPSESSID"],
            "python": ["python", "wsgi", "uwsgi"],
            "node": ["node", "express"],
            "java": ["java", "servlet", "jsp"],
            "dotnet": ["aspx", "aspnet"],
        }
        
        for lang, patterns in language_patterns.items():
            for pattern in patterns:
                if pattern.lower() in response.text.lower() or pattern.lower() in str(response.headers).lower():
                    result["language"] = lang
                    break
                    
    except Exception as e:
        result["error"] = str(e)
    
    return result
