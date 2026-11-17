"""
OSINT e geolocalização de IPs.
"""

import requests
import json
import time

class Intelligence:
    """Busca informações sobre IPs suspeitos."""

    def __init__(self):
        self.cache = {}

    def geolocate(self, ip):
        """Geolocaliza um IP, incluindo ASN (item 8: enriquecimento de rede)."""
        if ip in self.cache:
            return self.cache[ip]

        try:
            response = requests.get(
                f"http://ip-api.com/json/{ip}?fields=status,country,city,regionName,isp,org,as,lat,lon,timezone",
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    self.cache[ip] = {
                        "ip": ip,
                        "country": data.get("country", "Desconhecido"),
                        "city": data.get("city", "Desconhecido"),
                        "region": data.get("regionName", "Desconhecido"),
                        "isp": data.get("isp", "Desconhecido"),
                        "org": data.get("org", "Desconhecido"),
                        "asn": data.get("as", "Desconhecido"),
                        "latitude": data.get("lat"),
                        "longitude": data.get("lon"),
                        "timezone": data.get("timezone", "Desconhecido")
                    }
                    return self.cache[ip]
        except Exception:
            pass

        return {"ip": ip, "error": "Não foi possível geolocalizar"}

    def check_virustotal(self, ip, api_key=None):
        """Verifica IP no VirusTotal."""
        if not api_key:
            return {"error": "API key necessária"}

        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            headers = {"x-apikey": api_key}
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                return response.json()
        except Exception:
            pass

        return {"error": "Falha na consulta ao VirusTotal"}

    def check_abuseipdb(self, ip, api_key=None):
        """Verifica IP no AbuseIPDB."""
        if not api_key:
            return {"error": "API key necessária"}

        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {"Key": api_key, "Accept": "application/json"}
            params = {"ipAddress": ip, "maxAgeInDays": 90}
            response = requests.get(url, headers=headers, params=params, timeout=10)
            if response.status_code == 200:
                return response.json()
        except Exception:
            pass

        return {"error": "Falha na consulta ao AbuseIPDB"}

    def whois(self, domain):
        """Consulta WHOIS de um domínio."""
        try:
            import whois
            return whois.whois(domain)
        except Exception:
            return {"error": "Falha na consulta WHOIS"}
