import os

import requests

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY")

MOCK_IP_DB = {
    "185.220.101.42": {
        "reputation": "malicious",
        "country": "DE",
        "asn": "AS24940 Hetzner",
        "categories": ["tor-exit", "scanner"],
    },
    "192.168.1.1": {"reputation": "clean", "country": "US", "asn": "AS15169 Google"},
    "10.0.0.1": {"reputation": "private", "country": "N/A", "asn": "N/A"},
}


def lookup_ip_reputation(ip: str) -> dict:
    if ABUSEIPDB_KEY:
        try:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=5,
            )
            data = resp.json().get("data", {})
            return {
                "source": "abuseipdb",
                "reputation": "malicious" if data.get("abuseConfidenceScore", 0) > 50 else "clean",
                "abuse_confidence_score": data.get("abuseConfidenceScore"),
                "country": data.get("countryCode"),
                "total_reports": data.get("totalReports"),
                "isp": data.get("isp"),
            }
        except Exception:
            pass  # fall through to mock

    return MOCK_IP_DB.get(ip, {"source": "mock", "reputation": "unknown", "country": "Unknown"})


def check_email_headers(headers: str) -> dict:
    h = headers.lower()
    fail = any(w in h for w in ["fail", "suspicious", "phish", "spoof"])
    return {
        "spf": "fail" if fail else "pass",
        "dkim": "invalid" if fail else "valid",
        "dmarc": "fail" if fail else "pass",
        "sender_domain_age_days": 2 if fail else 1825,
        "reply_to_mismatch": fail,
    }


def search_past_incidents(query: str) -> dict:
    q = query.lower()
    if any(w in q for w in ["phish", "email", "credential", "link", "click"]):
        return {
            "matches": 3,
            "most_recent": "2024-11-15",
            "incidents": [
                {"id": "INC-2024-0891", "type": "phishing", "severity": "high", "outcome": "credentials stolen"},
                {"id": "INC-2024-0654", "type": "phishing", "severity": "medium", "outcome": "blocked by MFA"},
            ],
        }
    if any(w in q for w in ["brute", "login", "ssh", "rdp", "password", "failed attempt"]):
        return {
            "matches": 7,
            "most_recent": "2025-01-02",
            "incidents": [
                {"id": "INC-2025-0012", "type": "brute_force", "severity": "high", "outcome": "account locked"},
            ],
        }
    return {"matches": 0, "incidents": []}


TOOLS = {
    "lookup_ip_reputation": lookup_ip_reputation,
    "check_email_headers": check_email_headers,
    "search_past_incidents": search_past_incidents,
}
