"""
Wazuh Alert Monitor & IOC Enrichment Tool
-------------------------------------------
Pulls recent high-severity alerts from a Wazuh Indexer (OpenSearch),
extracts source IPs from both Windows and Linux event structures,
enriches external IPs against AbuseIPDB, and exports a CSV report.

Author: Egwyl666
"""

import csv
import os
from datetime import datetime

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # dotenv is optional — env vars can also be set manually in the shell

# --- Configuration (loaded from environment variables) ---
INDEXER_API = os.environ.get("WAZUH_INDEXER_URL", "https://localhost:9200")
INDEXER_USER = os.environ.get("WAZUH_INDEXER_USER", "admin")
INDEXER_PASS = os.environ.get("WAZUH_INDEXER_PASS")

ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_API_KEY")

PRIVATE_PREFIXES = ("192.168.", "10.", "172.16.", "172.17.", "172.18.",
                     "172.19.", "172.2", "172.3", "127.", "::1")


def get_alerts(limit: int = 20) -> dict:
    """Query Wazuh Indexer for recent alerts matching security-relevant rule groups."""
    query = {
        "size": limit,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "must": [
                    {"range": {"rule.level": {"gte": 7}}},
                    {"terms": {"rule.groups": ["authentication_failures", "windows_security"]}}
                ]
            }
        }
    }
    response = requests.post(
        f"{INDEXER_API}/wazuh-alerts-*/_search",
        auth=(INDEXER_USER, INDEXER_PASS),
        json=query,
        verify=False,
        timeout=10
    )
    response.raise_for_status()
    return response.json()


def extract_ip(source: dict) -> str | None:
    """Extract source IP from either Windows (data.win.eventdata.ipAddress)
    or Linux (data.srcip) event structures."""
    win_ip = source.get("data", {}).get("win", {}).get("eventdata", {}).get("ipAddress")
    if win_ip and win_ip not in ("::1", "-"):
        return win_ip

    linux_ip = source.get("data", {}).get("srcip")
    if linux_ip:
        return linux_ip

    return None


def parse_alerts(raw_response: dict) -> list[dict]:
    """Flatten raw OpenSearch hits into a simplified list of alert dicts."""
    hits = raw_response.get("hits", {}).get("hits", [])
    parsed = []
    for hit in hits:
        source = hit["_source"]
        parsed.append({
            "timestamp": source.get("timestamp"),
            "agent": source.get("agent", {}).get("name"),
            "rule_id": source.get("rule", {}).get("id"),
            "rule_level": source.get("rule", {}).get("level"),
            "description": source.get("rule", {}).get("description"),
            "src_ip": extract_ip(source),
        })
    return parsed


def check_abuseipdb(ip: str | None, api_key: str) -> str:
    """Check IP reputation against AbuseIPDB. Skips private/loopback ranges
    to avoid wasting API quota on addresses that will never be listed."""
    if not ip:
        return "no IP"
    if ip.startswith(PRIVATE_PREFIXES):
        return "internal/private IP — skip"
    if not api_key:
        return "no API key configured"

    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    response = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers=headers,
        params=params,
        timeout=10
    )
    response.raise_for_status()
    data = response.json().get("data", {})
    score = data.get("abuseConfidenceScore", "N/A")
    return f"abuse score: {score}%"


def export_to_csv(rows: list[dict], filename: str | None = None) -> str:
    """Write enriched alert rows to a timestamped CSV file."""
    if filename is None:
        filename = f"soc_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

    fieldnames = ["timestamp", "agent", "rule_id", "rule_level", "description", "src_ip", "ip_status"]
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    return filename


def main():
    if not INDEXER_PASS:
        raise SystemExit("ERROR: set WAZUH_INDEXER_PASS environment variable before running.")

    alerts_raw = get_alerts()
    alerts_parsed = parse_alerts(alerts_raw)

    csv_rows = []
    for alert in alerts_parsed:
        ip_status = check_abuseipdb(alert["src_ip"], ABUSEIPDB_KEY)
        print(f"[{alert['timestamp']}] {alert['agent']} | level={alert['rule_level']} "
              f"| {alert['description']} | IP={alert['src_ip']} ({ip_status})")

        alert["ip_status"] = ip_status
        csv_rows.append(alert)

    saved_file = export_to_csv(csv_rows)
    print(f"\nSaved {len(csv_rows)} alerts to: {saved_file}")


if __name__ == "__main__":
    main()
