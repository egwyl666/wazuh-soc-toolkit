# Wazuh Alert Monitor & IOC Enrichment Tool

A lightweight Python tool that automates a task SOC analysts do manually every shift:
pull recent high-severity security alerts from a Wazuh SIEM, extract source IPs from
both Windows and Linux event formats, check those IPs against AbuseIPDB threat
intelligence, and export a clean CSV report for further investigation or handoff.

Built as part of a home SOC lab (Wazuh manager + Windows Domain Controller + Linux
endpoint), used to detect and report on a live simulated password spray attack
(MITRE ATT&CK T1110).

## What it does

1. **Queries the Wazuh Indexer** (OpenSearch) directly for alerts with `rule.level >= 7`
   belonging to `authentication_failures` / `windows_security` rule groups.
2. **Normalizes IP extraction** across heterogeneous event structures — Windows events
   store the source IP under `data.win.eventdata.ipAddress`, Linux/syslog events under
   `data.srcip`. The tool checks both paths and filters out loopback/internal noise.
3. **Enriches external IPs** via the [AbuseIPDB](https://www.abuseipdb.com/) API,
   skipping private ranges (`192.168.x`, `10.x`, `172.16-31.x`, `127.x`, `::1`) to avoid
   wasting API quota on addresses that will never be listed.
4. **Exports a timestamped CSV report** for documentation, ticketing, or IR write-ups.

## Example output

```
[2026-07-12T02:18:46+0300] DC1 | level=10 | Multiple Windows Logon Failures | IP=192.168.50.102 (internal/private IP — skip)
[2026-07-09T00:39:27+0300] pios | level=10 | sshd: brute force trying to get access | IP=192.168.50.102 (internal/private IP — skip)

Saved 20 alerts to: soc_report_20260712_143022.csv
```

A sample report from the home lab is included in [`sample_report/`](sample_report/).

## Setup

```bash
git clone https://github.com/egwyl666/wazuh-soc-toolkit.git
cd wazuh-soc-toolkit
pip install -r requirements.txt
cp .env.example .env
# edit .env with your own Wazuh Indexer password and AbuseIPDB API key
```

## Usage

```bash
python3 alert_monitor.py
```

Run it directly on the Wazuh manager host (or anywhere with access to the Indexer's
`9200` port). Requires a Wazuh Indexer `admin`-level (or read-scoped) user and a free
[AbuseIPDB API key](https://www.abuseipdb.com/register).

## Why this exists

Built while studying for a SOC Analyst role, to practice the parts of the job that
don't show up in tutorials: dealing with inconsistent log schemas across OS types,
avoiding wasted API calls, and turning raw SIEM output into something a human can
actually hand off in a report — rather than just detecting an alert and stopping there.

## Stack

- Python 3.11+
- Wazuh 4.x (Indexer / OpenSearch REST API)
- [AbuseIPDB](https://www.abuseipdb.com/) API v2

## License

MIT
