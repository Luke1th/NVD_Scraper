#!/usr/bin/env python3
"""
NVD Scraper for Obsidian

Pulls the CVEs published in the last N days from the NIST National
Vulnerability Database (NVD) API 2.0 and writes one Markdown note per CVE
into an Obsidian vault, sorted into Critical / High / Medium / Low folders.

Configuration is read from environment variables:

    OBSIDIAN_VAULT_PATH   (required)  Absolute path to your Obsidian vault
    NVD_API_KEY           (optional)  Your NVD API key (higher rate limits)
    NVD_DAYS_BACK         (optional)  How many days to look back (default: 7)
"""

import datetime
import json
import os
import sys
import time

import requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000  # NVD maximum

# Path of the NVD folder inside the vault. Used for the filesystem and for
# the Dataview queries, so Obsidian-style forward slashes are used here.
NVD_REL = "01_Vulnerability Data/NVD"
DASHBOARD_REL = "00_Dashboard"

SEVERITIES = ["Critical", "High", "Medium", "Low", "Unscored"]
SEVERITY_ICONS = {
    "Critical": "🔴",
    "High": "🟠",
    "Medium": "🟡",
    "Low": "🟢",
    "Unscored": "⚪",
}


def load_config():
    """Read configuration from environment variables."""
    vault = os.environ.get("OBSIDIAN_VAULT_PATH")
    if not vault:
        sys.exit(
            "❌ OBSIDIAN_VAULT_PATH is not set.\n"
            "   Set it to the absolute path of your Obsidian vault, e.g.\n"
            '   PowerShell:  $env:OBSIDIAN_VAULT_PATH = "C:\\Users\\Bob\\Obsidian"\n'
            '   bash/zsh:    export OBSIDIAN_VAULT_PATH="$HOME/Obsidian"'
        )
    if not os.path.isdir(vault):
        sys.exit(f"❌ Vault path does not exist: {vault}")

    api_key = os.environ.get("NVD_API_KEY", "").strip()
    if not api_key:
        print("⚠️  NVD_API_KEY is not set. Requests will be slower (rate limited).")

    try:
        days_back = int(os.environ.get("NVD_DAYS_BACK", "7"))
    except ValueError:
        sys.exit("❌ NVD_DAYS_BACK must be a whole number.")

    return vault, api_key, days_back


def get_cvss_info(metrics):
    """Extract CVSS information (prefers v3.1, then v3.0, plus v2)."""
    cvss_v31 = metrics.get("cvssMetricV31", [{}])[0] if metrics.get("cvssMetricV31") else {}
    cvss_v30 = metrics.get("cvssMetricV30", [{}])[0] if metrics.get("cvssMetricV30") else {}
    cvss_v2 = metrics.get("cvssMetricV2", [{}])[0] if metrics.get("cvssMetricV2") else {}

    v3_data = cvss_v31.get("cvssData", {}) or cvss_v30.get("cvssData", {})
    v2_data = cvss_v2.get("cvssData", {})

    return {
        "v3_score": v3_data.get("baseScore", "N/A"),
        "v3_severity": v3_data.get("baseSeverity", "N/A"),
        "v3_vector": v3_data.get("vectorString", "N/A"),
        "v3_attack_vector": v3_data.get("attackVector", "N/A"),
        "v3_attack_complexity": v3_data.get("attackComplexity", "N/A"),
        "v3_privileges_required": v3_data.get("privilegesRequired", "N/A"),
        "v3_user_interaction": v3_data.get("userInteraction", "N/A"),
        "v3_scope": v3_data.get("scope", "N/A"),
        "v3_confidentiality": v3_data.get("confidentialityImpact", "N/A"),
        "v3_integrity": v3_data.get("integrityImpact", "N/A"),
        "v3_availability": v3_data.get("availabilityImpact", "N/A"),
        "v2_score": v2_data.get("baseScore", "N/A"),
        "v2_vector": v2_data.get("vectorString", "N/A"),
    }


def get_severity(score):
    """Map a CVSS v3 base score to a severity label.

    Newly published CVEs are often not scored yet, so a missing score is
    reported as "Unscored" instead of being silently treated as Medium.
    """
    if score == "N/A":
        return "Unscored"
    score = float(score)
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"


def english_description(cve_data):
    """Return the English description, falling back to the first one."""
    descriptions = cve_data.get("descriptions", [])
    for d in descriptions:
        if d.get("lang") == "en":
            return d.get("value", "")
    return descriptions[0].get("value", "") if descriptions else "No description available."


def write_file(path, content):
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def create_dashboard(base_folder):
    """Create the main Dataview dashboard note."""
    now = datetime.datetime.now()
    content = f"""---
type: dashboard
date: {now.strftime('%Y-%m-%d')}
tags: [nvd, dashboard]
---

# 🎯 Vulnerability Dashboard

## 📊 Severity Overview

```dataview
TABLE
    length(rows) as Count
FROM "{NVD_REL}"
WHERE type = "vulnerability"
GROUP BY severity
SORT severity ASC
```

## 🔴 Critical Vulnerabilities

```dataview
TABLE
    file.link as CVE,
    cvss_v3_score as CVSS,
    published as Published
FROM "{NVD_REL}"
WHERE type = "vulnerability" AND severity = "Critical"
SORT cvss_v3_score DESC
```

## 🟠 High Severity Vulnerabilities

```dataview
TABLE
    file.link as CVE,
    cvss_v3_score as CVSS,
    published as Published
FROM "{NVD_REL}"
WHERE type = "vulnerability" AND severity = "High"
SORT cvss_v3_score DESC
```

## 📋 Action Items
- [ ] Review Critical Vulnerabilities
- [ ] Assess High Severity Items
- [ ] Update Security Advisories
- [ ] Schedule Patch Review

Last Updated: {now.strftime('%Y-%m-%d %H:%M:%S')}
"""
    write_file(os.path.join(base_folder, "dashboard.md"), content)


def create_canvas(vault):
    """Create the Obsidian canvas that links to the dashboard."""
    canvas_folder = os.path.join(vault, DASHBOARD_REL)
    os.makedirs(canvas_folder, exist_ok=True)

    canvas_data = {
        "nodes": [
            {
                "id": "dashboard",
                "x": 0,
                "y": 0,
                "width": 500,
                "height": 500,
                "type": "file",
                "file": f"{NVD_REL}/dashboard.md",
            },
            {
                "id": "critical",
                "x": -600,
                "y": 0,
                "width": 400,
                "height": 400,
                "type": "text",
                "text": (
                    "# Critical Vulnerabilities\n\n```dataview\n"
                    f'TABLE cvss_v3_score as CVSS FROM "{NVD_REL}" '
                    'WHERE severity = "Critical" SORT cvss_v3_score DESC\n```'
                ),
            },
            {
                "id": "high",
                "x": 600,
                "y": 0,
                "width": 400,
                "height": 400,
                "type": "text",
                "text": (
                    "# High Severity\n\n```dataview\n"
                    f'TABLE cvss_v3_score as CVSS FROM "{NVD_REL}" '
                    'WHERE severity = "High" SORT cvss_v3_score DESC\n```'
                ),
            },
        ],
        "edges": [
            {"id": "e1", "fromNode": "dashboard", "fromSide": "left", "toNode": "critical", "toSide": "right"},
            {"id": "e2", "fromNode": "dashboard", "fromSide": "right", "toNode": "high", "toSide": "left"},
        ],
    }

    with open(os.path.join(canvas_folder, "Vulnerability_Intel.canvas"), "w", encoding="utf-8") as f:
        json.dump(canvas_data, f, indent=2)


def create_date_range_folder(base_folder, start, end):
    """Create the dated collection folder and its _README note."""
    folder_name = f"{start.strftime('%Y-%m-%d')}_to_{end.strftime('%Y-%m-%d')}"
    folder_path = os.path.join(base_folder, folder_name)
    os.makedirs(folder_path, exist_ok=True)

    source = f"{NVD_REL}/{folder_name}"
    content = f"""---
type: nvd-collection
date_range: {folder_name}
start_date: {start.strftime('%Y-%m-%d')}
end_date: {end.strftime('%Y-%m-%d')}
tags: [nvd, collection]
---

# NVD Vulnerabilities: {folder_name}

## 📊 Collection Statistics

```dataview
TABLE
    length(rows) as "Total",
    length(filter(rows, (r) => r.severity = "Critical")) as "Critical",
    length(filter(rows, (r) => r.severity = "High")) as "High",
    length(filter(rows, (r) => r.severity = "Medium")) as "Medium",
    length(filter(rows, (r) => r.severity = "Low")) as "Low",
    length(filter(rows, (r) => r.severity = "Unscored")) as "Unscored"
FROM "{source}"
WHERE type = "vulnerability"
GROUP BY true
```

## 🔴 Critical Vulnerabilities

```dataview
TABLE
    cvss_v3_score as "CVSS",
    published as "Published"
FROM "{source}"
WHERE type = "vulnerability" AND severity = "Critical"
SORT cvss_v3_score DESC
```

## Collection Details
- **Start Date:** {start.strftime('%Y-%m-%d')}
- **End Date:** {end.strftime('%Y-%m-%d')}
- **Generated:** {end.strftime('%Y-%m-%d %H:%M:%S')}
"""
    write_file(os.path.join(folder_path, "_README.md"), content)
    return folder_path


def fetch_all_cves(api_key, start, end):
    """Fetch every CVE published in [start, end], following pagination."""
    headers = {"apiKey": api_key} if api_key else {}
    # NVD allows 50 requests / 30 s with a key, 5 requests / 30 s without.
    delay = 1 if api_key else 6

    fmt = "%Y-%m-%dT%H:%M:%S.000"
    params = {
        "pubStartDate": start.strftime(fmt),
        "pubEndDate": end.strftime(fmt),
        "resultsPerPage": RESULTS_PER_PAGE,
        "startIndex": 0,
    }

    vulns = []
    while True:
        response = requests.get(NVD_URL, headers=headers, params=params, timeout=60)
        if response.status_code != 200:
            raise RuntimeError(f"NVD API error {response.status_code}: {response.text[:200]}")

        data = response.json()
        page = data.get("vulnerabilities", [])
        vulns.extend(page)

        total = data.get("totalResults", len(vulns))
        print(f"📥 Fetched {len(vulns)} / {total}")

        params["startIndex"] += len(page)
        if not page or params["startIndex"] >= total:
            break
        time.sleep(delay)

    return vulns


def build_note(cve_data, cvss, severity, added):
    """Render the Markdown note for a single CVE."""
    cve_id = cve_data["id"]
    references = "\n".join(f"- {ref['url']}" for ref in cve_data.get("references", []))

    return f"""---
id: {cve_id}
type: vulnerability
severity: {severity}
cvss_v3_score: {cvss['v3_score']}
cvss_v3_vector: {cvss['v3_vector']}
published: {cve_data.get("published", "N/A")}
lastModified: {cve_data.get("lastModified", "N/A")}
status: needs-triage
tags: [nvd, vulnerability, severity/{severity.lower()}]
---

# {cve_id} - {severity} Severity

## Overview
**CVSS Score:** {cvss['v3_score']}
**Severity:** {severity}

## Description
{english_description(cve_data)}

## CVSS Details
- **Vector:** {cvss['v3_vector']}
- **Attack Vector:** {cvss['v3_attack_vector']}
- **Attack Complexity:** {cvss['v3_attack_complexity']}
- **Privileges Required:** {cvss['v3_privileges_required']}
- **User Interaction:** {cvss['v3_user_interaction']}
- **Scope:** {cvss['v3_scope']}
- **Confidentiality / Integrity / Availability:** {cvss['v3_confidentiality']} / {cvss['v3_integrity']} / {cvss['v3_availability']}
- **CVSS v2 Score:** {cvss['v2_score']}

## References
{references}

## Timeline
- **Published:** {cve_data.get("published", "N/A")}
- **Last Modified:** {cve_data.get("lastModified", "N/A")}
- **Added to Database:** {added.strftime('%Y-%m-%d %H:%M:%S')}

## Action Items
- [ ] Initial Assessment
- [ ] Impact Analysis
- [ ] Patch Availability Check
- [ ] Risk Assessment
"""


def run():
    vault, api_key, days_back = load_config()

    base_folder = os.path.join(vault, *NVD_REL.split("/"))
    os.makedirs(base_folder, exist_ok=True)

    # NVD timestamps are UTC, so query in UTC.
    end = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    start = end - datetime.timedelta(days=days_back)

    print("🔄 Starting NVD vulnerability collection...")
    create_dashboard(base_folder)
    create_canvas(vault)
    folder_path = create_date_range_folder(base_folder, start, end)
    print(f"📁 Collection folder: {os.path.basename(folder_path)}")

    vulns = fetch_all_cves(api_key, start, end)
    print(f"📊 Retrieved {len(vulns)} vulnerabilities")

    severity_folders = {}
    for severity in SEVERITIES:
        severity_folders[severity] = os.path.join(folder_path, severity)
        os.makedirs(severity_folders[severity], exist_ok=True)

    counts = {s: 0 for s in SEVERITIES}
    for vuln in vulns:
        cve_id = "unknown"
        try:
            cve_data = vuln["cve"]
            cve_id = cve_data["id"]
            cvss = get_cvss_info(cve_data.get("metrics", {}))
            severity = get_severity(cvss["v3_score"])

            note = build_note(cve_data, cvss, severity, end)
            write_file(os.path.join(severity_folders[severity], f"{cve_id}.md"), note)

            counts[severity] += 1
            print(f"{SEVERITY_ICONS[severity]} Created note for {cve_id} ({severity})")
        except Exception as e:  # keep going if one CVE is malformed
            print(f"❌ Error processing {cve_id}: {e}")

    summary = ", ".join(f"{s}: {n}" for s, n in counts.items())
    print(f"✅ Done. {summary}")


def main():
    try:
        run()
    except requests.RequestException as e:
        sys.exit(f"❌ Network error: {e}")
    except RuntimeError as e:
        sys.exit(f"❌ {e}")


if __name__ == "__main__":
    main()
