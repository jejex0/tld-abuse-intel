#!/usr/bin/env python3
"""Validate pipeline outputs and model invariants.

Run after `analyze.py`, `charts.py`, and `report.py`.  Exits non-zero on the
first category of failure, listing every problem found.
"""

from __future__ import annotations

import csv
import json
import sys
from collections import Counter
from pathlib import Path

from common import (
    CURATED_DIR,
    FIGURES_DIR,
    PROCESSED_DIR,
    REPORT_DIR,
    analyze_hosts,
    load_psl,
    normalize_host,
    read_json,
)

FIGURE_NAMES = [
    "fig01_top_volume_2026.png",
    "fig02_top_density_2026.png",
    "fig03_risk_matrix.png",
    "fig04_density_trends.png",
    "fig05_payload_history.png",
    "fig06_payload_platforms.png",
    "fig07_c2_tlds.png",
    "fig08_platform_abuse.png",
    "fig09_feed_overlap.png",
    "fig10_tier_confidence.png",
    "fig11_live_vs_tranco.png",
    "fig12_persistence.png",
]
RISK_COLUMNS = {
    "risk_rank", "tld", "category", "risk_tier", "risk_score", "confidence",
    "record_scope", "annual_phishing_score", "annual_phishing_domains",
    "live_phishing_domains", "payload_domains", "c2_domains",
    "blocklist_suitability", "recommended_action",
}
CURATED_COLUMNS = {
    "year", "period_start", "period_end", "tld", "domains_in_tld",
    "phishing_domains", "phishing_score", "malicious_registrations",
}
TIERS = {"Critical", "High", "Medium", "Low"}
CONFIDENCES = {"High", "Medium", "Low"}
REPORT_SECTIONS = [
    "## Executive summary",
    "## 1. Data collection and scope",
    "## 2. Methodology",
    "## 3. Current phishing landscape",
    "## 4. Historical persistence and evolution",
    "## 5. Payload delivery and staging",
    "## 6. C2 infrastructure",
    "## 7. Free hosting and dynamic DNS",
    "## 8. Risk-tier rankings",
    "## 9. Confidence analysis",
    "## 10. Detection and policy recommendations",
    "## 11. Limitations",
    "## 12. Reproducibility",
    "## Appendix A",
    "## Appendix B",
    "## Appendix C",
]
REQUIRED_OUTPUTS = [
    "tld_risk_scores.csv",
    "tld_risk_scores.json",
    "live_tld_counts.csv",
    "platform_risk.csv",
    "feed_overlap.csv",
    "historical_tld_summary.csv",
    "payload_history_summary.csv",
    "payload_platform_history_summary.csv",
    "c2_history_summary.csv",
    "legacy_watchlist.csv",
    "snapshot_manifest.json",
    "history_manifest.json",
    "tranco_tld_counts.csv",
]


def check_psl(errors: list[str]) -> None:
    psl = load_psl()
    checks = [
        (psl.platform_suffix("a.pages.dev"), "pages.dev", "pages.dev platform suffix"),
        (psl.root_tld("a.pages.dev"), "dev", "pages.dev root TLD"),
        (psl.registrable_domain("www.example.co.uk"), "example.co.uk", "co.uk registrable"),
        (psl.registrable_domain("x.y.example.com"), "example.com", "com registrable"),
        (normalize_host("https://User:pass@Example.COM:443/a?b=1"), "example.com", "URL normalization"),
        (normalize_host("||evil.example^"), "evil.example", "adblock normalization"),
        (normalize_host("0.0.0.0 bad.example"), "bad.example", "hosts-file normalization"),
        (normalize_host("1.2.3.4"), None, "IP rejection"),
        (normalize_host("localhost"), None, "single-label rejection"),
    ]
    for actual, expected, label in checks:
        if actual != expected:
            errors.append(f"PSL/normalization: {label}: expected {expected!r}, got {actual!r}")

    result = analyze_hosts({"a.pages.dev", "b.pages.dev", "www.example.com"}, psl)
    if result["platform_hosts_total"] != 2:
        errors.append(f"PSL/analysis: expected 2 platform hosts, got {result['platform_hosts_total']}")
    if result["tld_hosts"].get("com") != 1:
        errors.append(f"PSL/analysis: expected 1 .com host, got {result['tld_hosts']}")
    if result["tld_hosts"].get("dev"):
        errors.append("PSL/analysis: pages.dev hosts must not be counted under .dev")


def read_csv_rows(path: Path) -> list[dict]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def check_curated(errors: list[str]) -> None:
    path = CURATED_DIR / "phishing_tld_history.csv"
    if not path.exists():
        errors.append(f"missing curated data: {path}")
        return
    rows = read_csv_rows(path)
    if len(rows) < 100:
        errors.append(f"curated data has only {len(rows)} rows; expected at least 100")
    missing = CURATED_COLUMNS - set(rows[0]) if rows else CURATED_COLUMNS
    if missing:
        errors.append(f"curated data missing columns: {sorted(missing)}")
        return
    years = set()
    for row in rows:
        years.add(row["year"])
        if row["tld"] != row["tld"].lower() or not row["tld"]:
            errors.append(f"curated data: invalid TLD {row['tld']!r}")
        for field in ("phishing_domains", "domains_in_tld", "malicious_registrations"):
            value = row.get(field) or ""
            if value and not value.replace(",", "").isdigit():
                errors.append(f"curated data: non-numeric {field}={value!r} for {row['tld']} {row['year']}")
    expected_years = {str(year) for year in range(2020, 2027)}
    if years != expected_years:
        errors.append(f"curated data years: expected {sorted(expected_years)}, got {sorted(years)}")


def check_risk(errors: list[str]) -> tuple[list[dict], dict]:
    csv_path = PROCESSED_DIR / "tld_risk_scores.csv"
    json_path = REPORT_DIR / "analysis_data.json"
    if not csv_path.exists():
        errors.append(f"missing risk CSV: {csv_path}")
        return [], {}
    rows = read_csv_rows(csv_path)
    if not rows:
        errors.append("risk CSV is empty")
        return rows, {}
    missing = RISK_COLUMNS - set(rows[0])
    if missing:
        errors.append(f"risk CSV missing columns: {sorted(missing)}")
        return rows, {}

    tlds = [row["tld"] for row in rows]
    if len(tlds) != len(set(tlds)):
        errors.append("risk CSV contains duplicate TLDs")
    ranks = [int(row["risk_rank"]) for row in rows]
    if ranks != list(range(1, len(rows) + 1)):
        errors.append("risk ranks are not contiguous from 1")
    for row in rows:
        if row["risk_tier"] not in TIERS:
            errors.append(f"invalid tier {row['risk_tier']!r} for .{row['tld']}")
        if row["confidence"] not in CONFIDENCES:
            errors.append(f"invalid confidence {row['confidence']!r} for .{row['tld']}")
        score = float(row["risk_score"])
        if not 0.0 <= score <= 100.0:
            errors.append(f"risk score out of range for .{row['tld']}: {score}")
        if row["blocklist_suitability"] not in CONFIDENCES:
            errors.append(f"invalid blocklist suitability for .{row['tld']}: {row['blocklist_suitability']}")

    if not json_path.exists():
        errors.append(f"missing analysis JSON: {json_path}")
        return rows, {}
    analysis = read_json(json_path)
    if not isinstance(analysis, dict):
        errors.append("analysis JSON is not an object")
        return rows, {}

    csv_tiers = Counter(row["risk_tier"] for row in rows)
    csv_conf = Counter(row["confidence"] for row in rows)
    if dict(csv_tiers) != analysis.get("tier_counts"):
        errors.append(f"tier counts mismatch: CSV={dict(csv_tiers)} JSON={analysis.get('tier_counts')}")
    if dict(csv_conf) != analysis.get("confidence_counts"):
        errors.append(f"confidence counts mismatch: CSV={dict(csv_conf)} JSON={analysis.get('confidence_counts')}")
    if sum(csv_tiers.values()) != analysis.get("counts", {}).get("tlds_scored"):
        errors.append("scored TLD count does not match counts.tlds_scored")

    counts = analysis.get("counts", {})
    if counts.get("phishing_hosts", 0) <= 0:
        errors.append("counts.phishing_hosts must be positive")
    if not 0 < counts.get("phishing_nonplatform_hosts", 0) <= counts.get("phishing_hosts", 0):
        errors.append("counts.phishing_nonplatform_hosts must be between 1 and phishing_hosts")
    if not 0 < counts.get("phishing_registered_domains", 0) <= counts.get("phishing_nonplatform_hosts", 0):
        errors.append("counts.phishing_registered_domains must not exceed non-platform hosts")
    for kind in ("payload", "c2"):
        hosts = counts.get(f"{kind}_hosts", 0)
        nonplatform = counts.get(f"{kind}_nonplatform_hosts", 0)
        domains = counts.get(f"{kind}_registered_domains", 0)
        if not 0 < nonplatform <= hosts:
            errors.append(f"counts.{kind}_nonplatform_hosts invalid ({nonplatform} of {hosts})")
        if not 0 < domains <= nonplatform:
            errors.append(f"counts.{kind}_registered_domains invalid ({domains} of {nonplatform})")

    concentration = analysis.get("concentration", {})
    values = [
        concentration.get("top3_live_share_pct", 0),
        concentration.get("top5_live_share_pct", 0),
        concentration.get("top10_live_share_pct", 0),
    ]
    if not (0 <= values[0] <= values[1] <= values[2] <= 100):
        errors.append(f"concentration shares are not monotonic/in range: {values}")

    snapshot = analysis.get("snapshot_date")
    manifest_path = PROCESSED_DIR / "snapshot_manifest.json"
    if manifest_path.exists() and snapshot != read_json(manifest_path).get("snapshot_date"):
        errors.append("analysis snapshot date does not match snapshot manifest")

    if analysis.get("generated_at") and not analysis["generated_at"].endswith("+00:00"):
        errors.append("analysis generated_at is not UTC ISO-8601")
    return rows, analysis


def check_outputs(errors: list[str]) -> None:
    for name in REQUIRED_OUTPUTS:
        path = PROCESSED_DIR / name
        if not path.exists() or path.stat().st_size == 0:
            errors.append(f"missing or empty processed output: {path}")
    for name in FIGURE_NAMES:
        path = FIGURES_DIR / name
        if not path.exists() or path.stat().st_size < 1024:
            errors.append(f"missing or too-small figure: {path}")


def check_report(errors: list[str]) -> None:
    path = REPORT_DIR / "ANALYSIS.md"
    if not path.exists():
        errors.append(f"missing report: {path}")
        return
    text = path.read_text(encoding="utf-8")
    if len(text.splitlines()) < 800:
        errors.append("report is unexpectedly short")
    for section in REPORT_SECTIONS:
        if section not in text:
            errors.append(f"report missing section: {section}")
    if "{\n" in text or "{chr(" in text or "None" in text:
        errors.append("report appears to contain unrendered template output")


def main() -> int:
    errors: list[str] = []
    check_psl(errors)
    check_curated(errors)
    check_risk(errors)
    check_outputs(errors)
    check_report(errors)

    if errors:
        print(f"validation failed with {len(errors)} issue(s):")
        for issue in errors:
            print(f"  - {issue}")
        return 1
    print("validation passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
