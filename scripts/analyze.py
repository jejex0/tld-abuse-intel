#!/usr/bin/env python3
"""Analyze current and historical TLD abuse data and produce risk rankings.

The risk model combines registry-scale annual data (Interisle / Cybercrime
Information Center) with live feed evidence, historical persistence, payload
delivery, C2 observation, and a Tranco popularity baseline.  See
docs/METHODOLOGY.md for the full rationale.
"""

from __future__ import annotations

import argparse
import csv
import itertools
import math
import statistics
from collections import Counter, defaultdict
from pathlib import Path

from common import (
    CURATED_DIR,
    PROCESSED_DIR,
    RAW_DIR,
    REPORT_DIR,
    ROOT,
    analyze_hosts,
    clamp,
    latest_snapshot_dir,
    load_psl,
    log_norm,
    read_hosts,
    read_json,
    utc_now_iso,
    write_csv,
    write_json,
)

WEIGHTS = {
    "density": 35.0,
    "volume": 15.0,
    "persistence": 15.0,
    "malreg": 15.0,
    "payload": 10.0,
    "c2": 5.0,
    "momentum": 5.0,
}
TIER_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
CONF_ORDER = {"High": 0, "Medium": 1, "Low": 2}
HIGH_COLLATERAL_TLDS = {
    "com", "net", "org", "info", "xyz", "cn", "ru", "de", "uk", "jp", "br", "in",
    "io", "co", "me", "app", "dev", "eu", "fr", "nl", "au", "ca", "pl", "it", "es",
}
MALREG_IMPUTED_SHARE = 0.74  # Interisle 2026 overall attacker-registered average
FREENOM_TLDS = {"tk", "ml", "ga", "cf", "gq"}
LEGACY_GTLDS = {"com", "net", "org", "info", "biz", "pro", "name", "int", "edu", "gov", "mil", "aero", "asia", "cat", "coop", "jobs", "mobi", "museum", "post", "tel", "travel", "xxx", "arpa"}


def to_int(value):
    if value is None or value == "":
        return None
    try:
        return int(str(value).replace(",", "").strip())
    except ValueError:
        return None


def to_float(value):
    if value is None or value == "":
        return None
    try:
        return float(str(value).replace(",", "").strip())
    except ValueError:
        return None


def safe_div(numerator, denominator):
    if numerator is None or denominator in (None, 0):
        return None
    return numerator / denominator


def pct_change(current, previous):
    if current is None or previous in (None, 0):
        return None
    return (current - previous) / previous * 100.0


def bump(tier: str, steps: int = 1) -> str:
    order = ["Low", "Medium", "High", "Critical"]
    return order[min(len(order) - 1, order.index(tier) + steps)]


def drop(tier: str, steps: int = 1) -> str:
    order = ["Low", "Medium", "High", "Critical"]
    return order[max(0, order.index(tier) - steps)]


def load_curated(path: Path) -> dict[str, dict[int, dict]]:
    by_tld: dict[str, dict[int, dict]] = defaultdict(dict)
    with path.open("r", encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            year = int(row["year"])
            by_tld[row["tld"]][year] = {
                "year": year,
                "period_start": row["period_start"],
                "period_end": row["period_end"],
                "rank_count": to_int(row["rank_count"]),
                "domains_in_tld": to_int(row["domains_in_tld"]),
                "phishing_domains": to_int(row["phishing_domains"]),
                "rank_score": to_int(row["rank_score"]),
                "phishing_score": to_float(row["phishing_score"]),
                "rank_malreg": to_int(row["rank_malreg"]),
                "malicious_registrations": to_int(row["malicious_registrations"]),
                "malicious_score": to_float(row["malicious_score"]),
                "source": row["source"],
                "notes": row["notes"],
            }
    return by_tld


def summarize_history(by_tld: dict[str, dict[int, dict]]) -> dict[str, dict]:
    summary = {}
    for tld, years in by_tld.items():
        years_sorted = sorted(years)
        present = len(years_sorted)
        top_count = sum(1 for y in years_sorted if (years[y]["rank_count"] or 999) <= 10)
        top_score = sum(1 for y in years_sorted if (years[y]["rank_score"] or 999) <= 10)
        top_any = sum(
            1
            for y in years_sorted
            if (years[y]["rank_count"] or 999) <= 10 or (years[y]["rank_score"] or 999) <= 10
        )
        scored = [(years[y]["phishing_score"], y) for y in years_sorted if years[y]["phishing_score"] is not None]
        peak_score, peak_year = max(scored) if scored else (None, None)
        annual_year = max((y for y in (2026, 2025, 2024) if y in years), default=None)
        annual = years.get(annual_year, {}) if annual_year else {}
        previous_years = [y for y in years_sorted if annual_year and y < annual_year]
        prev_year = max(previous_years) if previous_years else None
        prev = years.get(prev_year, {}) if prev_year else {}
        malreg_share = safe_div(annual.get("malicious_registrations"), annual.get("phishing_domains"))
        summary[tld] = {
            "first_year": min(years_sorted),
            "last_year": max(years_sorted),
            "years_present": present,
            "years_top10_count": top_count,
            "years_top10_score": top_score,
            "years_top10_any": top_any,
            "peak_score": peak_score,
            "peak_score_year": peak_year,
            "annual_year": annual_year,
            "annual_rank_count": annual.get("rank_count"),
            "annual_domains_in_tld": annual.get("domains_in_tld"),
            "annual_phishing_domains": annual.get("phishing_domains"),
            "annual_rank_score": annual.get("rank_score"),
            "annual_score": annual.get("phishing_score"),
            "annual_rank_malreg": annual.get("rank_malreg"),
            "annual_malicious_registrations": annual.get("malicious_registrations"),
            "annual_malicious_score": annual.get("malicious_score"),
            "annual_malreg_share": malreg_share,
            "prev_year": prev_year,
            "prev_phishing_domains": prev.get("phishing_domains"),
            "prev_phishing_score": prev.get("phishing_score"),
            "growth_domains_pct": pct_change(annual.get("phishing_domains"), prev.get("phishing_domains")),
            "growth_score_pct": pct_change(annual.get("phishing_score"), prev.get("phishing_score")),
            "years": years,
        }
    return summary


def load_csv_rows(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def load_current_snapshot(snapshot_dir: Path, psl) -> dict:
    manifest = read_json(snapshot_dir / "manifest.json")
    feed_hosts: dict[str, set[str]] = {}
    feed_stats: dict[str, dict] = {}
    for entry in manifest.get("sources", []):
        if entry.get("error"):
            continue
        path = ROOT / entry["path"] if (ROOT / entry["path"]).exists() else snapshot_dir / Path(entry["path"]).name
        if not path.exists():
            continue
        hosts = read_hosts(path, csv_first=entry.get("format") == "csv_domain")
        feed_hosts[entry["name"]] = hosts
        feed_stats[entry["name"]] = analyze_hosts(hosts, psl)

    kind_hosts: dict[str, set[str]] = defaultdict(set)
    kind_stats: dict[str, dict] = {}
    for entry in manifest.get("sources", []):
        name, kind = entry["name"], entry["kind"]
        if name not in feed_hosts:
            continue
        kind_hosts[kind] |= feed_hosts[name]
    for kind, hosts in kind_hosts.items():
        kind_stats[kind] = analyze_hosts(hosts, psl)

    phishing_feeds = [e["name"] for e in manifest.get("sources", []) if e.get("kind") == "phishing" and e["name"] in feed_hosts]
    live_feeds_for_tld: Counter[str] = Counter()
    for name in phishing_feeds:
        for tld, count in feed_stats[name]["tld_domains"].items():
            if count > 0:
                live_feeds_for_tld[tld] += 1

    overlap_rows = []
    for a, b in itertools.combinations(phishing_feeds, 2):
        set_a, set_b = feed_hosts[a], feed_hosts[b]
        union = len(set_a | set_b)
        inter = len(set_a & set_b)
        overlap_rows.append(
            {
                "feed_a": a,
                "feed_b": b,
                "hosts_a": len(set_a),
                "hosts_b": len(set_b),
                "intersection": inter,
                "jaccard_pct": round(100 * inter / union, 2) if union else 0.0,
                "containment_pct": round(100 * inter / min(len(set_a), len(set_b)), 2) if set_a and set_b else 0.0,
            }
        )

    return {
        "manifest": manifest,
        "snapshot_date": manifest.get("snapshot_date", snapshot_dir.name),
        "feed_hosts": feed_hosts,
        "feed_stats": feed_stats,
        "phishing_feeds": phishing_feeds,
        "phishing_stats": kind_stats.get("phishing", analyze_hosts(set(), psl)),
        "payload_stats": kind_stats.get("payload", analyze_hosts(set(), psl)),
        "c2_stats": kind_stats.get("c2", analyze_hosts(set(), psl)),
        "has_payload": any(e.get("kind") == "payload" and not e.get("error") for e in manifest.get("sources", [])),
        "has_c2": any(e.get("kind") == "c2" and not e.get("error") for e in manifest.get("sources", [])),
        "live_feeds_for_tld": live_feeds_for_tld,
        "overlap_rows": overlap_rows,
    }


def build_platform_rows(current: dict, psl) -> list[dict]:
    p = current["phishing_stats"]
    payload = current["payload_stats"]
    c2 = current["c2_stats"]
    total_live_hosts = p["total_hosts"]
    platforms = set(p["platform_hosts"]) | set(payload["platform_hosts"]) | set(c2["platform_hosts"])
    rows = []
    for platform in platforms:
        ph_hosts = p["platform_hosts"].get(platform, 0)
        rows.append(
            {
                "platform_suffix": platform,
                "root_tld": psl.root_tld(platform),
                "live_phishing_hosts": ph_hosts,
                "live_phishing_registrable": p["platform_domains"].get(platform, 0),
                "payload_hosts": payload["platform_hosts"].get(platform, 0),
                "c2_hosts": c2["platform_hosts"].get(platform, 0),
                "share_of_live_phishing_hosts_pct": round(100 * ph_hosts / total_live_hosts, 3) if total_live_hosts else 0.0,
                "note": "Free hosting / dynamic DNS / serverless namespace; control at subdomain level",
            }
        )
    rows.sort(key=lambda r: (r["live_phishing_hosts"], r["payload_hosts"], r["c2_hosts"]), reverse=True)
    return rows


def load_tranco(path: Path) -> tuple[dict[str, int], float, int]:
    rows = load_csv_rows(path)
    counts = {r["tld"]: int(r["domains"]) for r in rows if r.get("domains", "").isdigit()}
    total = int(round(sum(counts.values()))) if counts else 0
    return counts, (1.0 / total if total else 0.0), total


def build_tld_records(current, history, tranco, tranco_floor, tranco_total, payload_history, c2_history) -> list[dict]:
    p = current["phishing_stats"]
    payload = current["payload_stats"]
    c2 = current["c2_stats"]
    live_feeds = current["live_feeds_for_tld"]

    live_phishing = p["tld_domains"]
    live_phishing_hosts = p["tld_hosts"]
    payload_domains = payload["tld_domains"]
    payload_hosts = payload["tld_hosts"]
    c2_domains = c2["tld_domains"]
    c2_hosts = c2["tld_hosts"]

    total_phishing = sum(live_phishing.values())
    total_payload = sum(payload_domains.values())
    total_c2 = sum(c2_domains.values())

    platform_hosts_by_root: Counter[str] = Counter()
    platform_domains_by_root: Counter[str] = Counter()
    for platform, count in p["platform_hosts"].items():
        platform_hosts_by_root[psl_root(platform)] += count
    for platform, count in p["platform_domains"].items():
        platform_domains_by_root[psl_root(platform)] += count

    # TLD universe: annual data, material live evidence, and persistent TLDs.
    top_live = {t for t, n in sorted(live_phishing.items(), key=lambda kv: kv[1], reverse=True)[:40] if n >= 200}
    top_payload = {t for t, n in sorted(payload_domains.items(), key=lambda kv: kv[1], reverse=True)[:25] if n >= 10}
    top_c2 = {t for t, n in sorted(c2_domains.items(), key=lambda kv: kv[1], reverse=True)[:15] if n >= 2}
    annual_tlds = {
        t for t, h in history.items() if h["annual_year"] in (2024, 2025, 2026)
    }
    persistent = {
        t for t, h in history.items()
        if h["years_top10_any"] >= 3 and live_phishing.get(t, 0) >= 200
    }
    tlds = annual_tlds | top_live | top_payload | top_c2 | persistent

    max_annual_volume = max(
        (h["annual_phishing_domains"] for h in history.values() if h["annual_phishing_domains"]),
        default=1,
    )
    max_live_volume = max(live_phishing.values(), default=1)
    max_payload = max(payload_domains.values(), default=1)
    max_c2 = max(c2_domains.values(), default=1)
    max_score = max((h["annual_score"] for h in history.values() if h["annual_score"]), default=1)

    records = []
    for tld in sorted(tlds):
        hist = history.get(tld, {})
        annual_year = hist.get("annual_year")
        annual_score = hist.get("annual_score")
        annual_domains = hist.get("annual_phishing_domains")
        annual_malreg = hist.get("annual_malicious_registrations")
        malreg_share = hist.get("annual_malreg_share")
        malreg_imputed = False
        if annual_score is not None and malreg_share is None:
            malreg_share = MALREG_IMPUTED_SHARE
            malreg_imputed = True

        live_domains = live_phishing.get(tld, 0)
        live_hosts = live_phishing_hosts.get(tld, 0)
        payload_count = payload_domains.get(tld, 0)
        c2_count = c2_domains.get(tld, 0)
        tranco_count = tranco.get(tld, 0)
        tranco_share = tranco_count / tranco_total if tranco_total else 0.0
        live_share = live_domains / total_phishing if total_phishing else 0.0
        payload_share = payload_count / total_payload if total_payload else 0.0
        c2_share = c2_count / total_c2 if total_c2 else 0.0
        live_overrep = live_share / max(tranco_share, tranco_floor) if live_share else None
        payload_overrep = payload_share / max(tranco_share, tranco_floor) if payload_share else None
        c2_overrep = c2_share / max(tranco_share, tranco_floor) if c2_share else None

        platform_hosts_tld = platform_hosts_by_root.get(tld, 0)
        platform_domains_tld = platform_domains_by_root.get(tld, 0)
        platform_share = platform_hosts_tld / (live_hosts + platform_hosts_tld) if (live_hosts + platform_hosts_tld) else 0.0

        if annual_year == 2026 and live_domains:
            scope = "annual+live"
        elif annual_year == 2026:
            scope = "annual"
        elif annual_year in (2024, 2025) and live_domains:
            scope = "annual-fallback+live"
        elif annual_year in (2024, 2025):
            scope = "annual-fallback"
        elif live_domains:
            scope = "live-only"
        else:
            scope = "historical-only"

        volume_base = annual_domains or live_domains
        density_value = annual_score
        if density_value is not None:
            if density_value >= 1000:
                intensity = "extreme"
            elif density_value >= 400:
                intensity = "high"
            elif density_value >= 100:
                intensity = "elevated"
            else:
                intensity = "low"
        elif live_overrep is not None:
            if live_overrep >= 50:
                intensity = "high"
            elif live_overrep >= 10:
                intensity = "elevated"
            else:
                intensity = "low"
        else:
            intensity = "low"

        # Annual registration data and a point-in-time live snapshot have
        # different scales; live-only namespaces use lower thresholds.
        if annual_domains:
            large_cut, medium_cut = 50000, 10000
        else:
            large_cut, medium_cut = 10000, 2000
        if volume_base >= large_cut:
            scale = "large"
        elif volume_base >= medium_cut:
            scale = "medium"
        else:
            scale = "small"

        density_norm = 0.0
        if annual_score is not None:
            density_norm = clamp((math.log10(max(annual_score, 1)) - math.log10(5)) / (math.log10(6000) - math.log10(5)))
        elif live_overrep is not None:
            density_norm = log_norm(live_overrep, 500)
        volume_norm = log_norm(volume_base, max_annual_volume if annual_domains else max_live_volume)
        persistence_norm = clamp(hist.get("years_top10_any", 0) / 7)
        malreg_norm = clamp(malreg_share or 0.0)
        payload_norm = log_norm(payload_count, max_payload)
        c2_norm = log_norm(c2_count, max_c2)
        growth = max(hist.get("growth_domains_pct") or 0.0, hist.get("growth_score_pct") or 0.0)
        momentum_norm = clamp(growth / 300.0)

        components = {
            "density": density_norm,
            "volume": volume_norm,
            "persistence": persistence_norm,
            "malreg": malreg_norm,
            "payload": payload_norm,
            "c2": c2_norm,
            "momentum": momentum_norm,
        }
        risk_score = sum(WEIGHTS[k] * components[k] for k in WEIGHTS)

        # Density-led absolute tiering.  Critical is deliberately narrow:
        # extreme density + material volume, or high density + large volume, or
        # near-total attacker registration at scale.  Composite score controls
        # ordering inside a tier, not entry into Critical.
        critical = False
        if annual_score is not None:
            if annual_score >= 1000 and volume_base >= 10000:
                critical = True
            elif annual_score >= 500 and volume_base >= 50000:
                critical = True
            elif annual_score >= 400 and volume_base >= 20000 and (malreg_share or 0) >= 0.95:
                critical = True
        if critical:
            tier = "Critical"
        elif (
            (annual_score is not None and annual_score >= 400)
            or (annual_score is not None and annual_score >= 200 and volume_base >= 10000)
            or (annual_score is not None and annual_score >= 100 and volume_base >= 50000)
            or (annual_score is not None and annual_score >= 140 and volume_base >= 30000)
            or risk_score >= 52
            or (annual_score is None and live_overrep is not None and live_overrep >= 20 and live_domains >= 1000)
        ):
            tier = "High"
        elif (
            (annual_score is not None and annual_score >= 100)
            or (annual_score is not None and annual_score >= 50 and volume_base >= 10000)
            or volume_base >= 50000
            or scale == "medium"
            or risk_score >= 32
            or (live_domains >= 500 and live_overrep is not None and live_overrep >= 5)
        ):
            tier = "Medium"
        else:
            tier = "Low"
        tier_base = tier
        modifiers = []

        if malreg_share is not None and malreg_share >= 0.90 and volume_base >= 10000 and tier in ("Low", "Medium"):
            tier = bump(tier)
            modifiers.append("attacker-registered share >=90%")
        if hist.get("years_top10_any", 0) >= 5 and tier in ("Low", "Medium"):
            tier = bump(tier)
            modifiers.append("persistent top-10 presence")
        if (payload_count + c2_count) >= 20 and max(payload_overrep or 0, c2_overrep or 0) >= 5 and tier in ("Low", "Medium"):
            tier = bump(tier)
            modifiers.append("strong payload/C2 signal")
        if volume_base < 1000 and tier == "Critical":
            tier = "High"
            modifiers.append("small current volume cap")
        if scope == "live-only":
            if tier == "Critical":
                tier = "High"
                modifiers.append("live-only evidence cap")
            if platform_share > 0.5:
                tier = drop(tier)
                modifiers.append("mostly free-platform subdomains")
            if live_domains < 1000 and tier in ("Critical", "High"):
                tier = "Medium"
                modifiers.append("low live-only sample cap")
        if scope == "historical-only":
            if TIER_ORDER[tier] < TIER_ORDER["Medium"]:
                tier = "Medium"
            modifiers.append("historical-only cap")

        present_weights = 0.0
        if annual_score is not None or live_overrep is not None:
            present_weights += WEIGHTS["density"]
        if volume_base:
            present_weights += WEIGHTS["volume"]
        if hist.get("years_present"):
            present_weights += WEIGHTS["persistence"]
        if malreg_share is not None:
            present_weights += WEIGHTS["malreg"]
        if current.get("has_payload"):
            present_weights += WEIGHTS["payload"]
        if current.get("has_c2"):
            present_weights += WEIGHTS["c2"]
        if hist.get("growth_domains_pct") is not None or hist.get("growth_score_pct") is not None:
            present_weights += WEIGHTS["momentum"]
        coverage = present_weights / 100.0

        evidence = []
        if annual_year == 2026:
            evidence.append("Interisle 2026")
        elif annual_year in (2024, 2025):
            evidence.append(f"Interisle {annual_year}")
        if hist.get("years_present", 0) >= 2:
            evidence.append(f"historical ranking ({hist['years_present']} years)")
        if live_domains:
            evidence.append(f"{live_feeds.get(tld, 0)} live phishing feeds")
        if payload_count:
            evidence.append("URLhaus payload")
        if c2_count:
            evidence.append("C2Intel")
        if tranco_count:
            evidence.append("Tranco baseline")

        if (
            annual_year == 2026
            and (live_domains >= 100 or payload_count + c2_count >= 5)
            and malreg_share is not None
            and not malreg_imputed
            and coverage >= 0.75
        ):
            confidence = "High"
        elif (
            annual_year == 2026
            or (live_domains >= 1000 and live_feeds.get(tld, 0) >= 2)
            or (hist.get("years_present", 0) >= 2 and live_domains >= 100)
            or (annual_year in (2024, 2025) and live_domains >= 500)
        ):
            confidence = "Medium"
        else:
            confidence = "Low"
        conf_flags = []
        if malreg_imputed:
            conf_flags.append("malicious-registration share imputed at 74%")
        if scope == "historical-only":
            confidence = "Low"
            conf_flags.append("historical-only evidence")
        if scope == "live-only" and live_domains < 1000:
            confidence = "Low"
            conf_flags.append("small live-only sample")
        if scope == "live-only" and platform_share > 0.6:
            confidence = "Low"
            conf_flags.append("live signal dominated by free-hosting platforms")
        confidence_reason = "; ".join(evidence + conf_flags) if evidence or conf_flags else "no current evidence"

        if tranco_share <= 0.002 and platform_share < 0.5:
            suitability = "High"
        elif tranco_share <= 0.01:
            suitability = "Medium"
        else:
            suitability = "Low"

        if tier in ("Critical", "High"):
            if tranco_share >= 0.01 or tld in HIGH_COLLATERAL_TLDS:
                action = "Do not block the TLD wholesale (high collateral). Monitor domain-level abuse and escalate to registrar/registry."
            elif suitability == "High":
                action = "TLD-level blocklist candidate for high-risk or constrained environments; validate business need."
            elif suitability == "Medium":
                action = "Consider TLD blocking only for constrained environments; prefer domain-level detection."
            else:
                action = "Prioritize domain-level detection and registrar/registry escalation."
        else:
            action = "Monitor; block at domain level if observed."
        if platform_share > 0.5:
            action += " Live abuse is mostly on free-hosting subdomains; target the platform namespace."
        if tld in FREENOM_TLDS:
            action = "Legacy Freenom namespace with new registrations suspended; block legacy domains and monitor takedowns."

        notes = []
        if tld in FREENOM_TLDS:
            notes.append("Freenom-era namespace; registration freeze since 2023 means live abuse is legacy infrastructure")
        if annual_year in (2024, 2025):
            notes.append(f"2026 annual data unavailable; using {annual_year}")
        if annual_score is None and live_domains:
            notes.append("no annual registry denominator; density proxied from live over-representation")
        if malreg_imputed:
            notes.append("not in 2026 top-20 malicious-registration table")
        if platform_share > 0.5:
            notes.append(f"{platform_share:.1%} of live hosts under this TLD are on private platforms")
        if modifiers:
            notes.append("tier modifiers: " + ", ".join(modifiers))

        records.append(
            {
                "tld": tld,
                "category": classify_tld(tld),
                "risk_tier": tier,
                "risk_score": round(risk_score, 1),
                "confidence": confidence,
                "record_scope": scope,
                "annual_year": annual_year,
                "annual_domains_in_tld": hist.get("annual_domains_in_tld"),
                "annual_phishing_domains": annual_domains,
                "annual_phishing_score": annual_score,
                "annual_malicious_registrations": annual_malreg,
                "annual_malreg_share": round(malreg_share, 4) if malreg_share is not None else None,
                "malreg_imputed": malreg_imputed,
                "prev_year": hist.get("prev_year"),
                "prev_phishing_domains": hist.get("prev_phishing_domains"),
                "prev_phishing_score": hist.get("prev_phishing_score"),
                "growth_domains_pct": round(hist["growth_domains_pct"], 1) if hist.get("growth_domains_pct") is not None else None,
                "growth_score_pct": round(hist["growth_score_pct"], 1) if hist.get("growth_score_pct") is not None else None,
                "years_present": hist.get("years_present", 0),
                "years_top10_count": hist.get("years_top10_count", 0),
                "years_top10_score": hist.get("years_top10_score", 0),
                "years_top10_any": hist.get("years_top10_any", 0),
                "first_year": hist.get("first_year"),
                "last_year": hist.get("last_year"),
                "peak_score": hist.get("peak_score"),
                "peak_score_year": hist.get("peak_score_year"),
                "live_phishing_domains": live_domains,
                "live_phishing_hosts": live_hosts,
                "live_phishing_share": round(live_share, 6),
                "live_feeds": live_feeds.get(tld, 0),
                "live_overrep": round(live_overrep, 2) if live_overrep is not None else None,
                "payload_domains": payload_count,
                "payload_hosts": payload_hosts.get(tld, 0),
                "payload_share": round(payload_share, 6),
                "payload_overrep": round(payload_overrep, 2) if payload_overrep is not None else None,
                "c2_domains": c2_count,
                "c2_hosts": c2_hosts.get(tld, 0),
                "c2_share": round(c2_share, 6),
                "c2_overrep": round(c2_overrep, 2) if c2_overrep is not None else None,
                "tranco_domains": tranco_count,
                "tranco_share": round(tranco_share, 6),
                "platform_hosts_under_tld": platform_hosts_tld,
                "platform_domains_under_tld": platform_domains_tld,
                "platform_share_of_live": round(platform_share, 4),
                "density_norm": round(density_norm, 4),
                "volume_norm": round(volume_norm, 4),
                "persistence_norm": round(persistence_norm, 4),
                "malreg_norm": round(malreg_norm, 4),
                "payload_norm": round(payload_norm, 4),
                "c2_norm": round(c2_norm, 4),
                "momentum_norm": round(momentum_norm, 4),
                "coverage": round(coverage, 4),
                "intensity_category": intensity,
                "scale_category": scale,
                "tier_base": tier_base,
                "modifiers": ", ".join(modifiers),
                "blocklist_suitability": suitability,
                "recommended_action": action,
                "confidence_reason": confidence_reason,
                "evidence_sources": "; ".join(evidence),
                "notes": "; ".join(notes),
                "max_annual_volume": max_annual_volume,
                "max_live_volume": max_live_volume,
                "max_payload": max_payload,
                "max_c2": max_c2,
                "max_score": max_score,
            }
        )

    records.sort(key=lambda r: (TIER_ORDER[r["risk_tier"]], -r["risk_score"], -(r["annual_phishing_score"] or 0), -r["live_phishing_domains"]))
    for rank, record in enumerate(records, 1):
        record["risk_rank"] = rank
    return records


def psl_root(platform: str) -> str:
    # Platform suffixes are passed through the same PSL; the last label is the
    # real TLD for every platform we track (e.g. pages.dev -> dev).
    return platform.rsplit(".", 1)[-1]


def summarize_payload_history(rows: list[dict]) -> list[dict]:
    by_tld: dict[str, list[tuple[str, int]]] = defaultdict(list)
    for row in rows:
        try:
            by_tld[row["tld"]].append((row["snapshot_date"], int(row["registered_domains"])))
        except (KeyError, ValueError):
            continue
    out = []
    for tld, series in by_tld.items():
        series.sort()
        values = [v for _, v in series]
        peak_date, peak = max(series, key=lambda x: x[1])
        out.append(
            {
                "tld": tld,
                "snapshots_present": len(series),
                "first_date": series[0][0],
                "last_date": series[-1][0],
                "max_domains": peak,
                "peak_date": peak_date,
                "total_domains": sum(values),
                "avg_domains": round(statistics.mean(values), 1),
                "latest_domains": series[-1][1],
                "latest_date": series[-1][0],
            }
        )
    out.sort(key=lambda r: r["total_domains"], reverse=True)
    return out


def summarize_platform_history(rows: list[dict]) -> list[dict]:
    by_platform: dict[str, list[tuple[str, int]]] = defaultdict(list)
    for row in rows:
        try:
            by_platform[row["platform_suffix"]].append((row["snapshot_date"], int(row["hosts"])))
        except (KeyError, ValueError):
            continue
    out = []
    for platform, series in by_platform.items():
        series.sort()
        peak_date, peak = max(series, key=lambda x: x[1])
        out.append(
            {
                "platform_suffix": platform,
                "snapshots_present": len(series),
                "first_date": series[0][0],
                "last_date": series[-1][0],
                "max_hosts": peak,
                "peak_date": peak_date,
                "total_hosts": sum(v for _, v in series),
                "latest_hosts": series[-1][1],
            }
        )
    out.sort(key=lambda r: r["total_hosts"], reverse=True)
    return out


def summarize_c2_history(rows: list[dict]) -> list[dict]:
    by_tld: dict[str, list[tuple[str, int]]] = defaultdict(list)
    for row in rows:
        try:
            by_tld[row["tld"]].append((row["snapshot_date"], int(row["registered_domains"])))
        except (KeyError, ValueError):
            continue
    out = []
    for tld, series in by_tld.items():
        series.sort()
        out.append(
            {
                "tld": tld,
                "snapshots_present": len(series),
                "first_date": series[0][0],
                "last_date": series[-1][0],
                "max_domains": max(v for _, v in series),
                "latest_domains": series[-1][1],
                "total_domains": sum(v for _, v in series),
            }
        )
    out.sort(key=lambda r: r["total_domains"], reverse=True)
    return out


def classify_tld(tld: str) -> str:
    if len(tld) == 2:
        return "ccTLD"
    if tld in LEGACY_GTLDS:
        return "legacy gTLD"
    return "new gTLD"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--snapshot", help="snapshot date under data/raw (default: latest)")
    args = parser.parse_args()

    psl = load_psl()
    snapshot_dir = RAW_DIR / args.snapshot if args.snapshot else latest_snapshot_dir()
    if not snapshot_dir or not (snapshot_dir / "manifest.json").exists():
        raise SystemExit("No snapshot found. Run scripts/collect.py first.")

    current = load_current_snapshot(snapshot_dir, psl)
    by_tld = load_curated(CURATED_DIR / "phishing_tld_history.csv")
    history = summarize_history(by_tld)
    tranco_counts, tranco_floor, tranco_total = load_tranco(PROCESSED_DIR / "tranco_tld_counts.csv")

    payload_history = load_csv_rows(PROCESSED_DIR / "payload_history.csv")
    payload_platform_history = load_csv_rows(PROCESSED_DIR / "payload_platform_history.csv")
    c2_history = load_csv_rows(PROCESSED_DIR / "c2_history.csv")

    platform_rows = build_platform_rows(current, psl)
    write_csv(
        PROCESSED_DIR / "platform_risk.csv",
        platform_rows[:100],
        ["platform_suffix", "root_tld", "live_phishing_hosts", "live_phishing_registrable", "payload_hosts", "c2_hosts", "share_of_live_phishing_hosts_pct", "note"],
    )
    write_csv(
        PROCESSED_DIR / "feed_overlap.csv",
        current["overlap_rows"],
        ["feed_a", "feed_b", "hosts_a", "hosts_b", "intersection", "jaccard_pct", "containment_pct"],
    )

    records = build_tld_records(
        current, history, tranco_counts, tranco_floor, tranco_total, payload_history, c2_history
    )

    main_fields = [
        "risk_rank", "tld", "category", "risk_tier", "risk_score", "confidence", "record_scope", "annual_year",
        "annual_domains_in_tld", "annual_phishing_domains", "annual_phishing_score", "annual_malicious_registrations",
        "annual_malreg_share", "malreg_imputed", "prev_year", "prev_phishing_domains", "prev_phishing_score",
        "growth_domains_pct", "growth_score_pct", "years_present", "years_top10_count", "years_top10_score",
        "years_top10_any", "first_year", "last_year", "peak_score", "peak_score_year", "live_phishing_domains",
        "live_phishing_hosts", "live_phishing_share", "live_feeds", "live_overrep", "payload_domains",
        "payload_hosts", "payload_share", "payload_overrep", "c2_domains", "c2_hosts", "c2_share", "c2_overrep",
        "tranco_domains", "tranco_share", "platform_hosts_under_tld", "platform_domains_under_tld",
        "platform_share_of_live", "density_norm", "volume_norm", "persistence_norm", "malreg_norm", "payload_norm",
        "c2_norm", "momentum_norm", "coverage", "intensity_category", "scale_category", "tier_base", "modifiers",
        "blocklist_suitability", "recommended_action", "confidence_reason", "evidence_sources", "notes",
    ]
    write_csv(PROCESSED_DIR / "tld_risk_scores.csv", records, main_fields)

    # Compact live counts for transparency.
    live_rows = []
    for tld in sorted(set(current["phishing_stats"]["tld_domains"]) | set(current["payload_stats"]["tld_domains"]) | set(current["c2_stats"]["tld_domains"])):
        live_rows.append(
            {
                "tld": tld,
                "live_phishing_domains": current["phishing_stats"]["tld_domains"].get(tld, 0),
                "live_phishing_hosts": current["phishing_stats"]["tld_hosts"].get(tld, 0),
                "payload_domains": current["payload_stats"]["tld_domains"].get(tld, 0),
                "payload_hosts": current["payload_stats"]["tld_hosts"].get(tld, 0),
                "c2_domains": current["c2_stats"]["tld_domains"].get(tld, 0),
                "c2_hosts": current["c2_stats"]["tld_hosts"].get(tld, 0),
            }
        )
    write_csv(PROCESSED_DIR / "live_tld_counts.csv", live_rows)

    # Historical summaries.
    history_rows = []
    for tld, h in history.items():
        history_rows.append(
            {
                "tld": tld,
                "first_year": h["first_year"],
                "last_year": h["last_year"],
                "years_present": h["years_present"],
                "years_top10_count": h["years_top10_count"],
                "years_top10_score": h["years_top10_score"],
                "years_top10_any": h["years_top10_any"],
                "peak_score": h["peak_score"],
                "peak_score_year": h["peak_score_year"],
                "annual_year": h["annual_year"],
                "annual_phishing_domains": h["annual_phishing_domains"],
                "annual_phishing_score": h["annual_score"],
                "annual_malreg_share": round(h["annual_malreg_share"], 4) if h["annual_malreg_share"] is not None else None,
            }
        )
    history_rows.sort(key=lambda r: (-r["years_top10_any"], -(r["peak_score"] or 0), r["tld"]))
    write_csv(
        PROCESSED_DIR / "historical_tld_summary.csv",
        history_rows,
        ["tld", "first_year", "last_year", "years_present", "years_top10_count", "years_top10_score", "years_top10_any", "peak_score", "peak_score_year", "annual_year", "annual_phishing_domains", "annual_phishing_score", "annual_malreg_share"],
    )

    payload_summary = summarize_payload_history(payload_history)
    platform_history_summary = summarize_platform_history(payload_platform_history)
    c2_summary = summarize_c2_history(c2_history)
    write_csv(PROCESSED_DIR / "payload_history_summary.csv", payload_summary[:100])
    write_csv(PROCESSED_DIR / "payload_platform_history_summary.csv", platform_history_summary[:100])
    write_csv(PROCESSED_DIR / "c2_history_summary.csv", c2_summary[:100])

    # Legacy watchlist: historically prominent but no current annual/live evidence.
    risk_by_tld = {r["tld"]: r for r in records}
    legacy = []
    for tld, h in history.items():
        if tld in risk_by_tld:
            continue
        if h["years_top10_any"] >= 2:
            legacy.append(
                {
                    "tld": tld,
                    "first_year": h["first_year"],
                    "last_year": h["last_year"],
                    "years_top10_any": h["years_top10_any"],
                    "peak_score": h["peak_score"],
                    "live_phishing_domains": current["phishing_stats"]["tld_domains"].get(tld, 0),
                    "note": "Historical abuse concentration; no current annual top-20 or material live evidence.",
                }
            )
    legacy.sort(key=lambda r: (-r["years_top10_any"], -(r["peak_score"] or 0)))
    write_csv(
        PROCESSED_DIR / "legacy_watchlist.csv",
        legacy,
        ["tld", "first_year", "last_year", "years_top10_any", "peak_score", "live_phishing_domains", "note"],
    )

    def compact(r, fields):
        return {k: r.get(k) for k in fields}

    tier_counts = Counter(r["risk_tier"] for r in records)
    confidence_counts = Counter(r["confidence"] for r in records)
    scope_counts = Counter(r["record_scope"] for r in records)
    category_tiers: dict[str, Counter] = defaultdict(Counter)
    for r in records:
        category_tiers[r["category"]][r["risk_tier"]] += 1
    live_total = sum(current["phishing_stats"]["tld_domains"].values())
    live_sorted = sorted((r["live_phishing_domains"] for r in records), reverse=True)
    concentration = {
        "live_total": live_total,
        "top3_live_share_pct": round(100 * sum(live_sorted[:3]) / live_total, 2) if live_total else 0.0,
        "top5_live_share_pct": round(100 * sum(live_sorted[:5]) / live_total, 2) if live_total else 0.0,
        "top10_live_share_pct": round(100 * sum(live_sorted[:10]) / live_total, 2) if live_total else 0.0,
    }
    def best_growth(r):
        values = [r.get("growth_domains_pct"), r.get("growth_score_pct")]
        values = [v for v in values if v is not None]
        return max(values) if values else None
    def worst_growth(r):
        values = [r.get("growth_domains_pct"), r.get("growth_score_pct")]
        values = [v for v in values if v is not None]
        return min(values) if values else None
    growing = sorted(
        [r for r in records if r.get("annual_year") == 2026 and best_growth(r) is not None and best_growth(r) > 0],
        key=best_growth,
        reverse=True,
    )[:15]
    shrinking = sorted(
        [r for r in records if r.get("annual_year") == 2026 and worst_growth(r) is not None and worst_growth(r) < 0],
        key=worst_growth,
    )[:10]
    surge_fields = [
        "risk_rank", "tld", "category", "risk_tier", "confidence", "annual_year",
        "prev_phishing_domains", "annual_phishing_domains", "growth_domains_pct",
        "prev_phishing_score", "annual_phishing_score", "growth_score_pct",
    ]
    blocklist_candidates = [
        compact(r, ["risk_rank", "tld", "category", "risk_tier", "risk_score", "confidence", "blocklist_suitability", "recommended_action"])
        for r in records
        if r["risk_tier"] in ("Critical", "High") and r["blocklist_suitability"] in ("High", "Medium")
    ][:30]

    risk_fields = [
        "risk_rank", "tld", "category", "risk_tier", "risk_score", "confidence", "record_scope", "annual_year",
        "annual_phishing_domains", "annual_phishing_score", "annual_malreg_share", "growth_domains_pct",
        "years_top10_any", "live_phishing_domains", "live_phishing_share", "live_feeds", "live_overrep",
        "payload_domains", "c2_domains", "tranco_share", "platform_share_of_live", "blocklist_suitability",
        "recommended_action", "notes",
    ]
    analysis = {
        "generated_at": utc_now_iso(),
        "snapshot_date": current["snapshot_date"],
        "counts": {
            "phishing_hosts": current["phishing_stats"]["total_hosts"],
            "phishing_nonplatform_hosts": current["phishing_stats"]["registered_hosts"],
            "phishing_registered_domains": sum(current["phishing_stats"]["tld_domains"].values()),
            "phishing_platform_hosts": current["phishing_stats"]["platform_hosts_total"],
            "payload_hosts": current["payload_stats"]["total_hosts"],
            "payload_nonplatform_hosts": current["payload_stats"]["registered_hosts"],
            "payload_registered_domains": sum(current["payload_stats"]["tld_domains"].values()),
            "c2_hosts": current["c2_stats"]["total_hosts"],
            "c2_nonplatform_hosts": current["c2_stats"]["registered_hosts"],
            "c2_registered_domains": sum(current["c2_stats"]["tld_domains"].values()),
            "tranco_domains": tranco_total,
            "tlds_observed": len(live_rows),
            "tlds_scored": len(records),
        },
        "feed_summary": current["manifest"].get("feed_summary", []),
        "feed_overlap": current["overlap_rows"],
        "risk_model": {
            "weights": WEIGHTS,
            "tier_matrix": {
                "intensity": {"extreme": "score >= 1000 / 10k", "high": "400-999", "elevated": "100-399", "low": "<100"},
                "scale": {"large": ">=50,000 domains", "medium": "10,000-49,999", "small": "<10,000"},
                "tiers": "extreme/high + large/medium => Critical; high + small => High; elevated + large/medium => High; elevated + small => Medium; low + large => High; low + medium => Medium; low + small => Low",
            },
            "malreg_imputation": MALREG_IMPUTED_SHARE,
            "confidence": "High = 2026 registry data + live corroboration + non-imputed malicious-registration share + coverage >=75%; Medium = 2026 data or >=1,000 live domains across >=2 feeds; Low = single/weak source, historical-only, or small live-only sample",
        },
        "tier_counts": dict(tier_counts),
        "confidence_counts": dict(confidence_counts),
        "scope_counts": dict(scope_counts),
        "category_tiers": {cat: dict(counts) for cat, counts in category_tiers.items()},
        "concentration": concentration,
        "surges": {
            "growing": [compact(r, surge_fields) for r in growing],
            "shrinking": [compact(r, surge_fields) for r in shrinking],
        },
        "blocklist_candidates": blocklist_candidates,
        "risk_rows": [compact(r, risk_fields) for r in records],
        "top_by_density": [
            compact(r, risk_fields)
            for r in sorted(records, key=lambda r: -(r["annual_phishing_score"] or 0))[:20]
            if r["annual_phishing_score"] is not None
        ],
        "top_by_volume": [
            compact(r, risk_fields)
            for r in sorted(records, key=lambda r: -(r["annual_phishing_domains"] or 0))[:20]
            if r["annual_phishing_domains"] is not None
        ],
        "top_by_malreg": [
            compact(r, risk_fields)
            for r in sorted(records, key=lambda r: -(r["annual_malreg_share"] or 0))[:20]
            if r["annual_malreg_share"] is not None
        ],
        "top_by_live": [compact(r, risk_fields) for r in sorted(records, key=lambda r: -r["live_phishing_domains"])[:20]],
        "top_by_payload": [compact(r, risk_fields) for r in sorted(records, key=lambda r: -r["payload_domains"])[:20]],
        "top_by_c2": [compact(r, risk_fields) for r in sorted(records, key=lambda r: -r["c2_domains"])[:20]],
        "platforms": platform_rows[:40],
        "legacy": legacy[:30],
        "history": {
            "tld_summary": history_rows[:60],
            "payload_summary": payload_summary[:40],
            "platform_history": platform_history_summary[:30],
            "c2_summary": c2_summary[:30],
        },
        "payload_snapshots": [
            {
                "date": s["date"],
                "hosts": s["hosts"],
                "registered_hosts": s["registered_hosts"],
                "platform_hosts": s["platform_hosts"],
            }
            for s in read_json(PROCESSED_DIR / "history_manifest.json").get("payload_snapshots", [])
        ] if (PROCESSED_DIR / "history_manifest.json").exists() else [],
    }
    write_json(REPORT_DIR / "analysis_data.json", analysis)
    write_json(PROCESSED_DIR / "tld_risk_scores.json", {"metadata": analysis["risk_model"], "rows": records})

    print(f"Analyzed snapshot {current['snapshot_date']}")
    print(f"  phishing: {current['phishing_stats']['total_hosts']:,} hosts / {sum(current['phishing_stats']['tld_domains'].values()):,} unique registrable domains ({current['phishing_stats']['registered_hosts']:,} non-platform hosts)")
    print(f"  platform hosts: {current['phishing_stats']['platform_hosts_total']:,}")
    print(f"  payload: {current['payload_stats']['total_hosts']:,} hosts / {sum(current['payload_stats']['tld_domains'].values()):,} unique registrable domains")
    print(f"  C2: {current['c2_stats']['total_hosts']:,} hosts / {sum(current['c2_stats']['tld_domains'].values()):,} unique registrable domains")
    print(f"  scored TLDs: {len(records)}; tiers: {dict(tier_counts)}")
    print(f"  confidence: {dict(confidence_counts)}")
    print("Top 15 by risk:")
    for r in records[:15]:
        print(f"  {r['risk_rank']:>2}. {r['tld']:<8} {r['risk_tier']:<8} score={r['risk_score']:>5} conf={r['confidence']:<6} "
              f"annual={r['annual_phishing_score']} live={r['live_phishing_domains']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
