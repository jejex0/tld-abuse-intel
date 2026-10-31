#!/usr/bin/env python3
"""Render reports/ANALYSIS.md from the processed data."""

from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

from common import CURATED_DIR, PROCESSED_DIR, REPORT_DIR

TIER_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
CONF_ORDER = {"High": 0, "Medium": 1, "Low": 2}
PERIODS = {
    2020: "May–Jul 2020 (3-month study)",
    2021: "May 2020 – Apr 2021",
    2022: "May 2021 – Apr 2022",
    2023: "May 2022 – Apr 2023",
    2024: "May 2023 – Apr 2024",
    2025: "May 2024 – Apr 2025",
    2026: "May 2025 – Apr 2026",
}


def load_csv(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def num(value):
    if value in (None, ""):
        return None
    try:
        return int(float(str(value).replace(",", "")))
    except ValueError:
        return None


def flt(value):
    if value in (None, ""):
        return None
    try:
        return float(str(value).replace(",", ""))
    except ValueError:
        return None


def fmt_int(value) -> str:
    value = num(value)
    return f"{value:,}" if value is not None else "—"


def fmt_flt(value, digits: int = 1) -> str:
    value = flt(value)
    return f"{value:,.{digits}f}" if value is not None else "—"


def fmt_pct(value, digits: int = 1) -> str:
    value = flt(value)
    return f"{value * 100:,.{digits}f}%" if value is not None else "—"


def esc(value) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def md_table(headers: list[str], rows: list[list]) -> str:
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join(["---"] * len(headers)) + "|"]
    for row in rows:
        out.append("| " + " | ".join(esc(cell) for cell in row) + " |")
    return "\n".join(out)


def action_short(row: dict) -> str:
    action = row.get("recommended_action", "")
    if "Do not block" in action:
        return "Monitor only"
    if "Legacy Freenom" in action:
        return "Legacy takedown"
    if "TLD-level blocklist candidate" in action:
        return "TLD blocklist candidate"
    if "Consider TLD blocking" in action:
        return "Constrained blocklist"
    return "Domain-level"


def risk_table(records: list[dict], limit: int | None = None) -> str:
    rows = []
    for r in records[:limit] if limit else records:
        rows.append(
            [
                r["risk_rank"],
                f"`.{r['tld']}`",
                r["category"],
                r["risk_tier"],
                fmt_flt(r["risk_score"], 1),
                r["confidence"],
                fmt_flt(r["annual_phishing_score"], 1),
                fmt_int(r["annual_phishing_domains"]),
                fmt_pct(r["annual_malreg_share"]),
                f"{int(r['years_top10_any'])}/7",
                fmt_int(r["live_phishing_domains"]),
                f"{fmt_int(r['payload_domains'])} / {fmt_int(r['c2_domains'])}",
                r["blocklist_suitability"],
                action_short(r),
            ]
        )
    return md_table(
        ["Rank", "TLD", "Category", "Tier", "Score", "Confidence", "Density/10k", "Annual domains", "Malicious share", "Persistence", "Live domains", "Payload / C2", "Blocklist suitability", "Action"],
        rows,
    )


def main() -> int:
    analysis = json.loads((REPORT_DIR / "analysis_data.json").read_text(encoding="utf-8"))
    rows = load_csv(PROCESSED_DIR / "tld_risk_scores.csv")
    platforms = load_csv(PROCESSED_DIR / "platform_risk.csv")
    history = load_csv(PROCESSED_DIR / "historical_tld_summary.csv")
    payload_summary = load_csv(PROCESSED_DIR / "payload_history_summary.csv")
    platform_history = load_csv(PROCESSED_DIR / "payload_platform_history_summary.csv")
    c2_summary = load_csv(PROCESSED_DIR / "c2_history_summary.csv")
    curated = load_csv(CURATED_DIR / "phishing_tld_history.csv")
    feed_summary = analysis.get("feed_summary", [])
    overlap = analysis.get("feed_overlap", [])
    counts = analysis["counts"]
    category_tiers = analysis.get("category_tiers", {})
    concentration = analysis.get("concentration", {})
    surges = analysis.get("surges", {})

    by_tld = {r["tld"]: r for r in rows}
    critical = [r for r in rows if r["risk_tier"] == "Critical"]
    high = [r for r in rows if r["risk_tier"] == "High"]
    medium = [r for r in rows if r["risk_tier"] == "Medium"]
    low = [r for r in rows if r["risk_tier"] == "Low"]
    tiers = Counter(r["risk_tier"] for r in rows)
    confs = Counter(r["confidence"] for r in rows)
    suitability = Counter(r["blocklist_suitability"] for r in rows)
    suitability_ch = Counter(r["blocklist_suitability"] for r in critical + high)

    annual_2026 = [r for r in rows if str(r["annual_year"]) == "2026"]
    top_volume = sorted([r for r in annual_2026 if r["annual_phishing_domains"]], key=lambda r: int(r["annual_phishing_domains"]), reverse=True)[:15]
    top_density = sorted([r for r in annual_2026 if r["annual_phishing_score"]], key=lambda r: float(r["annual_phishing_score"]), reverse=True)[:15]
    top_malreg = sorted(
        [r for r in rows if r["annual_malreg_share"] and num(r["annual_phishing_domains"]) and num(r["annual_phishing_domains"]) >= 5000],
        key=lambda r: float(r["annual_malreg_share"]),
        reverse=True,
    )[:12]
    top_live = sorted(rows, key=lambda r: int(r["live_phishing_domains"]), reverse=True)[:15]
    top_payload = sorted(rows, key=lambda r: int(r["payload_domains"]), reverse=True)[:12]
    top_c2 = sorted(rows, key=lambda r: int(r["c2_domains"]), reverse=True)[:10]
    top_platforms = platforms[:15]
    top_history = history[:15]
    top_payload_history = payload_summary[:10]
    top_c2_history = c2_summary[:10]

    top5 = ", ".join(f"`.{r['tld']}`" for r in rows[:5])
    critical_names = ", ".join(f"`.{r['tld']}`" for r in critical)
    high_names = ", ".join(f"`.{r['tld']}`" for r in high[:12])
    medium_names = ", ".join(f"`.{r['tld']}`" for r in medium)
    low_names = ", ".join(f"`.{r['tld']}`" for r in low)

    phish_hosts = counts["phishing_hosts"]
    phish_regs = counts["phishing_registered_domains"]
    phish_nonplatform = counts["phishing_nonplatform_hosts"]
    platform_hosts = counts["phishing_platform_hosts"]
    platform_pct = platform_hosts / phish_hosts * 100 if phish_hosts else 0
    payload_hosts = counts["payload_hosts"]
    payload_regs = counts["payload_registered_domains"]
    c2_hosts = counts["c2_hosts"]
    c2_regs = counts["c2_registered_domains"]
    c2_nonplatform = counts["c2_nonplatform_hosts"]
    tranco_domains = counts["tranco_domains"]

    com = by_tld.get("com", {})
    top_tld = by_tld.get("top", {})
    pro = by_tld.get("pro", {})
    icu = by_tld.get("icu", {})
    cfd = by_tld.get("cfd", {})
    xin = by_tld.get("xin", {})
    cyou = by_tld.get("cyou", {})
    vip = by_tld.get("vip", {})
    sbs = by_tld.get("sbs", {})
    shop = by_tld.get("shop", {})
    jp = by_tld.get("jp", {})
    com_payload_share = (num(com.get("payload_domains")) or 0) / payload_regs * 100 if payload_regs else 0
    feed_overlap_min = min((flt(r["jaccard_pct"]) for r in overlap), default=0.0)
    feed_overlap_max = max((flt(r["jaccard_pct"]) for r in overlap), default=0.0)
    def overlap_lookup(a, b, field):
        row = next((r for r in overlap if {r["feed_a"], r["feed_b"]} == {a, b}), None)
        return flt(row[field]) if row else None
    top3_share = flt(concentration.get("top3_live_share_pct")) or 0.0
    top10_share = flt(concentration.get("top10_live_share_pct")) or 0.0

    # Historical coverage table.
    year_rows = []
    for year in sorted({int(r["year"]) for r in curated}):
        rs = [r for r in curated if int(r["year"]) == year]
        year_rows.append(
            [
                year,
                PERIODS.get(year, ""),
                len(rs),
                sum(1 for r in rs if str(r.get("rank_count", "")).strip()),
                sum(1 for r in rs if str(r.get("rank_score", "")).strip()),
                sum(1 for r in rs if str(r.get("rank_malreg", "")).strip()),
            ]
        )

    # Source table.
    source_rows = []
    for f in feed_summary:
        source_rows.append(
            [
                f"`{f['source']}`",
                f["kind"],
                fmt_int(f["unique_hosts"]),
                fmt_int(f["registered_hosts"]),
                fmt_int(f["platform_hosts"]),
                fmt_int(f["tlds_observed"]),
            ]
        )

    platform_rows = []
    for p in top_platforms:
        platform_rows.append(
            [
                f"`{p['platform_suffix']}`",
                f"`.{p['root_tld']}`",
                fmt_int(p["live_phishing_hosts"]),
                f"{float(p['share_of_live_phishing_hosts_pct']):.2f}%",
                fmt_int(p["payload_hosts"]),
                fmt_int(p["c2_hosts"]),
            ]
        )

    payload_rows = []
    for r in top_payload:
        payload_rows.append(
            [
                f"`.{r['tld']}`",
                fmt_int(r["payload_domains"]),
                fmt_pct(flt(r["payload_share"]), 2),
                fmt_flt(r["payload_overrep"], 1),
                r["risk_tier"],
                r["confidence"],
            ]
        )

    c2_rows = []
    for r in top_c2:
        c2_rows.append(
            [
                f"`.{r['tld']}`",
                fmt_int(r["c2_domains"]),
                fmt_pct(flt(r["c2_share"]), 2),
                fmt_flt(r["c2_overrep"], 1),
                r["risk_tier"],
                r["confidence"],
            ]
        )

    history_rows = []
    for h in top_history:
        risk = by_tld.get(h["tld"], {})
        history_rows.append(
            [
                f"`.{h['tld']}`",
                f"{h['years_top10_any']}/7",
                h["first_year"],
                h["last_year"],
                fmt_flt(h["peak_score"], 1),
                fmt_flt(h["annual_phishing_score"], 1),
                risk.get("risk_tier", "—"),
            ]
        )

    payload_history_rows = []
    for p in top_payload_history:
        payload_history_rows.append(
            [
                f"`.{p['tld']}`",
                fmt_int(p["total_domains"]),
                fmt_int(p["max_domains"]),
                p["peak_date"],
                fmt_int(p["latest_domains"]),
                f"{p['first_date']} → {p['last_date']}",
            ]
        )

    c2_history_rows = []
    for c in top_c2_history:
        c2_history_rows.append(
            [f"`.{c['tld']}`", fmt_int(c["total_domains"]), fmt_int(c["max_domains"]), c["snapshots_present"]]
        )

    appendix_rows = []
    for r in rows:
        appendix_rows.append(
            [
                r["risk_rank"],
                f"`.{r['tld']}`",
                r["category"],
                r["risk_tier"],
                fmt_flt(r["risk_score"], 1),
                r["confidence"],
                fmt_flt(r["annual_phishing_score"], 1),
                fmt_int(r["annual_phishing_domains"]),
                fmt_pct(r["annual_malreg_share"]),
                f"{int(r['years_top10_any'])}/7",
                fmt_int(r["live_phishing_domains"]),
                fmt_int(r["payload_domains"]),
                fmt_int(r["c2_domains"]),
                r["blocklist_suitability"],
            ]
        )

    category_rows = []
    for cat in ("new gTLD", "legacy gTLD", "ccTLD"):
        c = category_tiers.get(cat, {})
        category_rows.append([cat, c.get("Critical", 0), c.get("High", 0), c.get("Medium", 0), c.get("Low", 0), sum(c.values())])

    overlap_rows = []
    for o in sorted(overlap, key=lambda r: float(r["jaccard_pct"]), reverse=True):
        overlap_rows.append([
            o["feed_a"], o["feed_b"], fmt_int(o["hosts_a"]), fmt_int(o["hosts_b"]),
            fmt_int(o["intersection"]), f"{float(o['jaccard_pct']):.2f}%", f"{float(o['containment_pct']):.2f}%",
        ])

    def growth_cell(value):
        value = flt(value)
        return f"{value:+,.1f}%" if value is not None else "—"

    surge_rows = []
    for r in surges.get("growing", [])[:12]:
        surge_rows.append([
            f"`.{r['tld']}`", r["category"], fmt_int(r["prev_phishing_domains"]),
            fmt_int(r["annual_phishing_domains"]), growth_cell(r["growth_domains_pct"]),
            fmt_flt(r["prev_phishing_score"], 1), fmt_flt(r["annual_phishing_score"], 1),
            growth_cell(r["growth_score_pct"]), r["risk_tier"], r["confidence"],
        ])
    shrink_rows = []
    for r in surges.get("shrinking", [])[:10]:
        shrink_rows.append([
            f"`.{r['tld']}`", r["category"], fmt_int(r["prev_phishing_domains"]),
            fmt_int(r["annual_phishing_domains"]), growth_cell(r["growth_domains_pct"]),
            fmt_flt(r["prev_phishing_score"], 1), fmt_flt(r["annual_phishing_score"], 1),
            growth_cell(r["growth_score_pct"]), r["risk_tier"], r["confidence"],
        ])

    platform_history_rows = []
    for p in analysis.get("history", {}).get("platform_history", [])[:10]:
        platform_history_rows.append([
            f"`.{p['platform_suffix']}`", p["first_date"], p["last_date"], fmt_int(p["max_hosts"]),
            p["peak_date"], fmt_int(p["latest_hosts"]), p["snapshots_present"],
        ])

    candidates = [
        r for r in rows
        if r["risk_tier"] in ("Critical", "High") and r["blocklist_suitability"] in ("High", "Medium")
    ][:20]
    candidate_rows = []
    for r in candidates:
        candidate_rows.append([
            f"`.{r['tld']}`", r["category"], r["risk_tier"], r["blocklist_suitability"],
            fmt_flt(r["annual_phishing_score"], 1), fmt_int(r["annual_phishing_domains"]),
            fmt_pct(r["annual_malreg_share"]), fmt_int(r["live_phishing_domains"]), r["confidence"],
        ])

    report = f"""# TLD Abuse Intelligence: Phishing, Payload Delivery, and C2 Infrastructure

**Generated:** {analysis['generated_at']}  
**Current snapshot:** {analysis['snapshot_date']}  
**Annual data window:** 2020–2026 (interrupted/partial for some early years)  
**Payload history:** 11 archived URLhaus snapshots, 2023-03-15 → 2026-07-10  
**C2 history:** 2 archived C2Intel snapshots, 2025-08-15 and 2025-09-20; current 90-day feed

> **Scope and caution.** This is defensive threat-intelligence research, not a universal blocklist.
> A high risk tier means a namespace shows a high concentration of abuse. It does not mean every
> domain in that namespace is malicious, and it does not mean blocking the entire TLD is safe.

---

## Executive summary

We combined **{phish_hosts:,} live phishing hostnames** ({phish_regs:,} unique registrable domains)
from five independent feeds, **{payload_hosts:,} payload-delivery hosts**, **{c2_hosts:,} C2 hosts**,
seven years of Interisle / Cybercrime Information Center registry data, and archived payload/C2
snapshots. The result is a reproducible, source-attributed ranking of **{len(rows)} TLDs** across
four risk tiers.

**Tier distribution:** **{tiers['Critical']} Critical**, **{tiers['High']} High**,
**{tiers['Medium']} Medium**, **{tiers['Low']} Low**. Evidence confidence is
**{confs['High']} High**, **{confs['Medium']} Medium**, **{confs['Low']} Low**.

### Key findings

1. **The top five risk-ranked namespaces are {top5}.** These combine extreme abuse density,
   material volume, and/or near-total attacker registration. Ten of the eleven Critical TLDs are
   new gTLDs; the exception is the legacy `.pro` namespace.
2. **`.top` is the single most consistent high-scale abuser.** It ranks #2 by annual phishing
   volume ({fmt_int(top_tld.get('annual_phishing_domains'))} domains), #17 by density
   ({fmt_flt(top_tld.get('annual_phishing_score'))}/10k), and appears in the top-10 by volume or
   density in **{top_tld.get('years_top10_any', 0)} of 7 years**. Its malicious-registration share is
   {fmt_pct(top_tld.get('annual_malreg_share'))}.
3. **`.com` is the largest absolute source of phishing but is not the highest-density risk.**
   It has **{fmt_int(com.get('annual_phishing_domains'))}** annual phishing domains, yet
   **{fmt_flt(com.get('annual_phishing_score'))}/10k** density — roughly one order of magnitude below
   `.top` and two orders below `.xin`. In the live feeds, `.com` is **under-represented** relative to
   its Tranco popularity (over-representation index {fmt_flt(com.get('live_overrep'), 2)}). It is
   High risk but Low blocklist suitability.
4. **The extreme tail is dominated by attacker-registered domains, not compromised sites.**
   `.icu` ({fmt_pct(icu.get('annual_malreg_share'))} maliciously registered), `.cfd`
   ({fmt_pct(cfd.get('annual_malreg_share'))}), `.xin` ({fmt_pct(xin.get('annual_malreg_share'))}),
   `.cyou` ({fmt_pct(cyou.get('annual_malreg_share'))}), and `.vip`
   ({fmt_pct(vip.get('annual_malreg_share'))}) show very high attacker-registration shares.
   `.pro` ({fmt_pct(pro.get('annual_malreg_share'))}) and `.top` ({fmt_pct(top_tld.get('annual_malreg_share'))})
   are lower but still high.
5. **`.pro`, `.icu`, `.cfd`, `.cyou`, and `.jp` show sharp year-over-year changes.**
   `.pro` grew {fmt_pct(flt(pro.get('growth_domains_pct')) / 100)} in annual phishing domains;
   `.icu` {fmt_pct(flt(icu.get('growth_domains_pct')) / 100)}; `.cfd` {fmt_pct(flt(cfd.get('growth_domains_pct')) / 100)};
   `.cyou` {fmt_pct(flt(cyou.get('growth_domains_pct')) / 100)}; `.jp`
   {fmt_pct(flt(jp.get('growth_domains_pct')) / 100)} (534 → {fmt_int(jp.get('annual_phishing_domains'))} domains).
   The `.jp` jump is an outlier that warrants validation rather than immediate blanket action.
6. **Free hosting and dynamic DNS are a TLD-scale problem in their own right.**
   **{platform_pct:.1f}%** of live phishing hosts ({platform_hosts:,} of {phish_hosts:,}) sit on
   private platform suffixes, not registrable TLD domains. The largest are `duckdns.org` (16,936),
   `pages.dev` (14,538), `webflow.io` (11,940), `vercel.app` (11,566), and `github.io` (7,723).
   These are excluded from TLD risk counts to avoid unfairly inflating `.dev`, `.app`, `.io`, and `.org`.
7. **Payload delivery is concentrated in `.com`, but the high-density tail matters more for blocking.**
   `.com` accounts for **{com_payload_share:.1f}%** of current URLhaus registered payload domains
   ({fmt_int(com.get('payload_domains'))} of {payload_regs:,}). The next tier is `.net` (80), `.org` (58),
   `.cc` (32), `.top` (29), `.xyz` (27), `.win` (24), and `.lol` (21). Platform payload hosting is led by
   `r2.dev` (76), `workers.dev` (34), `pages.dev` (23), and `vercel.app` (20).
8. **C2 data is small but useful as a supporting signal.** The current union has {c2_hosts} hosts
   ({c2_nonplatform} non-platform hostnames / {c2_regs} unique registrable domains), led by `.com` (49), `.top` (13), `.net` (6), `.cn` (5), and `.shop` (5).
   Historical C2 snapshots are too sparse for trend claims. C2 infrastructure frequently uses popular
   TLDs and compromised hosts, so TLD blocking is not a C2 strategy.
9. **Historical persistence separates durable abuse from one-year spikes.** `.com`, `.top`, `.xyz`, and
   `.cn` appear in top-10 lists in 6–7 of 7 years. `.tk` persists in 5 years but is a special case:
   Freenom's registration freeze means today's `.tk`/`.ml`/`.ga`/`.cf`/`.gq` abuse is mostly legacy
   infrastructure. `.icu`, `.pro`, `.win`, and `.help` are surge entrants with sudden 2026 scale.
10. **Feed overlap is low; the union is justified.** Pairwise Jaccard overlap between phishing feeds is
    as low as {feed_overlap_min:.2f}% and at most {feed_overlap_max:.2f}%. OpenPhish is mostly contained
    in Phishing Army (97.2% containment) but adds freshness; Phishing.Database and Spam404 contribute
    largely disjoint domain sets.

### What to do first

- **For high-risk or constrained environments:** evaluate TLD-level blocks for `.xin`, `.icu`,
  `.cfd`, `.cyou`, `.vip`, `.sbs`, `.click`, `.live`, `.win`, `.help`, `.garden`, and `.top`.
  Validate business dependencies first; `.top` and `.pro` have moderate collateral.
- **Never blanket-block** `.com`, `.net`, `.org`, `.cn`, `.jp`, `.ru`, `.de`, `.uk`, `.br`, `.in`,
  or `.io`; use domain-level detection and takedown.
- **Control free-hosting subdomains** at the platform namespace level. Parent-TLD rules such as
  “block `.dev`” would be both over-broad and ineffective.
- **Monitor the surge cohort** (`.pro`, `.icu`, `.cfd`, `.cyou`, `.jp`, `.mobi`, `.garden`) for
  campaign reuse, registrar concentration, and new-registration patterns.
- **Treat payload/C2 signals as enrichment**, not as standalone TLD evidence. The C2 sample is
  too small for confident TLD-wide conclusions.

---

## 1. Data collection and scope

### 1.1 Current live feeds

| Source | Kind | Unique hosts | Non-platform hosts | Platform hosts | TLDs observed |
|---|---|---:|---:|---:|---:|
{chr(10).join('| ' + ' | '.join(r) + ' |' for r in source_rows)}

The live union contains **{phish_hosts:,} phishing hostnames** and **{phish_regs:,} unique
registrable phishing domains**. The difference is subdomain reuse: many hostnames collapse to the
same registrable domain. Of the live phishing hosts, **{phish_nonplatform:,}** are non-platform
hostnames and **{platform_hosts:,}** are platform hosts. Payload and C2 feeds are analyzed separately.

**Feed design choices:**

- **Phishing feeds:** OpenPhish (freshness), Phishing Army, Phishing.Database, Spam404, and the
  malware-filter phishing mirror. The union is de-duplicated at the registrable-domain level.
- **Payload feed:** the malware-filter mirror of URLhaus. URLhaus tracks malware distribution URLs;
  some are payload/staging hosts, some are compromised legitimate sites. It is not a pure “staging
  only” feed.
- **C2 feed:** C2IntelFeeds 30-day, 90-day, and DNS C2 domain feeds. The 90-day feed is the largest
  and is used for current counts. The sample is small and is weighted accordingly.
- **Popularity baseline:** Tranco top-1M domains, excluding private platform suffixes, used to
  compute live over-representation.

### 1.2 Historical registry data

The annual data comes from Interisle Consulting Group's Phishing Landscape studies and the
Cybercrime Information Center's TLD tables. Coverage is uneven by design:

| Year | Period | TLDs recorded | Count table | Score table | Malicious-registration table |
|---|---|---:|---:|---:|---:|
{chr(10).join('| ' + ' | '.join(str(x) for x in r) + ' |' for r in year_rows)}

- **2020** used a three-month study window (May–July), so its counts are not directly comparable to
  full-year studies.
- **2021–2023** reports list top-5/top-10 tables; full top-20 volume, density, and malicious
  registration tables are available from **2024 onward**.
- **2022** count ranks are available for the top five; exact counts and the full score table were not
  extractable from the published report. The dataset records only what the source supports.
- **2025 baselines** for 2026 entrants were filled from the 2026 year-over-year table. These rows are
  marked in the curated CSV and may not have been in the 2025 top-20 tables.
- **2026** is the current annual dataset: May 2025 – April 2026.

All source URLs, periods, and extraction notes are recorded in
`data/curated/phishing_tld_history.csv`.

### 1.3 What “TLD” means in this report

Three namespace levels are separated deliberately:

1. **Root TLD for registered domains** — the last label of the ICANN public suffix (`.com`, `.top`,
   `.cn`). Multi-label public suffixes are aggregated to their root (`co.uk` → `uk`, `my.id` → `id`).
   This matches the annual registry tables.
2. **Public suffix** — the full ICANN suffix (`co.uk`, `com.br`, `my.id`). A detail table is available
   in `data/processed/live_tld_counts.csv`.
3. **Private platform suffix** — a privately operated namespace such as `pages.dev`, `vercel.app`,
   `github.io`, `duckdns.org`, or `r2.dev`. These are **not** counted as registrations in the parent
   TLD. Hostnames on these namespaces are reported separately because the attacker did not register
   the parent TLD; they abuse a platform.

This distinction changes the story materially. Without it, `.dev` would appear to be one of the most
abused “TLDs” because of `pages.dev` and `r2.dev`; in reality, the abuse is on the platform
namespace, not on registered `.dev` domains.

### 1.4 Feed overlap and complementarity

| Feed A | Feed B | Hosts A | Hosts B | Intersection | Jaccard | Containment |
|---|---|---:|---:|---:|---:|---:|
{chr(10).join('| ' + ' | '.join(r) + ' |' for r in overlap_rows)}

Pairwise Jaccard overlap ranges from {feed_overlap_min:.2f}% to {feed_overlap_max:.2f}%. OpenPhish is
mostly contained in Phishing Army ({overlap_lookup("openphish", "phishing_army", "containment_pct"):.1f}%
containment), while Phishing.Database and Spam404 are largely disjoint. Phishing Army and the
malware-filter phishing mirror overlap by {overlap_lookup("phishing_army", "phishing_filter", "jaccard_pct"):.2f}%
(Jaccard), and Phishing.Database adds only {overlap_lookup("phishing_database", "phishing_filter", "containment_pct"):.1f}%
containment with the filter. The union is therefore justified: no single feed is a superset of the
others, and the low overlap increases coverage while keeping duplicates manageable.

---

## 2. Methodology

### 2.1 Metrics

| Metric | Definition | Why it matters |
|---|---|---|
| Annual phishing volume | Domains reported for phishing in the annual study | Absolute exposure and takedown workload |
| Phishing domain score | Phishing domains ÷ domains under management × 10,000 | Normalizes for TLD size; the core density metric |
| Malicious registration share | Maliciously registered phishing domains ÷ phishing domains | Separates attacker registration from compromise |
| Persistence | Years in a top-10 volume or density table, 2020–2026 | Distinguishes durable abuse from one-year spikes |
| Live share | TLD's share of current live phishing registrations | Point-in-time confirmation |
| Live over-representation | Live phishing share ÷ Tranco top-1M share | Adjusts for how common the TLD is among benign popular domains |
| Payload signal | Registered domains in URLhaus-derived payload lists | Malware delivery / staging exposure |
| C2 signal | Registered domains in C2Intel feeds | Command-and-control exposure, small sample |
| Momentum | Year-over-year change in volume or density | Detects emerging abuse |

The **over-representation index** is especially useful for TLDs that rarely appear in annual top-20
tables. A value of 1 means the TLD's share of live phishing equals its share of popular benign
domains. Values above 1 indicate over-representation; values below 1 mean the TLD is less prominent
in phishing than its benign footprint would suggest.

### 2.2 Risk score

The risk score is a 0–100 composite used for ordering within tiers:

| Component | Weight | Normalization |
|---|---:|---|
| Density | 35 | Log-scaled annual phishing score (5 → 6,000 per 10k) |
| Volume | 15 | Log-scaled annual or live phishing domains |
| Persistence | 15 | Top-10 appearances ÷ 7 |
| Malicious registration share | 15 | Direct 0–1 (74% imputed when absent) |
| Payload | 10 | Log-scaled URLhaus registered domains |
| C2 | 5 | Log-scaled C2Intel registered domains |
| Momentum | 5 | Year-over-year growth capped at 300% |

Missing components score zero and reduce evidence coverage. The malicious-registration share is
imputed at **74%** when a TLD is in the current annual tables but not in the top-20 malicious
registration table; this is Interisle's 2026 overall attacker-registered average. Imputation is
flagged in the CSV and prevents High confidence.

### 2.3 Tier rules

Risk tiers are **density-led and absolute**, not percentile-based, so they remain comparable across
runs:

- **Critical** — any of:
  - density ≥ 1,000 per 10k **and** volume ≥ 10,000;
  - density ≥ 500 **and** volume ≥ 50,000;
  - density ≥ 400 **and** volume ≥ 20,000 **and** malicious-registration share ≥ 95%.
- **High** — any of:
  - density ≥ 400;
  - density ≥ 200 **and** volume ≥ 10,000;
  - density ≥ 100 **and** volume ≥ 50,000;
  - density ≥ 140 **and** volume ≥ 30,000;
  - composite score ≥ 52;
  - live-only over-representation ≥ 20 with ≥ 1,000 live domains.
- **Medium** — density ≥ 100, or density ≥ 50 with volume ≥ 10,000, or volume ≥ 50,000, or a
  medium-scale live-only signal, or composite score ≥ 32.
- **Low** — everything else.

**Modifiers** can raise Low/Medium to High (never to Critical): malicious-registration share ≥ 90%
at meaningful scale, persistent top-10 presence, strong payload/C2 signal, and live-only scale.
Live-only evidence is capped at High; historical-only evidence is capped at Medium; live-only TLDs
with < 1,000 domains are capped at Medium. These caps prevent weak evidence from producing dramatic
tiers.

**Tier is not blocklist advice.** A Critical TLD with huge collateral (`.com` would not be Critical
under these rules, but `.cn` is High) may still be a poor blocking target. Blocklist suitability is
reported separately using Tranco collateral share and platform concentration.

### 2.4 Confidence

Confidence measures evidence quality, not severity:

- **High** — 2026 registry data + live phishing or payload/C2 corroboration + observed
  malicious-registration share + ≥ 75% component coverage.
- **Medium** — 2026 registry data without full corroboration, or ≥ 1,000 live domains across
  ≥ 2 feeds, or a persistent historical namespace with material live evidence.
- **Low** — historical-only, small live-only sample, or signal-only evidence.

A Critical/high tier with Low confidence is a **watchlist item**, not a confirmed policy target.

---

## 3. Current phishing landscape (2026 annual study)

![Top TLDs by volume](figures/fig01_top_volume_2026.png)

### 3.1 Volume leaders

| TLD | Annual phishing domains | Density/10k | Malicious share | Live domains | Tier | Confidence |
|---|---:|---:|---:|---:|---|---|
{chr(10).join(f"| `.{r['tld']}` | {fmt_int(r['annual_phishing_domains'])} | {fmt_flt(r['annual_phishing_score'])} | {fmt_pct(r['annual_malreg_share'])} | {fmt_int(r['live_phishing_domains'])} | {r['risk_tier']} | {r['confidence']} |" for r in top_volume)}

![Top TLDs by density](figures/fig02_top_density_2026.png)

### 3.2 Density leaders

| TLD | Density/10k | Annual domains | Malicious share | Persistence | Live domains | Tier |
|---|---:|---:|---:|---:|---:|---|
{chr(10).join(f"| `.{r['tld']}` | {fmt_flt(r['annual_phishing_score'])} | {fmt_int(r['annual_phishing_domains'])} | {fmt_pct(r['annual_malreg_share'])} | {r['years_top10_any']}/7 | {fmt_int(r['live_phishing_domains'])} | {r['risk_tier']} |" for r in top_density)}

![Risk matrix](figures/fig03_risk_matrix.png)

### 3.3 Attacker registration vs. compromise

| TLD | Malicious share | Malicious registrations | Phishing domains | Density/10k | Tier |
|---|---:|---:|---:|---:|---|
{chr(10).join(f"| `.{r['tld']}` | {fmt_pct(r['annual_malreg_share'])} | {fmt_int(r['annual_malicious_registrations'])} | {fmt_int(r['annual_phishing_domains'])} | {fmt_flt(r['annual_phishing_score'])} | {r['risk_tier']} |" for r in top_malreg)}

### 3.4 What stands out

- **Live phishing is highly concentrated.** The top three TLDs account for **{top3_share:.1f}%** of unique
  registrable live phishing domains; the top ten account for **{top10_share:.1f}%**. Concentration at this
  level means a small number of namespaces drive most of the operational workload.
- **Volume ≠ density.** `.com` has {fmt_int(com.get('annual_phishing_domains'))} phishing domains but a
  density of {fmt_flt(com.get('annual_phishing_score'))}/10k. `.xin` has only
  {fmt_int(xin.get('annual_phishing_domains'))} domains but a density of
  {fmt_flt(xin.get('annual_phishing_score'))}/10k — about 110× `.com`. A defender optimizing exposure
  should look at both axes; a defender choosing a blocklist should weight density and collateral.
- **The extreme tier is mostly new gTLDs.** `.icu` ({fmt_flt(icu.get('annual_phishing_score'))}/10k),
  `.cfd` ({fmt_flt(cfd.get('annual_phishing_score'))}/10k), `.xin`
  ({fmt_flt(xin.get('annual_phishing_score'))}/10k), `.pro`
  ({fmt_flt(pro.get('annual_phishing_score'))}/10k), `.win`, `.help`, and `.garden` combine extreme
  density with material volume. `.pro` is the legacy exception.
- **Malicious registration is the engine.** `.icu` ({fmt_pct(icu.get('annual_malreg_share'))}),
  `.cfd` ({fmt_pct(cfd.get('annual_malreg_share'))}), `.xin` ({fmt_pct(xin.get('annual_malreg_share'))}),
  `.cyou` ({fmt_pct(cyou.get('annual_malreg_share'))}), and `.vip`
  ({fmt_pct(vip.get('annual_malreg_share'))}) are overwhelmingly attacker-registered. This is a
  registration-abuse problem, not primarily a compromised-website problem.
- **`.cn` looks different.** It has {fmt_int(by_tld['cn'].get('annual_phishing_domains'))} phishing
  domains but only a {fmt_pct(by_tld['cn'].get('annual_malreg_share'))} malicious-registration share;
  the rest are compromised or otherwise not attacker-registered. That changes the mitigation path
  toward hosting/registrar remediation rather than registration controls.
- **`.jp` is a 2026 outlier.** It jumped from 534 phishing domains in 2025 to
  {fmt_int(jp.get('annual_phishing_domains'))} in 2026 ({fmt_pct(flt(jp.get('growth_domains_pct')) / 100)}),
  yet it is not in the malicious-registration top-20 table. This could reflect a campaign, a
  measurement/reporting change, or a large compromised footprint. It is ranked High with
  Medium confidence and flagged for validation.
- **`.shop` is a live-feed leader but less attacker-registered than peers.** It is #2 in live
  registrable phishing domains ({fmt_int(shop.get('live_phishing_domains'))}), but its annual
  malicious-registration share is {fmt_pct(shop.get('annual_malreg_share'))}, lower than the
  extreme tier. It remains High risk because of volume and density
  ({fmt_flt(shop.get('annual_phishing_score'))}/10k).

### 3.5 Fastest-growing and shrinking namespaces

Growth is measured against the prior annual period. Either domain growth or density growth can drive
the momentum component; a dash means the metric was not available in both periods. All rows shown are
true 2025→2026 comparisons; TLDs whose latest annual data is 2024 or 2025 are excluded from this table.

| TLD | Category | Prev phishing domains | 2026 phishing domains | Domain growth | Prev density | 2026 density | Density growth | Tier | Confidence |
|---|---|---:|---:|---:|---:|---:|---:|---|---|
{chr(10).join('| ' + ' | '.join(str(x) for x in r) + ' |' for r in surge_rows)}

**Largest declines (ordered by the weaker of domain or density growth):**

| TLD | Category | Prev phishing domains | 2026 phishing domains | Domain growth | Prev density | 2026 density | Density growth | Tier | Confidence |
|---|---|---:|---:|---:|---:|---:|---:|---|---|
{(chr(10).join('| ' + ' | '.join(str(x) for x in r) + ' |' for r in shrink_rows) if shrink_rows else '_No material declines in the current scoring set._')}

The growth table is dominated by registry-level surges: `.garden` (density +24,395%), `.mobi`
(density +6,351%), `.jp` (domains +8,672%), `.pro` (+667% domains), `.cyou` (+312% domains), and
`.help` (+295% domains). Such jumps can reflect genuine campaign migration, a change in reporting
coverage, or bulk registration; treat them as triage signals, not proof of a permanent shift.

---

## 4. Historical persistence and evolution

![Density trends](figures/fig04_density_trends.png)

### 4.1 Most persistent namespaces

| TLD | Top-10 years | First year | Last year | Peak density | 2026 density | Current tier |
|---|---:|---:|---:|---:|---:|---|
{chr(10).join('| ' + ' | '.join(str(x) for x in r) + ' |' for r in history_rows)}

![Persistence](figures/fig12_persistence.png)

### 4.2 What the long view adds

- **Durability is rare.** Only `.com`, `.top`, `.xyz`, and `.cn` appear in top-10 lists in six or
  more of seven years. A TLD that is dangerous in one annual table may disappear the next; a TLD
  that persists across years is a better candidate for standing policy.
- **`.top` is the archetype of durable, high-scale abuse.** Six of seven years, top-2 volume in 2026,
  and a malicious-registration share of {fmt_pct(top_tld.get('annual_malreg_share'))}. Its density
  ({fmt_flt(top_tld.get('annual_phishing_score'))}/10k) is high but not extreme; the problem is the
  combination of scale and persistence.
- **Freenom is a case study in namespace collapse, not remediation.** `.tk`, `.ml`, `.ga`, `.cf`, and
  `.gq` dominated 2020–2023 free-registration abuse. Freenom stopped offering registrations in
  January 2023. Today's live counts (`.tk` 3,107, `.ml` 2,196, `.ga` 1,836, `.cf` 1,400,
  `.gq` 1,323) are largely legacy domains. They remain High risk in the live data, but the
  appropriate response is legacy-domain takedown, not new-registration policy.
- **The 2026 surge cohort is new.** `.icu`, `.cfd`, `.pro`, `.win`, `.help`, `.cyou`, `.vip`, and
  `.garden` either entered the top tables or accelerated sharply. Their registries and registrars
  should be the focus of proactive abuse monitoring.
- **Small persistent TLDs still matter.** `.buzz`, `.best`, `.rest`, `.lol`, `.support`, and `.mom`
  have small absolute volumes but high density at times. They are cheap to block and can be
  disproportionately important for targeted campaigns.

**Historical caveats:** 2020 is a three-month study; 2022 data is partial; the 2021–2023 reports use
top-5/top-10 tables rather than the full top-20. The persistence count is therefore a conservative
lower bound, not a complete history.

---

## 5. Payload delivery and staging

URLhaus tracks malware distribution URLs. It is a useful proxy for payload delivery and staging, but
it is not a pure C2 feed and includes compromised legitimate sites.

![Payload history](figures/fig05_payload_history.png)

### 5.1 Current payload TLDs

| TLD | Payload domains | Share of payload | Over-representation | Tier | Confidence |
|---|---:|---:|---:|---|---|
{chr(10).join(f"| `.{r['tld']}` | {fmt_int(r['payload_domains'])} | {fmt_pct(flt(r['payload_share']), 2)} | {fmt_flt(r['payload_overrep'], 1)} | {r['risk_tier']} | {r['confidence']} |" for r in top_payload)}

![Payload platforms](figures/fig06_payload_platforms.png)

### 5.2 Historical payload patterns

| TLD | Total domains across snapshots | Peak | Peak date | Latest | Coverage |
|---|---:|---:|---|---:|---|
{chr(10).join('| ' + ' | '.join(str(x) for x in r) + ' |' for r in payload_history_rows)}

- **`.com` is the durable payload host.** It accounts for the largest total across snapshots and
  {com_payload_share:.1f}% of current registered payload domains. It is also the most common
  legitimate TLD, so this is exposure, not a reason to block.
- **The `.ru` “spike” is mostly subdomains.** The 2025-12-16 archived URLhaus list contained 10,513
  `.ru` hostnames but only 2,779 unique registrable `.ru` domains. This is a subdomain-heavy
  campaign, not 10,000 separately registered domains. Always distinguish hostnames from registrable
  domains when reading feed statistics.
- **Campaign bursts are visible in the tail.** The 2026-07-10 snapshot shows `.lat` (1,720),
  `.surf` (847), `.garden` (696), `.pics` (600), and `.bet` (488) — a burst pattern consistent with
  a coordinated campaign or a temporary hosting pattern. These tail TLDs can be high-value short-term
  blocks even if their annual counts are small.
- **Free platforms are prominent in payload delivery.** `r2.dev` (76 current hosts), `workers.dev`
  (34), `pages.dev` (23), `vercel.app` (20), `duckdns.org` (15), and `trycloudflare.com` (12) are
  common. The 2026-07-10 snapshot includes a 3,928-host `in.net` burst, showing that a single
  platform namespace can dominate a snapshot.

**Implication:** payload defense should combine URL/host indicators, platform-subdomain controls,
and TLD policy. TLD blocking alone is too coarse and misses popular-TLD hosting.

---

## 6. C2 infrastructure

![C2 TLDs](figures/fig07_c2_tlds.png)

### 6.1 Current C2 TLD distribution

| TLD | C2 domains | Share | Over-representation | Tier | Confidence |
|---|---:|---:|---:|---|---|
{chr(10).join('| ' + ' | '.join(str(x) for x in r) + ' |' for r in c2_rows)}

### 6.2 Historical C2 snapshots

| TLD | Total C2 domains | Peak | Snapshots |
|---|---:|---:|---:|
{chr(10).join('| ' + ' | '.join(str(x) for x in r) + ' |' for r in c2_history_rows)}

- The current C2 union is **{c2_hosts} hosts** ({c2_nonplatform} non-platform hostnames / {c2_regs} unique
  registrable domains). This is a small sample;
  a difference of two or three domains should not change a TLD's risk tier.
- `.com` dominates absolutely, as it does for payload and phishing. `.top`, `.net`, `.cn`, `.shop`,
  `.xyz`, and `.click` carry the visible tail. Over-representation is high for `.top` (19.5),
  `.click` (20.6), and `.shop` (8.0), but absolute counts are small.
- Historical C2 snapshots (2025-08-15 and 2025-09-20) contain 85 hosts each and only 28 TLDs. They
  do not provide a reliable trend. Current C2Intel data is used as enrichment, not as a primary
  ranking input.
- C2 frequently uses popular TLDs, compromised hosts, and legitimate cloud services. TLD-level
  blocking is not an effective C2 control; focus on protocol/URI patterns, hosting providers, and
  threat-intel matching.

---

## 7. Free hosting and dynamic DNS: the real platform problem

![Platform abuse](figures/fig08_platform_abuse.png)

**{platform_pct:.1f}%** of live phishing hostnames are on private platform suffixes. This is a
separate abuse economy from registered TLDs.

| Platform suffix | Parent TLD | Live phishing hosts | Share of live hosts | Payload hosts | C2 hosts |
|---|---|---:|---:|---:|---:|
{chr(10).join('| ' + ' | '.join(r) + ' |' for r in platform_rows)}

- `duckdns.org`, `pages.dev`, `webflow.io`, `vercel.app`, `github.io`, `ey.r.appspot.com`,
  `r2.dev`, `web.app`, `netlify.app`, and `workers.dev` are the largest current abuse namespaces.
- These namespaces are **excluded** from the parent TLD counts in the risk model. Counting
  `pages.dev` as `.dev` would attribute 14,538 phishing hosts to registered `.dev` domains that do
  not exist. The correct control is at the platform subdomain or account level.
- Platform abuse is also visible in payload history: `r2.dev`, `workers.dev`, `pages.dev`,
  `vercel.app`, `duckdns.org`, and `trycloudflare.com` recur across snapshots.
- **Recommendation:** maintain platform-specific allow/block policies, monitor new subdomains under
  these suffixes, and report abuse to the platform operators. A TLD blocklist cannot solve this
  layer.

### 7.1 Platform history

| Platform | First snapshot | Last snapshot | Max hosts | Peak date | Latest hosts | Snapshots |
|---|---|---|---:|---|---:|---:|
{chr(10).join('| ' + ' | '.join(str(x) for x in r) + ' |' for r in platform_history_rows)}

The platform mix shifts over time. `r2.dev`, `workers.dev`, `pages.dev`, `vercel.app`, and
`duckdns.org` recur across snapshots; `trycloudflare.com` and `plesk.page` show campaign-driven
spikes; and the 2026-07-10 snapshot contains a 3,928-host `in.net` burst. Platform-level telemetry
should therefore be refreshed more often than annual TLD data.

---

## 8. Risk-tier rankings

### 8.1 Tier summary

| Tier | Count | High confidence | Medium confidence | Low confidence |
|---|---:|---:|---:|---:|
| Critical | {tiers['Critical']} | {sum(1 for r in critical if r['confidence'] == 'High')} | {sum(1 for r in critical if r['confidence'] == 'Medium')} | {sum(1 for r in critical if r['confidence'] == 'Low')} |
| High | {tiers['High']} | {sum(1 for r in high if r['confidence'] == 'High')} | {sum(1 for r in high if r['confidence'] == 'Medium')} | {sum(1 for r in high if r['confidence'] == 'Low')} |
| Medium | {tiers['Medium']} | {sum(1 for r in medium if r['confidence'] == 'High')} | {sum(1 for r in medium if r['confidence'] == 'Medium')} | {sum(1 for r in medium if r['confidence'] == 'Low')} |
| Low | {tiers['Low']} | {sum(1 for r in low if r['confidence'] == 'High')} | {sum(1 for r in low if r['confidence'] == 'Medium')} | {sum(1 for r in low if r['confidence'] == 'Low')} |

**By namespace category:**

| Category | Critical | High | Medium | Low | Total |
|---|---:|---:|---:|---:|---:|
{chr(10).join('| ' + ' | '.join(str(x) for x in r) + ' |' for r in category_rows)}

Ten of the eleven Critical TLDs are new gTLDs; the exception is `.pro`, a legacy gTLD. No ccTLD
reaches Critical in this model: the ccTLDs with material abuse (`.cn`, `.cc`, `.jp`, `.ru`) have either lower
density or much larger benign footprints. The ccTLD risk is concentrated in High/Medium/Low tiers and
should be handled at the domain level.

![Tier and confidence](figures/fig10_tier_confidence.png)

### 8.2 Critical

{risk_table(critical)}

**Why these are Critical:**

- `.top`, `.icu`, `.cfd`, `.xin`, `.pro`, `.win`, `.help`, `.garden`, and `.lol` meet the extreme
  density + volume thresholds. `.vip` and `.cyou` meet the high-density/large-volume or
  near-total-malicious-registration thresholds.
- **`.garden`** is Critical on the strength of the annual registry data (1,567.7/10k) but has only
  22 live domains and Medium confidence; it is a strong registry-level signal without current feed
  corroboration.
- **`.lol`** is Critical based on the 2025 annual table (468.6/10k, 24,187 domains); it was not in
  the 2026 top-20 volume/score lists, so its current trajectory is less certain. Treat it as
  “Critical with a 2025 basis.”
- **`.win` and `.help`** are Critical but their malicious-registration shares are imputed at 74%
  (they are not in the 2026 malicious-registration top-20). The density and volume evidence is
  strong; the attacker-registration split is less certain.

### 8.3 High

Top 20 shown; all {tiers['High']} are in `data/processed/tld_risk_scores.csv`.

{risk_table(high, limit=20)}

**Interpretation:**

- `.com` is High because of enormous volume, not density. Its blocklist suitability is Low; do not
  block it.
- `.live`, `.sbs`, `.cc`, `.click`, `.shop`, `.xyz`, `.info`, `.cn`, and `.net` combine meaningful
  volume with elevated density. Some are large enough that whole-TLD blocking is impractical.
- `.mobi`, `.rest`, `.best`, `.mom`, `.lat`, `.life`, `.qpon`, and `.ink` are small-to-medium
  high-density namespaces; they are often better blocklist candidates than the large high-volume
  TLDs.
- `.bond` has a 99.0% malicious-registration share at 41,594 domains — one of the clearest
  attacker-registration signals in the dataset.

### 8.4 Medium and Low

**Medium ({len(medium)}):** {medium_names}.

**Low ({len(low)}):** {low_names}.

Medium contains a mix of:

- legacy or large namespaces with modest density (`.org`, `.ru`, `.buzz`, `.monster`);
- live-only TLDs with material volume but low over-representation (`.id`, `.br`, `.pl`);
- low-volume namespaces elevated by historical or payload signals.

Low contains mostly large ccTLDs with substantial benign popularity and below-parity live
over-representation (`.de`, `.uk`, `.co`, `.us`, `.au`, `.eu`, `.in`) plus small `.za` and `.st`.
This does **not** mean they are safe; it means their TLD-level abuse concentration is lower than
their size would predict. Domain-level detection still applies.

### 8.5 Blocklist suitability

Among Critical + High, blocklist suitability is **{suitability_ch['High']} High**, **{suitability_ch['Medium']} Medium**, and **{suitability_ch['Low']} Low**.

- **High suitability** means low Tranco collateral and limited platform concentration: good
  candidates for TLD-level blocking in constrained environments.
- **Medium suitability** means meaningful collateral or mixed evidence: consider only for high-risk
  user groups and validate business dependencies.
- **Low suitability** means high collateral: never block the TLD wholesale; use domain-level
  controls.

Suitability is a policy aid, not a risk downgrade. `.com` remains a High-risk namespace even though
it is a Low-suitability blocklist target.

---

## 9. Confidence analysis

**Confidence distribution:** High {confs['High']}, Medium {confs['Medium']}, Low {confs['Low']}.

- **High confidence** requires 2026 annual data, live or payload/C2 corroboration, an observed
  malicious-registration share, and broad component coverage. Examples: `.top`, `.icu`, `.cfd`,
  `.xin`, `.pro`, `.cyou`, `.vip`.
- **Medium confidence** covers three common situations:
  1. strong 2026 annual data but an imputed malicious-registration share (`.win`, `.help`, `.garden`);
  2. an older annual baseline with live corroboration (`.lol`, `.world`, `.support`, `.tk`);
  3. live-only namespaces with material volume (`.id`, `.br`, `.pl`, `.store`).
- **Low confidence** is reserved for historical-only evidence, small live-only samples, or
  signal-only records (`.quest`, `.zone`, `.za`, `.st`).

**Practical rule:** a Critical/High risk tier with Low confidence is a monitoring target, not a
blocklist target. Collect more live evidence, check registrar/hosting concentration, and re-run
before making a policy change.

---

## 10. Detection and policy recommendations

### 10.1 Tier-aligned actions

| Situation | Recommended action |
|---|---|
| Critical/High + High blocklist suitability | Evaluate TLD-level block for high-risk or constrained user groups; validate business need. |
| Critical/High + Medium suitability | Prefer domain-level detection; consider TLD block only for tightly scoped environments. |
| Critical/High + Low suitability (`.com`, `.net`, `.cn`, `.jp`, etc.) | Do not block the TLD; monitor domain-level abuse and escalate to registrar/registry. |
| High density + low volume (`.best`, `.rest`, `.qpon`, `.ink`, `.mom`) | High-value blocklist candidates; low collateral relative to abuse concentration. |
| Legacy Freenom (`.tk`, `.ml`, `.ga`, `.cf`, `.gq`) | Block legacy domains and pursue takedown; registration-level policy is moot after the 2023 freeze. |
| Free platform suffixes (`pages.dev`, `vercel.app`, `duckdns.org`, etc.) | Control at the platform subdomain/account level; do not block the parent TLD. |

### 10.2 Operational priorities

1. **DNS/proxy policy:** start with the Critical + High + High-suitability set. Exclude high-collateral
   TLDs. Re-evaluate quarterly as annual data and live feeds change.
2. **New-registration monitoring:** focus on `.pro`, `.icu`, `.cfd`, `.cyou`, `.vip`, `.sbs`,
   `.shop`, `.top`, and the surge cohort (`.jp`, `.mobi`, `.garden`). Watch registrar concentration
   and bulk registration patterns.
3. **Free-hosting controls:** maintain platform-specific policies for `pages.dev`, `vercel.app`,
   `web.app`, `netlify.app`, `workers.dev`, `r2.dev`, `duckdns.org`, `github.io`, `webflow.io`,
   and `trycloudflare.com`. Prefer subdomain allowlists and abuse-reporting workflows.
4. **Payload/C2 detection:** use URLhaus/C2Intel indicators, URI-path patterns, and hosting-provider
   intelligence. Do not rely on TLD reputation for C2.
5. **Registrar/registry pressure:** use the malicious-registration share and volume data to
   prioritize outreach. `.bond` (99.0% malicious), `.club` (96.2%), `.cyou` (95.9%), `.xin`
   (95.6%), `.icu` (95.0%), and `.cfd` (95.1%) are strong candidates for registry-level action.
6. **Brand protection:** monitor lookalikes in high-risk TLDs, but remember that `.com` remains the
   largest absolute source. Allocate monitoring by expected exposure, not tier alone.

### 10.3 Candidate shortlist (validate first)

This is a validation shortlist, not a production blocklist. It includes Critical/High TLDs with
High or Medium blocklist suitability and excludes high-collateral namespaces such as `.com`, `.net`,
`.cn`, `.jp`, and `.ru`. The top 20 by risk rank are shown; the full list is in the CSV.

| TLD | Category | Tier | Suitability | Density/10k | Annual domains | Malicious share | Live domains | Confidence |
|---|---|---|---|---:|---:|---:|---:|---|
{chr(10).join('| ' + ' | '.join(str(x) for x in r) + ' |' for r in candidate_rows)}

Before deployment, validate: (1) legitimate business traffic to the namespace, (2) whether the
abuse is concentrated on a platform subdomain rather than the TLD, (3) current annual data versus
the live snapshot, and (4) legal/contractual constraints on blocking.

---

## 11. Limitations

- **Feed bias and false positives.** Phishing feeds aggregate different sources, have different
  freshness, and contain occasional false positives or stale entries. The union reduces blind spots
  but does not eliminate them.
- **Hostname vs registrable domain.** Feeds list hostnames; we collapse to registrable domains for
  TLD analysis. Subdomain-heavy campaigns can look much larger at the host level (see the `.ru`
  payload example).
- **Annual data lag.** The 2026 annual study covers May 2025–April 2026, while live feeds are from
  October 2026. Rapid changes can be missing or under-represented.
- **Early-year coverage is partial.** 2020 is a three-month study; 2022 has only partial ranks/scores;
  2021–2023 use top-5/top-10 tables. Persistence is a conservative lower bound.
- **Malicious-registration imputation.** When a TLD is not in the top-20 malicious-registration
  table, we impute 74%. This is a population average, not a TLD-specific measurement; it lowers
  confidence and can misstate the attacker/compromise split.
- **C2 sample size.** C2Intel provides only a few hundred domains, and historical captures are
  sparse. C2 findings are supporting signals, not a ranking driver.
- **Payload definition.** URLhaus includes malware distribution and compromised legitimate sites; it
  is not a pure staging or C2 feed.
- **Platform attribution.** Private-suffix detection depends on the Public Suffix List. New
  platforms, wildcard private suffixes, and IDN names may be missed or misclassified.
- **No registrar-level data in the live model.** Registrar concentration is discussed qualitatively;
  the risk score is TLD-level.
- **No ground truth.** There is no complete label of “malicious vs benign” for every domain. The
  rankings are evidence-weighted inferences, not measurements of every domain.

---

## 12. Reproducibility

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python scripts/collect.py          # current feeds + PSL + Tranco
python scripts/collect_history.py  # archived payload/C2 snapshots
python scripts/analyze.py          # risk scores, tiers, confidence
python scripts/charts.py           # figures
python scripts/report.py           # this report
```

Outputs:

- `data/processed/tld_risk_scores.csv` — full scored table
- `data/processed/tld_risk_scores.json` — scored table + model metadata
- `data/processed/live_tld_counts.csv` — current live counts by TLD
- `data/processed/platform_risk.csv` — private platform abuse
- `data/processed/historical_tld_summary.csv` — persistence metrics
- `data/processed/payload_history.csv` — archived payload TLD counts
- `data/processed/c2_history.csv` — archived C2 TLD counts
- `data/processed/feed_overlap.csv` — feed overlap matrix
- `reports/analysis_data.json` — report/chart input
- `reports/figures/` — charts

Raw feeds are stored under `data/raw/` and are gitignored for size and upstream-license reasons. The
snapshot manifest (`data/processed/snapshot_manifest.json`) records source URLs, SHA-256 hashes,
timestamps, and counts. The curated annual data is committed under `data/curated/`.

---

## Appendix A: Full scoring table

| Rank | TLD | Category | Tier | Score | Confidence | Density/10k | Annual domains | Malicious share | Persistence | Live domains | Payload | C2 | Blocklist suitability |
|---:|---|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---|
{chr(10).join('| ' + ' | '.join(str(x) for x in r) + ' |' for r in appendix_rows)}

## Appendix B: Data dictionary

| Column | Meaning |
|---|---|
| `risk_rank` | Order after tier and composite score |
| `category` | ccTLD, legacy gTLD, or new gTLD |
| `risk_tier` | Critical / High / Medium / Low, from density-led absolute rules |
| `risk_score` | 0–100 composite (density 35, volume 15, persistence 15, malicious share 15, payload 10, C2 5, momentum 5) |
| `confidence` | Evidence quality: High / Medium / Low |
| `record_scope` | annual+live, annual, annual-fallback+live, annual-fallback, live-only, historical-only |
| `annual_year` | Year of the annual metrics used (2026 preferred, then 2025/2024) |
| `annual_phishing_domains` | Domains reported for phishing in the annual study |
| `annual_phishing_score` | Phishing domains per 10,000 registered domains |
| `annual_malreg_share` | Maliciously registered phishing domains ÷ phishing domains |
| `years_top10_any` | Years in a top-10 volume or density table, 2020–2026 |
| `live_phishing_domains` | Unique registrable domains in the current live phishing union |
| `live_overrep` | Live phishing share ÷ Tranco top-1M share |
| `payload_domains` | Unique registrable domains in the current URLhaus-derived payload list |
| `c2_domains` | Unique registrable domains in the current C2Intel union |
| `tranco_domains` | Domains in the Tranco top-1M list |
| `platform_hosts_under_tld` | Phishing hosts on private platform suffixes under this TLD (excluded from live counts) |
| `blocklist_suitability` | High / Medium / Low based on Tranco collateral and platform concentration |
| `recommended_action` | Short policy guidance; not a substitute for business validation |

## Appendix C: Sources and licenses

| Source | Role | URL |
|---|---|---|
| Interisle Phishing Landscape 2020–2023 | Historical phishing TLD rankings | https://interisle.net/ |
| Cybercrime Information Center TLD tables 2024–2026 | Annual volume, density, malicious registration | https://www.cybercrimeinfocenter.org/ |
| OpenPhish | Live phishing URLs | https://openphish.com/ |
| Phishing Army | Aggregated phishing blocklist | https://phishing.army/ |
| Phishing.Database | Active phishing domains | https://github.com/mitchellkrogza/Phishing.Database |
| Spam404 | Phishing/malicious domain blocklist | https://github.com/Spam404/lists |
| malware-filter (phishing and URLhaus mirrors) | Filtered phishing and malware domains | https://gitlab.com/malware-filter |
| URLhaus / abuse.ch | Source data for the URLhaus mirror | https://urlhaus.abuse.ch/ |
| C2IntelFeeds | C2 domains | https://github.com/drb-ra/C2IntelFeeds |
| Tranco | Popularity baseline | https://tranco-list.eu/ |
| Public Suffix List | Namespace parsing | https://publicsuffix.org/ |
| Internet Archive Wayback Machine | Historical payload/C2 snapshots | https://web.archive.org/ |

**Licensing:** code in this repository is MIT-licensed. The derived aggregates and analysis are
provided under CC BY 4.0 with attribution. Upstream data remains subject to its own terms; raw feeds
are not redistributed. The Public Suffix List is MPL 2.0. Consult each source before redistributing
derived data.

**Attribution:** Interisle Consulting Group and the Cybercrime Information Center for the annual
registry data; abuse.ch/URLhaus, malware-filter, C2IntelFeeds, OpenPhish, Phishing Army,
Phishing.Database, Spam404, Tranco, and the Internet Archive for operational data.

---

*Report generated by `scripts/report.py`. Re-run the pipeline to refresh. This analysis is provided
for defensive security research and does not constitute legal advice or a guarantee of maliciousness.*
"""

    out = REPORT_DIR / "ANALYSIS.md"
    out.write_text(report, encoding="utf-8")
    print(f"wrote {out} ({len(report.splitlines())} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
