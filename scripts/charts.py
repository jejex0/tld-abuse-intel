#!/usr/bin/env python3
"""Generate static charts for the TLD abuse report."""

from __future__ import annotations

import csv
import json
import math
from collections import defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.colors import LinearSegmentedColormap

from common import CURATED_DIR, FIGURES_DIR, PROCESSED_DIR, REPORT_DIR

TIER_COLORS = {
    "Critical": "#b2182b",
    "High": "#ef8a62",
    "Medium": "#fddbc7",
    "Low": "#67a9cf",
}
CONF_COLORS = {"High": "#1b7837", "Medium": "#f0ad4e", "Low": "#999999"}
GRID = "#d9d9d9"
TEXT = "#222222"
MUTED = "#666666"


def load_csv(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def style_axes(ax, title: str, subtitle: str | None = None):
    ax.set_title(title, fontsize=14, fontweight="bold", color=TEXT, loc="left", pad=14)
    if subtitle:
        ax.text(0.0, 1.01, subtitle, transform=ax.transAxes, fontsize=9, color=MUTED, va="bottom")
    ax.grid(axis="both", color=GRID, linewidth=0.6, alpha=0.7)
    ax.set_axisbelow(True)
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    for spine in ("left", "bottom"):
        ax.spines[spine].set_color("#999999")
    ax.tick_params(colors=TEXT, labelsize=9)


def save(fig, name: str):
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    path = FIGURES_DIR / name
    fig.savefig(path, dpi=170, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"  wrote {path.relative_to(REPORT_DIR.parent)}")


def chart_top_volume(rows: list[dict]):
    data = [r for r in rows if str(r.get("annual_year")) == "2026" and r.get("annual_phishing_domains")]
    data = sorted(data, key=lambda r: int(r["annual_phishing_domains"]), reverse=True)[:15]
    if not data:
        return
    labels = [r["tld"] for r in data]
    values = [int(r["annual_phishing_domains"]) for r in data]
    colors = [TIER_COLORS.get(r["risk_tier"], "#999999") for r in data]
    fig, ax = plt.subplots(figsize=(10.5, 6.4))
    bars = ax.barh(labels[::-1], values[::-1], color=colors[::-1], edgecolor="white", height=0.72)
    for bar, r in zip(bars, data[::-1]):
        score = r.get("annual_phishing_score") or "-"
        ax.text(bar.get_width() * 1.01 + max(values) * 0.005, bar.get_y() + bar.get_height() / 2,
                f"{int(bar.get_width()):,}  ({score}/10k)", va="center", fontsize=8.5, color=TEXT)
    ax.set_xlim(0, max(values) * 1.24)
    ax.set_xlabel("Phishing domains reported, May 2025 – April 2026", fontsize=10, color=TEXT)
    style_axes(ax, "Most abused TLDs by volume (2026 annual study)",
               "Bar color = risk tier; label shows volume and phishing domains per 10,000 registered domains")
    save(fig, "fig01_top_volume_2026.png")


def chart_top_density(rows: list[dict]):
    data = [r for r in rows if str(r.get("annual_year")) == "2026" and r.get("annual_phishing_score")]
    data = sorted(data, key=lambda r: float(r["annual_phishing_score"]), reverse=True)[:15]
    if not data:
        return
    labels = [r["tld"] for r in data]
    values = [float(r["annual_phishing_score"]) for r in data]
    colors = [TIER_COLORS.get(r["risk_tier"], "#999999") for r in data]
    fig, ax = plt.subplots(figsize=(10.5, 6.4))
    bars = ax.barh(labels[::-1], values[::-1], color=colors[::-1], edgecolor="white", height=0.72)
    for bar, r in zip(bars, data[::-1]):
        vol = r.get("annual_phishing_domains") or 0
        ax.text(bar.get_width() * 1.01 + max(values) * 0.005, bar.get_y() + bar.get_height() / 2,
                f"{float(bar.get_width()):,.1f}/10k  ({int(vol):,} domains)", va="center", fontsize=8.5, color=TEXT)
    ax.set_xlim(0, max(values) * 1.24)
    ax.set_xlabel("Phishing domains per 10,000 registered domains (abuse density)", fontsize=10, color=TEXT)
    style_axes(ax, "Highest abuse density by TLD (2026 annual study)",
               "Density normalizes for TLD size; small TLDs can outrank .com by orders of magnitude")
    save(fig, "fig02_top_density_2026.png")


def chart_risk_matrix(rows: list[dict]):
    data = [r for r in rows if str(r.get("annual_year")) == "2026" and r.get("annual_phishing_score") and r.get("annual_phishing_domains")]
    if len(data) < 5:
        return
    fig, ax = plt.subplots(figsize=(11, 7))
    for r in data:
        x = float(r["annual_phishing_score"])
        y = int(r["annual_phishing_domains"])
        size = 40 + 2.8 * math.sqrt(max(int(r.get("live_phishing_domains") or 0), 1))
        ax.scatter(x, y, s=size, color=TIER_COLORS.get(r["risk_tier"], "#999999"),
                   alpha=0.75, edgecolor="white", linewidth=0.8, zorder=3)
    ax.set_xscale("log")
    ax.set_yscale("log")
    for cutoff in (100, 400, 1000):
        ax.axvline(cutoff, color="#bbbbbb", linestyle="--", linewidth=0.8, zorder=1)
        ax.text(cutoff, ax.get_ylim()[1] * 0.92, f"{cutoff}/10k", fontsize=7.5, color=MUTED, ha="center")
    for cutoff in (10000, 50000):
        ax.axhline(cutoff, color="#bbbbbb", linestyle=":", linewidth=0.8, zorder=1)
        ax.text(ax.get_xlim()[0] * 1.05, cutoff * 1.05, f"{cutoff:,} domains", fontsize=7.5, color=MUTED)
    # Annotate the highest-risk and highest-volume records, avoiding duplicates.
    annotate = sorted(data, key=lambda r: float(r["risk_score"]), reverse=True)[:14]
    annotate += sorted(data, key=lambda r: int(r["annual_phishing_domains"]), reverse=True)[:5]
    seen = set()
    for r in annotate:
        if r["tld"] in seen:
            continue
        seen.add(r["tld"])
        ax.annotate(r["tld"], (float(r["annual_phishing_score"]), int(r["annual_phishing_domains"])),
                    textcoords="offset points", xytext=(5, 4), fontsize=8, color=TEXT)
    ax.set_xlabel("Abuse density (phishing domains per 10,000 registrations, log scale)", fontsize=10)
    ax.set_ylabel("Annual phishing domains (log scale)", fontsize=10)
    style_axes(ax, "Risk matrix: density vs. volume (2026 annual data)",
               "Bubble size ~ live phishing volume; color = risk tier. Top-right is the highest-priority quadrant.")
    save(fig, "fig03_risk_matrix.png")


def chart_history_scores(rows: list[dict], curated: list[dict]):
    selected = [r["tld"] for r in rows if str(r.get("annual_year")) == "2026"][:10]
    for mandatory in ("com", "top", "xyz", "shop", "cyou"):
        if mandatory in {r["tld"] for r in rows} and mandatory not in selected:
            selected.append(mandatory)
    selected = selected[:10]
    series: dict[str, dict[int, float]] = defaultdict(dict)
    for row in curated:
        if row["tld"] in selected and row.get("phishing_score"):
            series[row["tld"]][int(row["year"])] = float(row["phishing_score"])
    if not series:
        return
    years = [2024, 2025, 2026]
    fig, ax = plt.subplots(figsize=(11, 6.2))
    palette = ["#b2182b", "#d6604d", "#f4a582", "#92c5de", "#4393c3", "#2166ac",
               "#5aae61", "#9970ab", "#c2a5cf", "#762a83"]
    for i, tld in enumerate(selected):
        ys = [series[tld].get(y) for y in years]
        if not any(v is not None for v in ys):
            continue
        ax.plot(years, ys, marker="o", linewidth=2, markersize=6,
                color=palette[i % len(palette)], label=tld)
    ax.set_yscale("log")
    ax.set_xticks(years)
    ax.set_xticklabels(["2024\n(May 2023–Apr 2024)", "2025\n(May 2024–Apr 2025)", "2026\n(May 2025–Apr 2026)"])
    ax.set_ylabel("Phishing domains per 10,000 registered domains (log scale)")
    style_axes(ax, "Abuse density trends for persistent TLDs",
               "Annual Interisle / Cybercrime Information Center data; gaps mean the TLD did not appear in the top-20 score table")
    ax.legend(ncol=2, fontsize=8.5, frameon=False, loc="upper left", bbox_to_anchor=(1.0, 1.0))
    save(fig, "fig04_density_trends.png")


def chart_payload_history():
    rows = load_csv(PROCESSED_DIR / "payload_history.csv")
    if not rows:
        return
    by_tld: dict[str, dict[str, int]] = defaultdict(dict)
    totals: dict[str, int] = defaultdict(int)
    for row in rows:
        try:
            value = int(row["registered_domains"])
        except (KeyError, ValueError):
            continue
        by_tld[row["tld"]][row["snapshot_date"]] = value
        totals[row["tld"]] += value
    top = [t for t, _ in sorted(totals.items(), key=lambda kv: kv[1], reverse=True)[:7]]
    dates = sorted({r["snapshot_date"] for r in rows})
    fig, ax = plt.subplots(figsize=(11.5, 6.2))
    palette = ["#b2182b", "#ef8a62", "#2166ac", "#67a9cf", "#5aae61", "#9970ab", "#c51b7d"]
    for i, tld in enumerate(top):
        ys = [by_tld[tld].get(d) for d in dates]
        ax.plot(dates, ys, marker="o", markersize=4, linewidth=1.8,
                color=palette[i % len(palette)], label=tld)
    ax.set_yscale("log")
    ax.set_ylabel("Registered domains in URLhaus payload blocklist (log scale)")
    ax.tick_params(axis="x", rotation=45)
    style_axes(ax, "Payload-delivery TLD trends from archived URLhaus snapshots",
               "Each point is an Internet Archive capture of the URLhaus domain blocklist; private hosting platforms excluded")
    ax.legend(ncol=2, fontsize=8.5, frameon=False, loc="upper left", bbox_to_anchor=(1.0, 1.0))
    # Annotate the largest single-snapshot spike without colliding with the title.
    spikes = [(tld, d, v) for tld, series in by_tld.items() for d, v in series.items()]
    if spikes:
        tld, date, value = max(spikes, key=lambda x: x[2])
        ax.annotate(
            f"{tld} spike: {value:,}\n({date})",
            xy=(date, value),
            xytext=(0.42, 0.80),
            textcoords="axes fraction",
            fontsize=8,
            color="#b2182b",
            arrowprops={"arrowstyle": "->", "color": "#b2182b", "linewidth": 0.8},
        )
    save(fig, "fig05_payload_history.png")


def chart_platform_history():
    rows = load_csv(PROCESSED_DIR / "payload_platform_history.csv")
    if not rows:
        return
    by_platform: dict[str, dict[str, int]] = defaultdict(dict)
    totals: dict[str, int] = defaultdict(int)
    for row in rows:
        try:
            value = int(row["hosts"])
        except (KeyError, ValueError):
            continue
        by_platform[row["platform_suffix"]][row["snapshot_date"]] = value
        totals[row["platform_suffix"]] += value
    top = [p for p, _ in sorted(totals.items(), key=lambda kv: kv[1], reverse=True)[:7]]
    dates = sorted({r["snapshot_date"] for r in rows})
    fig, ax = plt.subplots(figsize=(11.5, 6.2))
    palette = ["#b2182b", "#ef8a62", "#2166ac", "#67a9cf", "#5aae61", "#9970ab", "#c51b7d"]
    for i, platform in enumerate(top):
        ys = [by_platform[platform].get(d) for d in dates]
        ax.plot(dates, ys, marker="o", markersize=4, linewidth=1.8,
                color=palette[i % len(palette)], label=platform)
    ax.set_yscale("log")
    ax.set_ylabel("Hosts in URLhaus payload blocklist (log scale)")
    ax.tick_params(axis="x", rotation=45)
    style_axes(ax, "Free-hosting and dynamic-DNS platforms in archived payload lists",
               "Private suffixes are aggregated separately from registered TLDs; counts can spike during bulk campaigns")
    ax.legend(ncol=2, fontsize=8.5, frameon=False, loc="upper left", bbox_to_anchor=(1.0, 1.0))
    save(fig, "fig06_payload_platforms.png")


def chart_c2(analysis: dict):
    rows = analysis.get("top_by_c2", [])
    rows = [r for r in rows if int(r.get("c2_domains") or 0) > 0][:12]
    if not rows:
        return
    labels = [r["tld"] for r in rows]
    values = [int(r["c2_domains"]) for r in rows]
    colors = [TIER_COLORS.get(r["risk_tier"], "#999999") for r in rows]
    fig, ax = plt.subplots(figsize=(9.5, 5.4))
    bars = ax.bar(labels, values, color=colors, edgecolor="white")
    for bar, v in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.6, str(v),
                ha="center", fontsize=8.5, color=TEXT)
    ax.set_ylabel("C2 domains observed (90-day feed union)")
    style_axes(ax, "C2 infrastructure by TLD",
               f"Sample: {analysis['counts']['c2_hosts']} C2 hosts / {analysis['counts']['c2_registered_domains']} registered domains; small-sample signal only")
    save(fig, "fig07_c2_tlds.png")


def chart_platforms(analysis: dict):
    rows = [r for r in analysis.get("platforms", []) if r.get("live_phishing_hosts", 0) > 0][:15]
    if not rows:
        return
    labels = [r["platform_suffix"] for r in rows]
    values = [r["live_phishing_hosts"] for r in rows]
    fig, ax = plt.subplots(figsize=(10.5, 6.4))
    bars = ax.barh(labels[::-1], values[::-1], color="#7b3294", edgecolor="white", height=0.72)
    for bar, r in zip(bars, rows[::-1]):
        ax.text(bar.get_width() + max(values) * 0.008, bar.get_y() + bar.get_height() / 2,
                f"{int(bar.get_width()):,}  ({r['share_of_live_phishing_hosts_pct']:.1f}%)",
                va="center", fontsize=8.5, color=TEXT)
    ax.set_xlim(0, max(values) * 1.25)
    ax.set_xlabel("Live phishing hostnames on the private namespace")
    style_axes(ax, "Free-hosting / dynamic-DNS abuse (separate from TLD registration)",
               "Platform suffixes are excluded from the TLD risk counts to avoid inflating parent TLDs")
    save(fig, "fig08_platform_abuse.png")


def chart_feed_overlap(analysis: dict):
    rows = analysis.get("feed_overlap", [])
    if not rows:
        return
    names = sorted({r["feed_a"] for r in rows} | {r["feed_b"] for r in rows})
    matrix = [[0.0] * len(names) for _ in names]
    for i, name in enumerate(names):
        matrix[i][i] = 100.0
    for row in rows:
        i, j = names.index(row["feed_a"]), names.index(row["feed_b"])
        matrix[i][j] = matrix[j][i] = float(row["jaccard_pct"])
    fig, ax = plt.subplots(figsize=(8.2, 6.6))
    cmap = LinearSegmentedColormap.from_list("overlap", ["#f7fbff", "#c6dbef", "#6baed6", "#2171b5", "#08306b"])
    im = ax.imshow(matrix, cmap=cmap, vmin=0, vmax=max(100.0, max(max(r) for r in matrix)))
    ax.set_xticks(range(len(names)))
    ax.set_yticks(range(len(names)))
    ax.set_xticklabels(names, rotation=35, ha="right", fontsize=8.5)
    ax.set_yticklabels(names, fontsize=8.5)
    for i in range(len(names)):
        for j in range(len(names)):
            val = matrix[i][j]
            ax.text(j, i, f"{val:.1f}", ha="center", va="center", fontsize=7.5,
                    color="white" if val > 40 else TEXT)
    ax.set_title("Hostname overlap between phishing feeds (Jaccard, %)",
                 fontsize=14, fontweight="bold", color=TEXT, loc="left", pad=14)
    ax.text(0.0, 1.01, "Low overlap means the union adds coverage; high overlap means redundant sources",
            transform=ax.transAxes, fontsize=9, color=MUTED, va="bottom")
    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    save(fig, "fig09_feed_overlap.png")


def chart_tier_confidence(analysis: dict):
    tiers = ["Critical", "High", "Medium", "Low"]
    confs = ["High", "Medium", "Low"]
    rows = analysis.get("risk_rows", [])
    counts = {c: [sum(1 for r in rows if r["risk_tier"] == t and r["confidence"] == c) for t in tiers] for c in confs}
    fig, ax = plt.subplots(figsize=(9.5, 5.6))
    bottom = [0] * len(tiers)
    for conf in confs:
        values = counts[conf]
        bars = ax.bar(tiers, values, bottom=bottom, color=CONF_COLORS[conf], edgecolor="white", label=f"{conf} confidence")
        for bar, v in zip(bars, values):
            if v:
                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_y() + bar.get_height() / 2,
                        str(v), ha="center", va="center", fontsize=9, color="white" if conf != "Medium" else TEXT)
        bottom = [b + v for b, v in zip(bottom, values)]
    ax.set_ylabel("Number of TLDs")
    style_axes(ax, "Risk tiers and evidence confidence",
               "Risk tier reflects abuse severity; confidence reflects data coverage and corroboration")
    ax.legend(frameon=False, fontsize=9)
    save(fig, "fig10_tier_confidence.png")


def chart_live_vs_tranco(analysis: dict):
    rows = [r for r in analysis.get("risk_rows", []) if r.get("live_phishing_share") and r.get("tranco_share")]
    if len(rows) < 5:
        return
    fig, ax = plt.subplots(figsize=(10.5, 6.8))
    for r in rows:
        x = max(float(r["tranco_share"]) * 100, 1e-5)
        y = max(float(r["live_phishing_share"]) * 100, 1e-5)
        ax.scatter(x, y, s=55, color=TIER_COLORS.get(r["risk_tier"], "#999999"),
                   alpha=0.8, edgecolor="white", linewidth=0.7, zorder=3)
    lims = [1e-5, 100]
    ax.plot(lims, lims, color="#999999", linestyle="--", linewidth=0.9, label="parity")
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlim(1e-5, 100)
    ax.set_ylim(1e-5, 100)
    ax.set_xlabel("Share of Tranco top-1M domains (%) — popularity baseline", fontsize=10)
    ax.set_ylabel("Share of live phishing registrations (%)", fontsize=10)
    annotate = sorted(rows, key=lambda r: float(r.get("live_overrep") or 0), reverse=True)[:10]
    seen = set()
    for i, r in enumerate(annotate):
        if r["tld"] in seen:
            continue
        seen.add(r["tld"])
        offset = (6, 5) if i % 2 == 0 else (6, -11)
        ax.annotate(r["tld"], (max(float(r["tranco_share"]) * 100, 1e-5), max(float(r["live_phishing_share"]) * 100, 1e-5)),
                    textcoords="offset points", xytext=offset, fontsize=8, color=TEXT)
    style_axes(ax, "Over-representation: phishing share vs. benign popularity",
               "Points above the parity line are over-represented in phishing; distance above the line is the over-representation index")
    ax.legend(frameon=False, fontsize=9, loc="upper left")
    save(fig, "fig11_live_vs_tranco.png")


def chart_persistence(analysis: dict):
    rows = analysis.get("history", {}).get("tld_summary", [])[:15]
    if not rows:
        return
    risk = {r["tld"]: r for r in analysis.get("risk_rows", [])}
    labels = [r["tld"] for r in rows]
    values = [r["years_top10_any"] for r in rows]
    colors = [TIER_COLORS.get(risk.get(r["tld"], {}).get("risk_tier"), "#bdbdbd") for r in rows]
    fig, ax = plt.subplots(figsize=(10.5, 6.2))
    bars = ax.barh(labels[::-1], values[::-1], color=colors[::-1], edgecolor="white", height=0.72)
    for bar, v in zip(bars, values[::-1]):
        ax.text(bar.get_width() + 0.05, bar.get_y() + bar.get_height() / 2, str(v),
                va="center", fontsize=8.5, color=TEXT)
    ax.set_xlim(0, 7.6)
    ax.set_xlabel("Years in top-10 by volume or density (2020–2026)")
    style_axes(ax, "Historical persistence of abused TLDs",
               "Gray bars are historical namespaces no longer in the current risk set; color = current risk tier")
    save(fig, "fig12_persistence.png")


def main():
    analysis_path = REPORT_DIR / "analysis_data.json"
    if not analysis_path.exists():
        raise SystemExit("reports/analysis_data.json not found; run scripts/analyze.py first.")
    analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
    rows = analysis.get("risk_rows", [])
    curated = load_csv(CURATED_DIR / "phishing_tld_history.csv")

    print("Generating charts:")
    chart_top_volume(rows)
    chart_top_density(rows)
    chart_risk_matrix(rows)
    chart_history_scores(rows, curated)
    chart_payload_history()
    chart_platform_history()
    chart_c2(analysis)
    chart_platforms(analysis)
    chart_feed_overlap(analysis)
    chart_tier_confidence(analysis)
    chart_live_vs_tranco(analysis)
    chart_persistence(analysis)


if __name__ == "__main__":
    main()
