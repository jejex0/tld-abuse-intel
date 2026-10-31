#!/usr/bin/env python3
"""Collect current phishing, payload-delivery, and C2 feeds.

Raw feeds are stored under data/raw/<UTC date>/ and are intentionally ignored
by git (size and upstream licensing).  A manifest with hashes, counts, and
licensing pointers is written to data/processed/snapshot_manifest.json so the
derived analysis is reproducible.
"""

from __future__ import annotations

import argparse
import io
import shutil
import sys
import time
import zipfile
from pathlib import Path

import requests

from common import (
    PSL_PATH,
    PROCESSED_DIR,
    RAW_DIR,
    analyze_hosts,
    load_psl,
    load_tranco,
    read_hosts,
    sha256_file,
    utc_now_iso,
    write_csv,
    write_json,
)

SOURCES = [
    {
        "name": "openphish",
        "kind": "phishing",
        "format": "urls",
        "url": "https://openphish.com/feed.txt",
        "license": "OpenPhish public/community feed; see https://openphish.com/",
    },
    {
        "name": "phishing_army",
        "kind": "phishing",
        "format": "domains",
        "url": "https://phishing.army/download/phishing_army_blocklist_extended.txt",
        "license": "See https://phishing.army/",
    },
    {
        "name": "phishing_database",
        "kind": "phishing",
        "format": "domains",
        "url": "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt",
        "license": "See https://github.com/mitchellkrogza/Phishing.Database",
    },
    {
        "name": "spam404",
        "kind": "phishing",
        "format": "domains",
        "url": "https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt",
        "license": "See https://github.com/Spam404/lists",
    },
    {
        "name": "phishing_filter",
        "kind": "phishing",
        "format": "domains",
        "url": "https://malware-filter.gitlab.io/malware-filter/phishing-filter-domains.txt",
        "license": "CC0-1.0 via https://gitlab.com/malware-filter/phishing-filter",
    },
    {
        "name": "urlhaus_filter",
        "kind": "payload",
        "format": "domains",
        "url": "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains.txt",
        "license": "CC0-1.0 via https://gitlab.com/malware-filter/urlhaus-filter; source data URLhaus",
    },
    {
        "name": "c2intel_30d",
        "kind": "c2",
        "format": "csv_domain",
        "url": "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/domainC2s-30day-filter-abused.csv",
        "license": "See https://github.com/drb-ra/C2IntelFeeds",
    },
    {
        "name": "c2intel_90d",
        "kind": "c2",
        "format": "csv_domain",
        "url": "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/domainC2s-90day-filter-abused.csv",
        "license": "See https://github.com/drb-ra/C2IntelFeeds",
    },
    {
        "name": "c2intel_dns",
        "kind": "c2",
        "format": "csv_domain",
        "url": "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/DNSC2Domains.csv",
        "license": "See https://github.com/drb-ra/C2IntelFeeds",
    },
]

TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
USER_AGENT = "tld-abuse-intel/1.0 (defensive research; contact: repo owner)"


def fetch(session: requests.Session, url: str, dest: Path, attempts: int = 3) -> None:
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            with session.get(url, stream=True, timeout=120) as response:
                response.raise_for_status()
                dest.parent.mkdir(parents=True, exist_ok=True)
                with dest.open("wb") as fh:
                    for chunk in response.iter_content(chunk_size=1024 * 1024):
                        if chunk:
                            fh.write(chunk)
            if dest.stat().st_size == 0:
                raise RuntimeError("empty response")
            return
        except Exception as exc:  # noqa: BLE001 - network errors vary
            last_error = exc
            if attempt < attempts:
                time.sleep(2 * attempt)
    raise RuntimeError(f"download failed after {attempts} attempts: {last_error}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--date", default=utc_now_iso()[:10], help="snapshot date (UTC)")
    parser.add_argument("--refresh-psl", action="store_true", help="refresh the committed PSL before collection")
    parser.add_argument("--reuse", action="store_true", help="reuse existing raw files instead of downloading")
    parser.add_argument("--force", action="store_true", help="force all downloads even with --reuse")
    args = parser.parse_args()

    snapshot_dir = RAW_DIR / args.date
    snapshot_dir.mkdir(parents=True, exist_ok=True)
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT, "Accept-Encoding": "gzip, deflate"})

    if args.refresh_psl or not PSL_PATH.exists():
        print(f"[psl] downloading to {PSL_PATH}")
        fetch(session, "https://publicsuffix.org/list/public_suffix_list.dat", PSL_PATH)

    psl = load_psl()
    manifest = {
        "snapshot_date": args.date,
        "generated_at": utc_now_iso(),
        "psl": {
            "path": "data/reference/public_suffix_list.dat",
            "sha256": sha256_file(PSL_PATH),
        },
        "sources": [],
        "tranco": {},
        "errors": [],
    }

    ok_kinds: set[str] = set()
    host_sets: dict[str, set[str]] = {}
    for source in SOURCES:
        dest = snapshot_dir / (source["name"] + (".csv" if source["format"] == "csv_domain" else ".txt"))
        entry = dict(source, path=str(dest.relative_to(Path(__file__).resolve().parents[1])))
        reuse = args.reuse and not args.force and dest.exists() and dest.stat().st_size > 0
        try:
            if reuse:
                print(f"[feed] {source['name']} (reusing {dest.name})")
            else:
                print(f"[feed] {source['name']} <- {source['url']}")
                fetch(session, source["url"], dest)
            hosts = read_hosts(dest, csv_first=source["format"] == "csv_domain")
            host_sets[source["name"]] = hosts
            entry.update(
                fetched_at=utc_now_iso(),
                bytes=dest.stat().st_size,
                sha256=sha256_file(dest),
                lines=sum(1 for _ in dest.open("rb")),
                unique_hosts=len(hosts),
                error=None,
            )
            ok_kinds.add(source["kind"])
        except Exception as exc:  # noqa: BLE001
            entry.update(fetched_at=utc_now_iso(), error=str(exc), unique_hosts=0)
            manifest["errors"].append({"source": source["name"], "error": str(exc)})
            print(f"[warn] {source['name']}: {exc}", file=sys.stderr)
        manifest["sources"].append(entry)

    # Tranco popularity baseline (used for over-representation analysis).
    tranco_zip = snapshot_dir / "tranco-top-1m.csv.zip"
    tranco_csv = snapshot_dir / "tranco-top-1m.csv"
    try:
        if args.reuse and not args.force and tranco_csv.exists() and tranco_csv.stat().st_size > 0:
            print(f"[tranco] reusing {tranco_csv.name}")
        else:
            print(f"[tranco] {TRANCO_URL}")
            fetch(session, TRANCO_URL, tranco_zip)
            with zipfile.ZipFile(tranco_zip) as zf:
                member = next((n for n in zf.namelist() if n.endswith(".csv")), None)
                if not member:
                    raise RuntimeError("no CSV member in Tranco archive")
                with zf.open(member) as src, tranco_csv.open("wb") as dst:
                    shutil.copyfileobj(src, dst)
        counts, total = load_tranco(tranco_csv, psl)
        rows = [
            {"tld": tld, "domains": count, "share": round(count / total, 8)}
            for tld, count in sorted(counts.items(), key=lambda kv: kv[1], reverse=True)
        ]
        write_csv(PROCESSED_DIR / "tranco_tld_counts.csv", rows)
        manifest["tranco"] = {
            "url": TRANCO_URL,
            "fetched_at": utc_now_iso(),
            "sha256": sha256_file(tranco_zip),
            "domains": total,
            "tlds": len(counts),
        }
    except Exception as exc:  # noqa: BLE001
        manifest["errors"].append({"source": "tranco", "error": str(exc)})
        print(f"[warn] tranco: {exc}", file=sys.stderr)

    # Compact per-feed summary for the analysis/report layer.
    summary = []
    for entry in manifest["sources"]:
        if entry.get("error"):
            continue
        hosts = host_sets.get(entry["name"], set())
        stats = analyze_hosts(hosts, psl)
        summary.append(
            {
                "source": entry["name"],
                "kind": entry["kind"],
                "unique_hosts": stats["total_hosts"],
                "registered_hosts": stats["registered_hosts"],
                "platform_hosts": stats["platform_hosts_total"],
                "tlds_observed": len(stats["tld_domains"]),
                "platforms_observed": len(stats["platform_hosts"]),
            }
        )
    manifest["feed_summary"] = summary

    write_json(snapshot_dir / "manifest.json", manifest)
    write_json(PROCESSED_DIR / "snapshot_manifest.json", manifest)

    print("\nCollected:")
    for row in summary:
        print(
            f"  {row['source']:18} {row['kind']:8} hosts={row['unique_hosts']:>8,} "
            f"registered={row['registered_hosts']:>8,} platforms={row['platform_hosts']:>7,}"
        )

    missing = {"phishing", "payload"} - ok_kinds
    if missing:
        print(f"[error] missing required feed kinds: {sorted(missing)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
