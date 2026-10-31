#!/usr/bin/env python3
"""Reconstruct historical payload and C2 TLD distributions from Wayback snapshots.

The live URLhaus mirror and C2IntelFeeds are overwritten continuously, so their
history is recovered from Internet Archive captures.  Only aggregate counts are
committed; raw captures stay under data/raw/history/ (gitignored).
"""

from __future__ import annotations

import argparse
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone

import requests

from common import (
    PROCESSED_DIR,
    RAW_DIR,
    analyze_hosts,
    load_psl,
    read_hosts,
    utc_now_iso,
    write_csv,
    write_json,
)

PAYLOAD_URL = "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains.txt"
PAYLOAD_FALLBACK = [
    ("2023-03-15", "20230315003236"),
    ("2023-09-24", "20230924152237"),
    ("2024-02-22", "20240222230814"),
    ("2024-04-17", "20240417165956"),
    ("2024-12-20", "20241220084935"),
    ("2025-02-28", "20250228011524"),
    ("2025-04-11", "20250411215835"),
    ("2025-07-02", "20250702164101"),
    ("2025-09-10", "20250910101419"),
    ("2025-12-16", "20251216023205"),
    ("2026-07-10", "20260710114456"),
]
C2_ORIGINALS = [
    "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/domainC2s-30day-filter-abused.csv",
    "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/domainC2s-90day-filter-abused.csv",
]
C2_FALLBACK = [
    ("2025-08-15", "20250815083510", C2_ORIGINALS[0]),
    ("2025-09-20", "20250920121336", C2_ORIGINALS[0]),
    ("2026-03-02", "20260302040808", C2_ORIGINALS[0]),
]
USER_AGENT = "tld-abuse-intel/1.0 (defensive research)"
HISTORY_DIR = RAW_DIR / "history"


def get(session: requests.Session, url: str, attempts: int = 3) -> str:
    last: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            response = session.get(url, timeout=120)
            response.raise_for_status()
            return response.text
        except Exception as exc:  # noqa: BLE001
            last = exc
            if attempt < attempts:
                time.sleep(2 * attempt)
    raise RuntimeError(str(last))


def cdx(session: requests.Session, url: str, **params) -> list[list[str]]:
    payload = {"url": url, "output": "json", **params}
    response = session.get("https://web.archive.org/cdx/search/cdx", params=payload, timeout=120)
    response.raise_for_status()
    if response.text.strip().startswith("["):
        import json

        rows = json.loads(response.text)
        return rows[1:] if rows else []
    return []


def payload_snapshots(session: requests.Session) -> list[tuple[str, str, str]]:
    try:
        rows = cdx(
            session,
            PAYLOAD_URL,
            **{
                "from": "2023",
                "to": datetime.now(timezone.utc).strftime("%Y"),
                "collapse": "timestamp:6",
                "filter": "statuscode:200",
                "fl": "timestamp,original,statuscode",
            },
        )
    except Exception as exc:  # noqa: BLE001
        print(f"[warn] CDX payload query failed: {exc}", file=sys.stderr)
        rows = []
    snapshots = []
    for row in rows:
        if len(row) < 2:
            continue
        ts = row[0]
        date = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"
        snapshots.append((date, ts, f"https://web.archive.org/web/{ts}id_/{PAYLOAD_URL}"))
    if not snapshots:
        snapshots = [
            (date, ts, f"https://web.archive.org/web/{ts}id_/{PAYLOAD_URL}")
            for date, ts in PAYLOAD_FALLBACK
        ]
    # De-duplicate by month, keeping the latest capture in each month.
    by_month: dict[str, tuple[str, str, str]] = {}
    for item in snapshots:
        by_month[item[0][:7]] = item
    return sorted(by_month.values())


def c2_snapshots(session: requests.Session) -> list[tuple[str, str, str]]:
    rows: list[list[str]] = []
    try:
        response = session.get(
            "https://web.archive.org/cdx/search/cdx",
            params={
                "url": "raw.githubusercontent.com/drb-ra/C2IntelFeeds/",
                "matchType": "prefix",
                "output": "json",
                "from": "2024",
                "to": datetime.now(timezone.utc).strftime("%Y"),
                "collapse": "urlkey",
                "fl": "timestamp,original",
                "limit": "500",
            },
            timeout=120,
        )
        response.raise_for_status()
        import json

        data = json.loads(response.text)
        rows = data[1:] if data else []
    except Exception as exc:  # noqa: BLE001
        print(f"[warn] CDX C2 query failed: {exc}", file=sys.stderr)
    snaps = []
    for row in rows:
        if len(row) < 2:
            continue
        ts, original = row[0], row[1].replace("&quot;", "")
        if "domainC2s" not in original or "filter-abused" not in original:
            continue
        canonical = next((o for o in C2_ORIGINALS if original.endswith(o.split("/feeds/")[-1])), None)
        if not canonical:
            continue
        date = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"
        snaps.append((date, ts, f"https://web.archive.org/web/{ts}id_/{canonical}"))
    if not snaps:
        snaps = [(d, ts, f"https://web.archive.org/web/{ts}id_/{orig}") for d, ts, orig in C2_FALLBACK]
    else:
        existing_months = {s[0][:7] for s in snaps}
        for d, ts, orig in C2_FALLBACK:
            if d[:7] not in existing_months:
                snaps.append((d, ts, f"https://web.archive.org/web/{ts}id_/{orig}"))
    by_month: dict[str, tuple[str, str, str]] = {}
    for item in snaps:
        by_month[item[0][:7]] = item
    return sorted(by_month.values())


def process_snapshot(
    kind: str, date: str, ts: str, url: str, session: requests.Session, psl, reuse: bool = False
) -> dict | None:
    raw_path = HISTORY_DIR / kind / f"{date}_{ts}.txt"
    if reuse and raw_path.exists() and raw_path.stat().st_size > 0:
        text = raw_path.read_text(encoding="utf-8", errors="ignore")
        print(f"[{kind}] {date} (reusing {raw_path.name})")
    else:
        try:
            text = get(session, url)
        except Exception as exc:  # noqa: BLE001
            print(f"[warn] {kind} {date} fetch failed: {exc}", file=sys.stderr)
            return None
    if kind == "payload":
        if "# Title:" not in text[:1000] or len(text) < 5000:
            print(f"[warn] {kind} {date} looks invalid ({len(text)} bytes)", file=sys.stderr)
            return None
    else:
        if len(text) < 50:
            print(f"[warn] {kind} {date} looks empty", file=sys.stderr)
            return None
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    if not raw_path.exists():
        raw_path.write_text(text, encoding="utf-8", errors="ignore")
    hosts = read_hosts(raw_path, csv_first=(kind == "c2"))
    if not hosts:
        return None
    stats = analyze_hosts(hosts, psl)
    return {
        "kind": kind,
        "date": date,
        "timestamp": ts,
        "url": url,
        "hosts": stats["total_hosts"],
        "registered_hosts": stats["registered_hosts"],
        "platform_hosts": stats["platform_hosts_total"],
        "tld_domains": stats["tld_domains"],
        "tld_hosts": stats["tld_hosts"],
        "platform_domains": stats["platform_domains"],
        "platform_breakdown": stats["platform_hosts"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=24, help="maximum snapshots per feed")
    parser.add_argument("--reuse", action="store_true", help="reuse previously downloaded raw snapshots")
    parser.add_argument("--only", choices=["payload", "c2"], help="process only one feed type")
    args = parser.parse_args()

    HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    psl = load_psl()
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT, "Accept-Encoding": "gzip, deflate"})

    payload = []
    if args.only in (None, "payload"):
        for date, ts, url in payload_snapshots(session)[-args.limit:]:
            print(f"[payload] {date} {ts}")
            result = process_snapshot("payload", date, ts, url, session, psl, reuse=args.reuse)
            if result:
                payload.append(result)
            time.sleep(0.5)

    c2 = []
    if args.only in (None, "c2"):
        for date, ts, url in c2_snapshots(session)[-args.limit:]:
            print(f"[c2] {date} {ts}")
            result = process_snapshot("c2", date, ts, url, session, psl, reuse=args.reuse)
            if result:
                c2.append(result)
            time.sleep(0.5)

    payload_rows = []
    payload_platform_rows = []
    for snap in payload:
        for tld, count in snap["tld_domains"].items():
            payload_rows.append(
                {
                    "snapshot_date": snap["date"],
                    "tld": tld,
                    "registered_domains": count,
                    "hosts": snap["tld_hosts"].get(tld, 0),
                }
            )
        for platform, count in snap["platform_breakdown"].items():
            payload_platform_rows.append(
                {
                    "snapshot_date": snap["date"],
                    "platform_suffix": platform,
                    "hosts": count,
                    "registered_subdomains": snap["platform_domains"].get(platform, 0),
                }
            )
    c2_rows = []
    for snap in c2:
        for tld, count in snap["tld_domains"].items():
            c2_rows.append(
                {
                    "snapshot_date": snap["date"],
                    "tld": tld,
                    "registered_domains": count,
                    "hosts": snap["tld_hosts"].get(tld, 0),
                }
            )

    if payload_rows:
        write_csv(
            PROCESSED_DIR / "payload_history.csv",
            sorted(payload_rows, key=lambda r: (r["snapshot_date"], -r["registered_domains"])),
            ["snapshot_date", "tld", "registered_domains", "hosts"],
        )
    if payload_platform_rows:
        write_csv(
            PROCESSED_DIR / "payload_platform_history.csv",
            sorted(payload_platform_rows, key=lambda r: (r["snapshot_date"], -r["hosts"])),
            ["snapshot_date", "platform_suffix", "hosts", "registered_subdomains"],
        )
    if c2_rows:
        write_csv(
            PROCESSED_DIR / "c2_history.csv",
            sorted(c2_rows, key=lambda r: (r["snapshot_date"], -r["registered_domains"])),
            ["snapshot_date", "tld", "registered_domains", "hosts"],
        )

    manifest_path = PROCESSED_DIR / "history_manifest.json"
    manifest = {}
    if manifest_path.exists():
        import json

        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["generated_at"] = utc_now_iso()
    if payload:
        manifest["payload_snapshots"] = [
            {
                "date": s["date"],
                "timestamp": s["timestamp"],
                "url": s["url"],
                "hosts": s["hosts"],
                "registered_hosts": s["registered_hosts"],
                "platform_hosts": s["platform_hosts"],
            }
            for s in payload
        ]
    if c2:
        manifest["c2_snapshots"] = [
            {
                "date": s["date"],
                "timestamp": s["timestamp"],
                "url": s["url"],
                "hosts": s["hosts"],
                "registered_hosts": s["registered_hosts"],
                "platform_hosts": s["platform_hosts"],
            }
            for s in c2
        ]
    write_json(manifest_path, manifest)
    print(
        f"\nProcessed {len(payload)} payload snapshots and {len(c2)} C2 snapshots; "
        f"{len(payload_rows)} payload rows, {len(c2_rows)} C2 rows."
    )
    if args.only in (None, "payload") and not payload and not (PROCESSED_DIR / "payload_history.csv").exists():
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
