"""Shared helpers for the TLD abuse intelligence pipeline.

The module deliberately uses only the Python standard library plus requests
(only collectors need requests).  Keeping parsing logic here makes the
collector, analyzer, and tests share the exact same Public Suffix List rules.
"""

from __future__ import annotations

import csv
import hashlib
import ipaddress
import json
import math
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
RAW_DIR = DATA_DIR / "raw"
PROCESSED_DIR = DATA_DIR / "processed"
CURATED_DIR = DATA_DIR / "curated"
REFERENCE_DIR = DATA_DIR / "reference"
REPORT_DIR = ROOT / "reports"
FIGURES_DIR = REPORT_DIR / "figures"
PSL_PATH = REFERENCE_DIR / "public_suffix_list.dat"

LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


class PublicSuffixList:
    """Minimal Public Suffix List implementation.

    Rules are kept separate for the ICANN and PRIVATE sections so callers can
    distinguish a real top-level domain (e.g. ``dev`` for ``pages.dev``) from a
    privately operated namespace (e.g. ``pages.dev``).
    """

    def __init__(self, path: Path | str = PSL_PATH):
        self.path = Path(path)
        self.icann = _RuleSet()
        self.private = _RuleSet()
        self._load()
        combined = _RuleSet()
        combined.exact = self.icann.exact | self.private.exact
        combined.wildcards = self.icann.wildcards | self.private.wildcards
        combined.exceptions = self.icann.exceptions | self.private.exceptions
        self._combined = combined

    def _load(self) -> None:
        in_private = False
        with self.path.open("r", encoding="utf-8", errors="ignore") as fh:
            for raw in fh:
                line = raw.strip()
                if not line:
                    continue
                if line.startswith("// ===BEGIN PRIVATE DOMAINS==="):
                    in_private = True
                    continue
                if line.startswith("//"):
                    continue
                target = self.private if in_private else self.icann
                if line.startswith("!"):
                    target.exceptions.add(line[1:].lower())
                elif line.startswith("*."):
                    target.wildcards.add(line[2:].lower())
                else:
                    target.exact.add(line.lower())

    def _rules(self, include_private: bool) -> "_RuleSet":
        return self._combined if include_private else self.icann

    def suffix(self, host: str, include_private: bool = False) -> str:
        rules = self._rules(include_private)
        labels = host.split(".")
        for n in range(len(labels), 0, -1):
            candidate = ".".join(labels[-n:])
            if candidate in rules.exceptions:
                return ".".join(labels[-(n - 1):]) if n > 1 else labels[-1]
            if candidate in rules.exact:
                return candidate
            if n >= 2 and ".".join(labels[-(n - 1):]) in rules.wildcards:
                return candidate
        return labels[-1]

    def root_tld(self, host: str) -> str:
        return self.suffix(host, include_private=False).split(".")[-1]

    def platform_suffix(self, host: str) -> str | None:
        full = self.suffix(host, include_private=True)
        icann = self.suffix(host, include_private=False)
        return full if full != icann else None

    def registrable_domain(self, host: str) -> str:
        return self.registrable_from_suffix(host, self.suffix(host, include_private=True))

    @staticmethod
    def registrable_from_suffix(host: str, suffix: str) -> str:
        labels = host.split(".")
        n = len(suffix.split("."))
        return ".".join(labels[-(n + 1):]) if len(labels) > n else suffix


class _RuleSet:
    __slots__ = ("exact", "wildcards", "exceptions")

    def __init__(self) -> None:
        self.exact: set[str] = set()
        self.wildcards: set[str] = set()
        self.exceptions: set[str] = set()


def normalize_host(value: str) -> str | None:
    """Normalize one feed line into a lowercase DNS hostname.

    Handles plain domains, URLs, adblock ``||domain^`` entries, hosts-file
    entries, wildcard prefixes, ports, and quoted CSV fields.  IP addresses and
    malformed names are rejected.
    """

    if not value:
        return None
    line = value.strip().strip("\ufeff")
    if not line or line.startswith("#") or line.startswith(";"):
        return None
    if "[" in line or "]" in line:
        return None

    # Adblock-style network filter: ||example.com^
    if line.startswith("||"):
        line = line[2:].split("^")[0]

    # Hosts-file line: 0.0.0.0 example.com
    parts = line.split()
    if len(parts) > 1:
        try:
            ipaddress.ip_address(parts[0])
            line = parts[1]
        except ValueError:
            line = parts[0]

    line = line.strip().strip('"').strip("'")

    if "://" in line:
        host = urlsplit(line).hostname
    elif "/" in line:
        try:
            host = urlsplit("//" + line).hostname
        except ValueError:
            return None
    else:
        host = line

    if not host:
        return None
    host = host.strip().lower().rstrip(".")
    host = host.removeprefix("*.").lstrip(".")
    if not host or "/" in host:
        return None

    if host.startswith("["):
        return None
    if ":" in host:
        host = host.split(":", 1)[0]
    if not host or "." not in host:
        return None
    # Fast IPv4 rejection without paying exception overhead for every domain.
    if host.replace(".", "").isdigit():
        return None

    if len(host) > 253 or not all(LABEL_RE.match(label) for label in host.split(".")):
        return None
    return host


def read_hosts(path: Path | str, csv_first: bool = False) -> set[str]:
    hosts: set[str] = set()
    with Path(path).open("r", encoding="utf-8", errors="ignore") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if csv_first:
                line = line.split(",", 1)[0].strip().strip('"')
            host = normalize_host(line)
            if host:
                hosts.add(host)
    return hosts


def analyze_hosts(hosts: Iterable[str], psl: PublicSuffixList) -> dict:
    """Aggregate a hostname set by real TLD and by private platform suffix."""

    tld_domains: dict[str, set[str]] = defaultdict(set)
    tld_hosts: Counter[str] = Counter()
    platform_domains: dict[str, set[str]] = defaultdict(set)
    platform_hosts: Counter[str] = Counter()
    platform_root: dict[str, str] = {}

    total = 0
    for host in hosts:
        total += 1
        full = psl.suffix(host, include_private=True)
        icann = psl.suffix(host, include_private=False)
        if full != icann:
            platform = full
            platform_hosts[platform] += 1
            platform_domains[platform].add(psl.registrable_from_suffix(host, full))
            platform_root[platform] = icann.split(".")[-1]
            continue
        root = icann.split(".")[-1]
        tld_hosts[root] += 1
        tld_domains[root].add(psl.registrable_from_suffix(host, full))

    return {
        "total_hosts": total,
        "tld_domains": {k: len(v) for k, v in tld_domains.items()},
        "tld_hosts": dict(tld_hosts),
        "platform_domains": {k: len(v) for k, v in platform_domains.items()},
        "platform_hosts": dict(platform_hosts),
        "platform_root": platform_root,
        "registered_hosts": sum(tld_hosts.values()),
        "platform_hosts_total": sum(platform_hosts.values()),
    }


def load_psl(path: Path | str = PSL_PATH) -> PublicSuffixList:
    return PublicSuffixList(path)


def load_tranco(path: Path | str, psl: PublicSuffixList) -> tuple[dict[str, int], int]:
    """Return (root-TLD domain counts, total domains) for the Tranco list.

    Tranco's top-1M list contains one row per registrable domain, so counting
    rows by root TLD is equivalent to counting unique domains and avoids
    retaining a million-element set in memory.
    """

    counts: Counter[str] = Counter()
    total = 0
    with Path(path).open("r", encoding="utf-8", errors="ignore") as fh:
        for raw in fh:
            parts = raw.strip().split(",")
            if len(parts) < 2:
                continue
            host = normalize_host(parts[1])
            if not host:
                continue
            full = psl.suffix(host, include_private=True)
            icann = psl.suffix(host, include_private=False)
            if full != icann:
                continue
            counts[icann.split(".")[-1]] += 1
            total += 1
    return dict(counts), total


def sha256_file(path: Path | str) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_csv(path: Path | str, rows: Iterable[dict], fieldnames: list[str] | None = None) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = list(rows)
    if fieldnames is None:
        fieldnames = list(rows[0].keys()) if rows else []
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def write_json(path: Path | str, obj) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, sort_keys=False)
        fh.write("\n")


def read_json(path: Path | str):
    with Path(path).open("r", encoding="utf-8") as fh:
        return json.load(fh)


def clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def log_norm(value: float, maximum: float) -> float:
    if value <= 0 or maximum <= 0:
        return 0.0
    return clamp(math.log10(1.0 + value) / math.log10(1.0 + maximum))


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def latest_snapshot_dir() -> Path | None:
    if not RAW_DIR.exists():
        return None
    candidates = [p for p in RAW_DIR.iterdir() if p.is_dir() and (p / "manifest.json").exists()]
    return max(candidates, key=lambda p: p.name) if candidates else None


def snapshot_dirs() -> list[Path]:
    if not RAW_DIR.exists():
        return []
    return sorted(
        [p for p in RAW_DIR.iterdir() if p.is_dir() and (p / "manifest.json").exists()],
        key=lambda p: p.name,
    )
