# Data sources

All sources below are public. Raw downloads are stored under `data/raw/` and are
**not committed**; run the collectors to reproduce them. Retrieval examples use
the snapshot dated 2026-10-31.

## 1. Current feeds

| # | Source | Role | URL | Format | Refresh |
|---|---|---|---|---|---|
| 1 | OpenPhish | Phishing URLs | <https://openphish.com/feed.txt> | One URL per line | Continuous |
| 2 | Phishing Army | Aggregated phishing domains | <https://phishing.army/download/phishing_army_blocklist_extended.txt> | Domains / hosts | Frequent |
| 3 | Phishing.Database | Active phishing domains | <https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt> | One domain per line | Frequent |
| 4 | Spam404 | Phishing / malicious domains | <https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt> | One domain per line | Periodic |
| 5 | malware-filter phishing filter | Filtered phishing domains | <https://malware-filter.gitlab.io/malware-filter/phishing-filter-domains.txt> | Domains | Daily |
| 6 | malware-filter URLhaus filter | Payload / malware domains | <https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains.txt> | Domains | Daily |
| 7 | C2IntelFeeds 30-day | C2 domains | <https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/domainC2s-30day-filter-abused.csv> | CSV, `domain` column | Daily |
| 8 | C2IntelFeeds 90-day | C2 domains | <https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/domainC2s-90day-filter-abused.csv> | CSV, `domain` column | Daily |
| 9 | C2IntelFeeds DNS | DNS C2 domains | <https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/DNSC2Domains.csv> | CSV, `domain` column | Daily |
| 10 | Tranco | Popularity baseline | <https://tranco-list.eu/top-1m.csv.zip> | Ranked domain CSV (zipped) | Research list, periodic |
| 11 | Public Suffix List | Namespace parsing | <https://publicsuffix.org/list/public_suffix_list.dat> | PSL text | Periodic |

### 1.1 Extraction notes

- **OpenPhish** provides URLs. The collector reduces each URL to its hostname,
  case-folds it, strips trailing dots, and rejects malformed hosts and bare IPs.
- **Domain lists** accept one host per line. Comments (`#`), blank lines, and
  blocklist prefixes are ignored where present.
- **C2 feeds** are CSVs; the collector reads the `domain` field and ignores rows
  without a parseable hostname. The three C2 files are unioned.
- **URLhaus-filter** is a domain-only derivative of abuse.ch URLhaus. It is used
  instead of the URLhaus API because it is stable, text-based, and CC0-licensed
  at the filter layer.
- **Tranco** is counted by root TLD. Private suffixes are skipped so platform
  hosts do not inflate `.dev`, `.app`, `.io`, or `.org`.
- **PSL** is vendored for reproducibility and refreshed only on request
  (`--refresh-psl`).

### 1.2 Snapshot mechanics

`scripts/collect.py`:

1. downloads each source to `data/raw/<YYYY-MM-DD>/`;
2. records SHA-256 hashes, byte sizes, and retrieval timestamps in
   `data/processed/snapshot_manifest.json`;
3. writes per-source counts and the Tranco TLD baseline.

`--reuse` keeps existing files; `--force` re-downloads even with `--reuse`.

## 2. Annual registry studies

| Source | Years | Role | URL |
|---|---|---|---|
| Interisle Consulting Group, *Phishing Landscape* | 2020–2023 | Annual phishing TLD volume and density rankings | <https://interisle.net/> |
| Cybercrime Information Center (CIC) TLD tables | 2024–2026 | Volume, density, malicious registrations, year-over-year changes | <https://www.cybercrimeinfocenter.org/> |

Curated rows live in `data/curated/phishing_tld_history.csv` with columns:

```
year, period_start, period_end, tld, rank_count, domains_in_tld,
phishing_domains, rank_score, phishing_score, rank_malreg,
malicious_registrations, malicious_score, source, notes
```

Provenance notes:

- **2020** covers May–July only (three months), not a full year.
- **2021–2023** are partial top-5/top-10 tables.
- **2024–2026** are full top-20 volume and density tables; 2026 also includes a
  malicious-registration table and year-over-year comparisons.
- **2025 baselines** from the 2026 CIC year-over-year table are included so
  growth can be computed consistently.
- Ranks are retained from the source tables; they are not recomputed globally.

Because publication cutoffs and definitions vary by year, historical comparisons
are indicative rather than strictly like-for-like. Persistence counts distinct
years of top-10 presence and is robust to this limitation.

## 3. Historical payload and C2 reconstruction

Live URLhaus and C2Intel feeds are overwritten continuously. History is recovered
from the Internet Archive Wayback Machine.

### 3.1 Method

1. Query the CDX API:
   `https://web.archive.org/cdx/search/cdx?url=<feed-url>&output=json`.
2. Select captures spanning the retention window, preferring distinct dates.
3. Fetch each capture with a normal HTTP client so content encoding is handled.
4. Reject captures that lack the expected feed header or that are binary/gzip
   garbage.
5. Run the same host normalization and PSL/platform separation as current data.
6. Aggregate to TLD and platform-suffix counts.

### 3.2 Payload history

| Item | Value |
|---|---|
| Origin | `https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains.txt` |
| Snapshots | 11 |
| Window | 2023-03-15 → 2026-07-10 |
| Outputs | `payload_history.csv`, `payload_history_summary.csv`, `payload_platform_history.csv`, `payload_platform_history_summary.csv` |

### 3.3 C2 history

| Item | Value |
|---|---|
| Origin | C2IntelFeeds 30/90-day CSVs |
| Snapshots | 2 committed (2025-08-15, 2025-09-20); a 2026-03-02 capture is available but not used in the current summary |
| Outputs | `c2_history.csv`, `c2_history_summary.csv` |

Capture timestamps, selected URLs, and per-snapshot counts are recorded in
`data/processed/history_manifest.json`. Wayback coverage is incomplete and
uneven; absence of a capture is not evidence of absence of abuse.

## 4. Reference data

| Dataset | Role | License |
|---|---|---|
| Public Suffix List | ICANN/PRIVATE suffix parsing and platform separation | MPL 2.0 |
| Tranco top-1M | Benign popularity baseline for over-representation | See Tranco terms |
| `data/curated/phishing_tld_history.csv` | Annual registry observations | Derived; cite upstream reports |

## 5. Licensing and redistribution

- Code: MIT.
- Derived aggregates and analysis: CC BY 4.0.
- Raw feeds: not redistributed; each provider's terms apply.
- PSL: MPL 2.0; the vendored file retains its header.
- Before publishing derived data at scale, confirm that upstream terms permit it.
  Some feeds restrict commercial use or require attribution.

See [`../DATA_LICENSE.md`](../DATA_LICENSE.md) for the repository's data-license
policy.

## 6. Attribution

Interisle Consulting Group and the Cybercrime Information Center for the annual
registry data; abuse.ch/URLhaus, malware-filter, C2IntelFeeds, OpenPhish,
Phishing Army, Phishing.Database, Spam404, Tranco, the Public Suffix List
maintainers, and the Internet Archive for operational and reference data.
