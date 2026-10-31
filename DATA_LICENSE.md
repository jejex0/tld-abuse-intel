# Data licensing and attribution

This repository contains code and derived, aggregate data. They are licensed
differently.

## Code

All source code under `scripts/` is licensed under the MIT License. See
[`LICENSE`](LICENSE).

## Derived data and analysis

The files under `data/processed/`, `data/curated/`, `reports/`, and
`reports/figures/` are derived aggregates produced by this project. They are
made available under the **Creative Commons Attribution 4.0 International
(CC BY 4.0)** license: <https://creativecommons.org/licenses/by/4.0/>.

Attribution: *TLD Abuse Intelligence, jejex0, 2026,
https://github.com/jejex0/tld-abuse-intel*.

CC BY 4.0 applies only to the extent this project holds rights in the derived
work. It does not grant rights to upstream source data beyond the terms set by
each upstream provider.

## Upstream sources

Raw feeds are **not redistributed**. `data/raw/` is excluded from the
repository. To reproduce the dataset, run the collectors, which download from
the upstream providers. Each source retains its own terms:

| Source | Role | Terms / notes |
|---|---|---|
| Interisle Consulting Group, *Phishing Landscape* 2020–2023 | Annual phishing TLD rankings | Citation required; see <https://interisle.net/> |
| Cybercrime Information Center TLD tables 2024–2026 | Annual volume, density, malicious registration | Citation required; see <https://www.cybercrimeinfocenter.org/> |
| OpenPhish | Live phishing URLs | See <https://openphish.com/> |
| Phishing Army | Aggregated phishing blocklist | See <https://phishing.army/> |
| Phishing.Database | Active phishing domains | See <https://github.com/mitchellkrogza/Phishing.Database> |
| Spam404 | Phishing/malicious domain list | See <https://github.com/Spam404/lists> |
| malware-filter | Filtered phishing and URLhaus domains | CC0-1.0 for the filtered lists; source data from URLhaus |
| abuse.ch / URLhaus | Malware URL source data | See <https://urlhaus.abuse.ch/> |
| C2IntelFeeds | C2 domains | See <https://github.com/drb-ra/C2IntelFeeds> |
| Tranco | Popularity baseline | See <https://tranco-list.eu/> |
| Public Suffix List | Namespace parsing | MPL 2.0, <https://publicsuffix.org/> |
| Internet Archive Wayback Machine | Historical snapshots | See <https://web.archive.org/> |

Before redistributing derived data at scale, confirm that the upstream terms
allow it. Some feeds restrict commercial use or require attribution.

## No warranty

These data are provided for defensive security research. They are not a
production blocklist and come with no warranty of accuracy, completeness, or
fitness for a particular purpose.
