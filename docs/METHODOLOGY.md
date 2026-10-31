# Methodology

This document describes how TLD Abuse Intelligence collects, normalizes, scores,
and ranks namespaces. The generated report at
[`../reports/ANALYSIS.md`](../reports/ANALYSIS.md) is the primary output; this
file is the reference for the model's rules.

## 1. Scope

The unit of analysis is the **top-level domain** (the final label of a
hostname), plus **private platform suffixes** such as `pages.dev` and
`vercel.app`, which are reported separately.

Three abuse roles are tracked:

| Role | Definition | Primary source |
|---|---|---|
| Phishing | Hostnames reported as phishing or credential theft | Five live phishing feeds + annual registry studies |
| Payload / staging | Hosts delivering malware or hosting staged payloads | URLhaus-derived domain lists |
| C2 | Hosts observed as command-and-control endpoints | C2IntelFeeds |

A TLD's tier reflects the concentration of abuse, not the maliciousness of every
domain in the namespace. The model is explicitly **not** a production blocklist.

## 2. Normalization

### 2.1 Public Suffix List

Hostnames are parsed with the [Public Suffix List](https://publicsuffix.org/)
(PSL), including the ICANN and PRIVATE sections. The PSL is vendored at
`data/reference/public_suffix_list.dat` (MPL 2.0) so results are reproducible
offline.

- `suffix(host)` returns the public suffix.
- `registrable_domain(host)` returns the eTLD+1.
- Private-section suffixes are marked as **platform suffixes**. A host under
  `foo.pages.dev` has registrable domain `foo.pages.dev` for platform accounting,
  but is **not** counted as a registered `.dev` domain.
- `root_tld(host)` is the ICANN root label used for TLD aggregation.

This separation matters: counting `pages.dev` abuse as `.dev` would attribute
tens of thousands of phishing hosts to registered `.dev` domains that do not
exist.

### 2.2 Host and domain counts

For each feed and for the union:

- `hosts` — unique normalized hostnames.
- `nonplatform_hosts` — hosts not under a private platform suffix.
- `registered_domains` — unique registrable domains (eTLD+1) for non-platform
  hosts.
- `platform_hosts` — hosts under private suffixes, reported by platform suffix.

Invalid hosts, bare IPs, single-label names, and malformed labels are dropped.
URLs are reduced to hostnames; ports, paths, and credentials are removed.

### 2.3 Feed deduplication

The phishing union is deduplicated by normalized hostname across five feeds.
Per-feed counts and pairwise overlaps are written to
`data/processed/feed_overlap.csv` and shown in the report.

## 3. Annual registry data

`data/curated/phishing_tld_history.csv` contains annual observations for
2020–2026, compiled from:

- Interisle Consulting Group *Phishing Landscape* reports (2020–2023), and
- Cybercrime Information Center (CIC) TLD tables (2024–2026).

Each row records the year, the TLD's rank in volume and density, domains under
management, phishing domains, phishing score (density), malicious registrations,
malicious score, and an optional note. Coverage is uneven by design:

- 2020 is May–July (three months).
- 2021–2023 are partial top-5/top-10 tables.
- 2024–2026 are full top-20 volume and density tables.
- 2025 baselines are also used for year-over-year comparisons in the 2026 CIC
  table.

Persistence counts distinct years in which a TLD appears in a top-10 volume or
density table. The denominator is seven years (2020–2026).

### 3.1 Density

```
density_per_10k = phishing_domains / domains_in_tld * 10,000
```

Density is the core signal because it normalizes for namespace size. `.com` can
have the largest absolute volume while remaining far less concentrated than
`.xin`.

### 3.2 Malicious registration share

```
malicious_share = malicious_registrations / phishing_domains
```

This separates **attacker-registered** domains from **compromised legitimate**
sites. A high share implies bulk registration and registrar/registry-level
abuse; a low share implies compromise and domain-level detection.

When a TLD appears in a 2026 volume/density table but not in the top-20
malicious-registration table, the share is **imputed at 74%**, the overall
attacker-registered average reported by Interisle for 2026. Imputation is
recorded in `malreg_imputed` and the `notes` field, and it **prevents High
confidence**.

### 3.3 Year-over-year growth

Growth is computed from the last two annual observations:

```
growth_pct = (current - previous) / previous * 100
```

For momentum scoring, the larger of volume growth and density growth is used and
capped at 300%. The report's growth table is restricted to TLDs whose most recent
annual observation is 2026, so a stale 2025 row is not presented as a 2025→2026
change.

## 4. Live-feed metrics

For TLD `t` in the live phishing union:

```
live_share(t)   = live_domains(t) / total_live_domains
tranco_share(t) = tranco_domains(t) / total_tranco_domains
live_overrep(t) = live_share(t) / tranco_share(t)
```

Tranco is the top-1M list, with private-suffix hosts excluded. An
over-representation index of 1 means the TLD's share of live phishing equals its
share of popular benign domains. Values above 1 indicate over-representation;
values below 1 indicate the TLD is less prominent in phishing than its benign
footprint suggests.

Payload and C2 over-representation use the same formula against the live
registrable-domain baseline for their respective feeds.

## 5. Composite risk score

The risk score is a 0–100 composite used for **ordering within tiers**. It is not
the tier assignment rule.

| Component | Weight | Normalization |
|---|---:|---|
| Density | 35 | `clamp((log10(score) - log10(5)) / (log10(6000) - log10(5)))` |
| Volume | 15 | Log-scaled annual phishing domains, or live domains for live-only TLDs |
| Persistence | 15 | `years_top10_any / 7` |
| Malicious registration share | 15 | Direct 0–1 (74% imputed when absent) |
| Payload | 10 | Log-scaled URLhaus registered domains |
| C2 | 5 | Log-scaled C2Intel registered domains |
| Momentum | 5 | `min(max(volume_growth, density_growth), 300) / 300` |

For live-only TLDs with no annual density, density is proxied by log-scaled live
over-representation. Missing components score zero and reduce **coverage**:

```
coverage = sum(weights of present components) / 100
```

## 6. Tier assignment

Tiers are **density-led and absolute**, not percentile-based. This keeps
Critical meaningful across runs and prevents a fixed quota of TLDs from being
forced into each tier.

### 6.1 Critical

A TLD is Critical if any of:

1. density ≥ 1,000 per 10k **and** volume ≥ 10,000; or
2. density ≥ 500 **and** volume ≥ 50,000; or
3. density ≥ 400 **and** volume ≥ 20,000 **and** malicious-registration share
   ≥ 95%.

### 6.2 High

A TLD is High if not Critical and any of:

- density ≥ 400;
- density ≥ 200 **and** volume ≥ 10,000;
- density ≥ 100 **and** volume ≥ 50,000;
- density ≥ 140 **and** volume ≥ 30,000;
- composite score ≥ 52; or
- live-only over-representation ≥ 20 with ≥ 1,000 live domains.

### 6.3 Medium

A TLD is Medium if not Critical/High and any of:

- density ≥ 100;
- density ≥ 50 **and** volume ≥ 10,000;
- volume ≥ 50,000;
- medium live-only scale;
- composite score ≥ 32; or
- ≥ 500 live domains with over-representation ≥ 5.

### 6.4 Low

Everything else.

### 6.5 Modifiers and caps

Modifiers can raise **Low or Medium to High only** — never to Critical:

- malicious-registration share ≥ 90% at volume ≥ 10,000;
- persistent top-10 presence (≥ 5 of 7 years);
- strong payload/C2 signal (≥ 20 domains and over-representation ≥ 5).

Caps prevent weak evidence from producing dramatic tiers:

- Critical with current volume < 1,000 → High.
- Live-only evidence → capped at High; also dropped one tier if more than 50% of
  live hosts are on platform suffixes.
- Live-only with < 1,000 live domains → capped at Medium.
- Historical-only evidence → capped at Medium.

`tier_base` preserves the pre-modifier tier; `modifiers` records every
adjustment.

## 7. Evidence confidence

Confidence measures **evidence quality**, not severity. It is independent of
tier.

| Confidence | Requirements |
|---|---|
| High | 2026 registry data + live phishing or payload/C2 corroboration + observed (non-imputed) malicious share + coverage ≥ 75% |
| Medium | 2026 registry data without full corroboration; or ≥ 1,000 live domains across ≥ 2 feeds; or ≥ 2 years of history with ≥ 100 live domains; or 2024/2025 registry data with ≥ 500 live domains |
| Low | Historical-only, small live-only sample, dominant platform signal, or signal-only evidence |

Additional low-confidence flags:

- malicious share imputed at 74%;
- historical-only evidence;
- live-only sample < 1,000 domains;
- more than 60% of live domains on free-hosting platforms.

A Critical/High tier with Low confidence should be treated as a **watchlist
item**, not a confirmed policy target.

## 8. Blocklist suitability

Suitability is separate from risk and approximates collateral damage:

| Suitability | Rule |
|---|---|
| High | Tranco share ≤ 0.2% and platform share < 50% |
| Medium | Tranco share ≤ 1% |
| Low | Tranco share > 1%, or a known high-collateral namespace |

The `HIGH_COLLATERAL_TLDS` set (`.com`, `.net`, `.org`, `.xyz`, `.cn`, `.ru`,
`.jp`, `.io`, `.app`, `.dev`, etc.) forces Low suitability and a "do not block
wholesale" action regardless of rule output.

Recommended actions are tier- and suitability-aware:

- Critical/High + High suitability → TLD blocklist candidate for constrained
  environments, subject to validation.
- Critical/High + Medium suitability → prefer domain-level detection; TLD block
  only for tightly scoped environments.
- Critical/High + Low suitability → do not block the TLD; monitor and escalate.
- Low/Medium → monitor and block at domain level.

## 9. Separate platform analysis

Private platform suffixes are analyzed as their own abuse economy:

- live phishing hosts, payload hosts, and C2 hosts per suffix;
- share of total live phishing hosts;
- historical presence across archived snapshots.

The report recommends platform/subdomain controls rather than parent-TLD blocks.
Counting `pages.dev` as `.dev` would be both technically wrong and operationally
counterproductive.

## 10. Historical reconstruction

Live URLhaus and C2Intel files are overwritten continuously. Historical
distributions are reconstructed from Internet Archive captures:

1. Query the Wayback CDX API for the feed URL.
2. Select captures, preferring distinct dates spread across the retention window.
3. Validate that the capture is the expected text feed (not a binary or error
   page).
4. Parse hosts, apply the same PSL normalization and platform separation used for
   current data.
5. Write aggregate snapshots to `data/processed/payload_history.csv`,
   `payload_platform_history.csv`, and `c2_history.csv`.

Early payload captures use the malware-filter URLhaus mirror; C2 history uses
C2IntelFeeds. Capture dates and source URLs are recorded in
`data/processed/history_manifest.json`.

## 11. Determinism and validation

- All scripts are deterministic given the same raw inputs, curated CSV, PSL, and
  Tranco list.
- `scripts/validate.py` checks PSL behavior, curated-data shape, tier and score
  ranges, count consistency between the CSV and JSON outputs, figure presence,
  and report section presence.
- `make all` runs collect → history → analyze → charts → report → validate.
- The GitHub Actions workflow reruns the pipeline weekly and commits updated
  processed data and reports.

## 12. Known limitations

- Annual registry data has reporting lags, changing top-N cutoffs, and partial
  early years.
- Density depends on registry-reported domains under management, which varies in
  quality by registry.
- Malicious-registration imputation at 74% can over- or under-state individual
  TLDs. It is flagged and caps confidence.
- Live feeds over-sample recently reported and public sources; stealthy
  infrastructure is under-represented.
- C2 samples are small and should not drive TLD policy on their own.
- TLD-level blocking has high collateral risk and legal/contractual constraints.
  Always validate business traffic, platform concentration, data freshness, and
  policy before deployment.
