# Contributing

Thanks for your interest in improving TLD Abuse Intelligence. This project is a
research dataset and analysis pipeline, so contributions that improve data
quality, reproducibility, or the risk model are especially valuable.

## Ways to contribute

- **Correct curated data.** If an annual registry row in
  `data/curated/phishing_tld_history.csv` is wrong or missing, open a
  [data correction issue](.github/ISSUE_TEMPLATE/data_correction.yml) with the
  source URL, retrieval date, and the exact value you believe is correct.
- **Suggest a public feed.** New phishing, payload, or C2 feeds must be public,
  documented, and reasonably stable. Note the license/terms.
- **Improve the model.** Changes to scoring, tier rules, or confidence must keep
  the model reproducible and must not make the output a de facto blocklist.
- **Fix bugs.** Reproducible failures are best reported with the command run,
  Python version, and relevant output.

## Data changes require provenance

Any change to curated or reference data must include:

1. The source URL.
2. The retrieval date.
3. A short note describing what changed and why.

Raw downloads in `data/raw/` are intentionally not committed. If you add a new
source, update `docs/DATA_SOURCES.md` and the collector in `scripts/`.

## Pull requests

1. Fork and create a topic branch.
2. Keep changes focused; one logical change per PR.
3. Run the pipeline and validator before opening the PR:

   ```bash
   make all
   # or, with cached raw data:
   python3 scripts/collect.py --reuse
   python3 scripts/collect_history.py --reuse
   python3 scripts/analyze.py
   python3 scripts/charts.py
   python3 scripts/report.py
   python3 scripts/validate.py
   ```

4. Describe the change, the data impact, and any output that changed.
5. Do not commit secrets, private indicators, or raw third-party feeds.

## Reporting false positives

Phishing feeds contain false positives. If a domain is incorrectly counted,
prefer reporting it to the upstream feed as well; this project aggregates
public sources and does not maintain its own domain blocklist.

## Code of conduct

Be respectful and assume good faith. This is defensive security research: do not
use it to justify blocking entire namespaces without validating collateral.
