PYTHON ?= python3

.PHONY: all setup collect history analyze charts report validate clean distclean

all: collect history analyze charts report validate

setup:
	$(PYTHON) -m pip install -r requirements.txt

collect:
	$(PYTHON) scripts/collect.py

history:
	$(PYTHON) scripts/collect_history.py

analyze:
	$(PYTHON) scripts/analyze.py

charts:
	$(PYTHON) scripts/charts.py

report:
	$(PYTHON) scripts/report.py

validate:
	$(PYTHON) scripts/validate.py

# Remove interpreter caches only.
clean:
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type f -name '*.py[co]' -delete

# Also remove downloaded raw feeds. Regenerate with `make collect history`.
distclean: clean
	rm -rf data/raw
