PYTHON ?= python3

.PHONY: install test lint clean

install:
	$(PYTHON) -m pip install -r requirements.txt
	$(PYTHON) -m pip install -e .

test:
	$(PYTHON) -m pytest tests/ -v

lint:
	$(PYTHON) -m compileall -q crucible

clean:
	rm -rf build dist *.egg-info .pytest_cache
	find . -type d -name __pycache__ -exec rm -rf {} +
	rm -f reports/*.json reports/*.md
	rm -rf .crucible_work
