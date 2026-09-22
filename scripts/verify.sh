#!/usr/bin/env sh
# One-shot verification: lint, format check, type check, tests. Stops on first failure.
set -e
if [ -x .venv/Scripts/python.exe ]; then PY=.venv/Scripts/python.exe
elif [ -x .venv/bin/python ]; then PY=.venv/bin/python
else echo ".venv missing: run 'python -m venv .venv' and 'pip install -e .[dev]'" >&2; exit 1; fi
"$PY" -m ruff check src tests
"$PY" -m ruff format --check src tests
"$PY" -m mypy
"$PY" -m pytest --cov=aica --cov-report=term-missing
echo "ALL CHECKS PASSED"
