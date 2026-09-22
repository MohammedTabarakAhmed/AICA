@echo off
REM One-shot verification: lint, format check, type check, tests. Exits non-zero on first failure.
setlocal
set PY=.venv\Scripts\python.exe
if not exist %PY% ( echo .venv missing: run "python -m venv .venv" and "pip install -e .[dev]" & exit /b 1 )
%PY% -m ruff check src tests || exit /b 1
%PY% -m ruff format --check src tests || exit /b 1
%PY% -m mypy || exit /b 1
%PY% -m pytest --cov=aica --cov-report=term-missing || exit /b 1
echo ALL CHECKS PASSED
