# AICA — Enterprise AI Coding Assistant Agent

**AICA** stands for **AI Coding Assistant**. It is an AI helper for programmers: it reads
your code, answers questions about it, writes and fixes code, runs the tests, and asks
a person before doing anything risky.

GitHub repository: **`AICA`**.

Implementation of the *Enhanced AI Coding Agent BRD v3*
(`docs/brd/Enhanced_AI_Coding_Agent_BRD_Functional_v3.docx`).

Start with `BRIEFER.md` (a plain-English map of the project and where it stands). Requirement tracking lives in `ACCEPTANCE.md`; the
decision log and next action in `PROGRESS.md`.

## Repository layout

```
config/policy.toml     bounded autonomy, approval, network, secrets and git policy (AG-007, SAFE-*)
config/models.toml     approved models and routing; credentials come from named env vars (MM-001)
config/*.example       templates for databases, MCP servers, repositories and Slack
src/aica/policy/       policy schema + loader, run budget, cancellation token
src/aica/safety/       command classifier, secret redaction, prompt-injection defense
src/aica/audit/        redacted audit events + JSONL sink
src/aica/workspace/    path guard, Git guard (GIT-010), snapshots (FS-007), project conventions (CC-004, MEM-004)
src/aica/models/       model adapters, gateway, routing and fallback (MM-*)
src/aica/rag/          AST chunking, embeddings, SQLite index (RAG-001..010)
src/aica/tools/        filesystem, shell, git, tests, retrieval, browser tools + registry (MCP-002..006)
src/aica/testing/      test discovery, result parsing, verification ledger, test generation (TEST-001..009)
src/aica/chat/         sessions/memory, assistant, log diagnostics, commit messages, task report (CHAT-*, MEM-*, GIT-006)
src/aica/agent/        the agent loop: plan, execute, observe, adapt, report; subagents (AG-001..010)
src/aica/review/       code and security review of a change (REV-001..007)
src/aica/evaluation/   golden tasks, metrics, release gates (EVAL-001..009)
src/aica/adaptation/   fine-tuning data, datasets, training jobs, adapters and promotion (BRD 13)
src/aica/admin/        RBAC, approval queue, controls, usage, retention (ADM-*, SEC-*)
src/aica/database/     SQL classification, dialects, connections, migrations (DB-001..007)
src/aica/mcp/          MCP client: stdio JSON-RPC, handshake, tool discovery (MCP-001/007)
src/aica/integrations/ GitHub connector and Slack bridge (INT-004, INT-006)
src/aica/api/          HTTP API: sessions, tasks, event streaming, tools (API-*)
src/aica/web/          the web page served at /ui/ (INT-003)
src/aica/cli.py        the `aica` command-line interface (INT-002)
ide/vscode/            the VS Code extension (INT-001)
evaluation/tasks/      golden tasks: the exam; evaluation/training/ holds the practice tasks
training/kaggle/       the QLoRA notebook and the Kaggle walkthrough
tests/                 unit suite; tests/integration/ is the cross-module suite
docs/brd/              the BRD (functional source of truth)
scripts/verify.*       one-shot lint + format + type + test run
```

## Using it

```cmd
aica index                          REM build/refresh the repository index
aica search "how is X computed"     REM hybrid retrieval with path:line citations
aica deps --symbol compute_total    REM definitions and cross-file references
aica test --discover-only           REM show the project's real test commands
aica test --kind unit               REM run them and get a parsed result
aica test --kind integration        REM run the cross-module suite in tests/integration
aica conventions                    REM conventions detected from this repo, with evidence
aica conventions --record "..."     REM record a project convention (persists in .aica)
aica debug --log build.log          REM diagnose a failure from a log or stack trace
aica commit-message                 REM a validated commit message for the current diff
aica gen-tests --file src/x.py      REM propose tests for a file (nothing is written)
aica review                         REM review the current change; exits 2 on findings, 6 if incomplete
aica review --base main --json      REM review the branch against main, machine-readable
aica task "add input validation"    REM run an agent task: plan, execute, verify, report
aica browse --url http://127.0.0.1:3000  REM drive a real browser, collect evidence
aica db schema --table orders       REM inspect an approved database (read-only)
aica db query --sql "SELECT ..."    REM run a read-only query; writes need the tool + approval
aica mcp tools                      REM discover the tools your approved MCP servers offer
aica serve --port 8000              REM run the HTTP API (loopback, token-authenticated)
aica run <command>                  REM policy-checked execution
aica approvals list                 REM pending approvals; approve/reject by id
aica eval run --out report.json     REM run the golden tasks against a model
aica adapt practice                 REM fine-tuning data: see BRIEFER.md for the full sequence
aica slack run                      REM Slack approvals, task updates and questions
aica repo pr --number 11            REM a pull request from the approved GitHub connector
aica models                         REM approved models, their status and routing
aica policy                         REM the effective policy and available tools
aica audit                          REM recent material actions
```

`aica --help` lists every command; each has its own `--help`.

`aica ask`, `aica complete`, `aica debug`, `aica gen-tests` and `aica commit-message`
additionally need a reachable model: set the credential
environment variable named in `config/models.toml` and add the endpoint host to
`[network].allowed_hosts` in `config/policy.toml`.

`aica review` runs without a model too: the test-adequacy and security checks are
deterministic. It then reports `model: none`, marks the model-dependent checks as not run,
and exits **6** — an incomplete review is never reported as a pass. Exit codes: `0` clean,
`2` a finding at or above `--fail-on` (default `high`), `6` the review could not be
completed. New, untracked files are included by default; nothing is ever written or staged.

## Local development (Windows / CMD or PowerShell)

Python 3.12+ is required (3.14 verified). A project-local virtual environment is
mandatory:

```cmd
python -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip
pip install -e ".[dev]"
```

On Git Bash / POSIX shells use `.venv/Scripts/python.exe` (Windows) or
`.venv/bin/python` (Linux/macOS) in place of `python`.

The browser tools (WEB-001..006) are an optional extra, because they need real browser
binaries (~300MB, stored outside this repository):

```cmd
pip install -e ".[dev,browser]"
python -m playwright install chromium
```

Without it everything else still works: the browser tools import Playwright lazily and print
an install hint instead of failing obscurely.

Databases are configured in `config/databases.toml` (see `config/databases.toml.example`).
SQLite needs nothing; PostgreSQL needs `pip install -e ".[postgres]"`. Connections are chosen
**by name** — nothing in the system accepts a connection string from a model — and a password
written into the config file is rejected in favour of an environment variable.

MCP servers are configured in `config/mcp.toml` (see `config/mcp.toml.example`). Their tools
appear as `mcp.<server>.<tool>`, so a server cannot shadow a built-in tool, and the `mcp` tool
group is **not** in the default `allowed_tools` — add it to `config/policy.toml` deliberately.
A server marked `trusted = false` (the default) needs approval for every call.

The HTTP API (`pip install -e ".[api]"`, then `aica serve`) binds **127.0.0.1 only** and
requires `Authorization: Bearer <token>` on every endpoint except `/health`. Set
`AICA_API_TOKEN` to choose the token; otherwise one is generated and printed at startup. The
API is a surface over the same tools and guards the CLI uses — a destructive command is
refused with HTTP 409 exactly as it is refused at the prompt.

## Verification commands

Run all of these before claiming any task complete:

```cmd
ruff check src tests
ruff format --check src tests
mypy
pytest --cov=aica --cov-report=term-missing
```

or the wrapper: `scripts\verify.cmd` (Windows) / `scripts/verify.sh` (POSIX).

## Configuration

Copy `.env.example` to `.env` (never committed). Policy is read from
`config/policy.toml` (override with `AICA_POLICY_FILE`); audit logs go to `.aica/audit/`
(override with `AICA_AUDIT_DIR`). Model credentials are supplied only through
environment variables.

## Security posture

- Network access is **deny by default**; hosts must be allowlisted in policy.
- Destructive, privileged, external, production, file-delete, protected-branch-commit,
  database-write and secret-access actions **require approval** by default.
- Everything written to the audit log is passed through secret redaction.
- Content from repositories, tools, logs and models is treated as untrusted data and is
  fenced before it reaches a model.
- The agent refuses to modify files that carry uncommitted developer changes unless
  explicitly authorized, and refuses to change protected branches directly.
