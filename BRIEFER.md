# Briefer: start here

The whole project on a few pages, in plain English, with just enough technical detail to
find your way around. It covers what was built from Phase 0 until now, where things stand,
and what to do when stuck. The detail lives in:

| File | What it is for |
|---|---|
| `README.md` | a short overview of the project |
| "Setup and reference" (below) | install, every command, configuration and security |
| `training/kaggle/README.md` | the Kaggle training walkthrough |

## What AICA is

**AICA is a coding assistant: a program (the worker) that uses an AI model (the brain).**
You give it a task in plain words. It reads the repository, makes a plan, edits files, runs
the tests and reports what happened. It is written in Python (the `aica` package in `src/`).

- **The brain is swappable.** Models are listed in `config/models.toml`. Today the main one is
  Qwen 27B on Groq (a free cloud API). GLM, Gemini and a local Qwen 7B (running on this PC
  through Ollama) are backups, tried in order if one fails.
- **It never fakes success.** A task counts as done only when the tests really ran and passed.
  A "verification ledger" records every check, and the final report must match it.
- **Risky actions need a human.** Deleting files, pushing, database writes and using secrets
  all stop and ask for approval. Every important action is written to an audit log
  (`.aica/audit/`).

## How one task works

1. **Plan.** The model returns a plan as JSON: a list of steps, each naming one tool (read a
   file, edit a file, run tests...). The plan is validated first. A step naming a tool that
   doesn't exist, or that the policy forbids, is rejected before anything runs.
2. **Execute.** Each step goes through the tool registry, which checks the policy, the allowed
   folders, approvals, and whether a file has your uncommitted changes (those are never
   overwritten).
3. **Fill in later.** A step that depends on something not read yet (for example, writing a
   file before seeing it) is marked "deferred" and filled in only after the earlier steps have
   run. This stops the model inventing file contents.
4. **Adapt.** If a step fails, the model sees the error and picks what to do: retry, replace
   the step, skip it, or give up. The number of repairs is limited.
5. **Limits.** Every run has a step budget and a time budget. A single command can't outlive
   the run, and a stopped command's whole process tree is killed.
6. **Verify and report.** The required checks (unit tests, lint...) are run for real, then a
   report lists the files changed, the checks run and anything unresolved.

## What was built, phase by phase

**Phase 0 - Foundation: safety first.**
- A policy file (`config/policy.toml`) sets the limits: steps, time, allowed tools, allowed
  network hosts, and which actions need approval.
- A command classifier sorts shell commands into read-only, normal, privileged, destructive or
  external. The dangerous kinds need approval.
- Secret redaction (API keys, tokens, passwords are masked in logs and prompts), a path guard
  (no escaping the project folder) and a Git guard (your uncommitted work is protected).
- Code checks: ruff (lint and format), mypy (strict type checks), pytest (tests).

**Phase 1 - The basic coding assistant.**
- Chat and code completion about the repository, with file:line citations.
- Repository search (RAG, "retrieval"): code is split into chunks by function and class (using
  the syntax tree), then found by keywords, by meaning, by symbol name and by imports.
- File tools with snapshots and undo, a controlled shell, Git tools, and a test runner that
  finds the project's real test commands and reads their results.
- The `aica` command-line tool (the CLI): the terminal way to use all of this.

**Phase 2 - The agent: multi-step work on its own.**
- The plan-execute-adapt-verify loop above, with pause, resume and cancel. A run's state is
  saved, so it survives a restart.
- Subagents: research, implementation, testing and review helpers, each with fewer tools than
  the main agent.
- Browser automation (Playwright: drives a real Chromium browser for end-to-end tests).
- Databases (SQLite, PostgreSQL): read-only by default; writes need approval.
- MCP: plug in outside tool servers, sandboxed so they can't pretend to be built-in tools.
- An HTTP API (FastAPI), so other programs can drive AICA.

**Phase 3 - Models, memory, safety.**
- A model registry with approval status, exact version pinning, routing (which model does which
  kind of work) and fallback (the next model when one is down or rate-limited).
- Live providers: Groq, GLM, Gemini and local Ollama. Kimi and DeepSeek are **deferred by the
  owner**: they would use the same adapter the others already prove.
- Session memory, approvals, prompt-injection defence (repository text is treated as data,
  never as instructions), a network allowlist, secrets injected only when approved, and an
  emergency stop.
- Code review (`aica review`: bugs, conventions, missing tests, security), anchored to the
  exact changed lines.
- An evaluation harness: "golden tasks", an exam of fixed problems, to measure a model honestly.

**Phase 4 - Enterprise features and integrations.**
- Roles and permissions (RBAC: viewer, developer, approver, admin), an approval queue, the rule
  that you can't approve your own request, kill switches for models, tools and integrations,
  quotas, audit search, and data retention.
- Several ways in: the VS Code extension, a web page (`aica serve`, then `/ui/`), GitHub (reads
  and comments on PRs; a CI workflow reviews every PR) and Slack (Approve/Reject buttons,
  "task finished" messages, questions to `@aica`).
- Verified on Python, TypeScript, Java, Go and Rust projects.

**Phase 5 - Fine-tuning (first run done, 2026-09-27).**
- Teach the small local 7B model from the big model's verified work, so AICA can run free and
  offline. The steps are in the next section. The first adapter was trained, examined and
  refused by the gates: it was not good enough to serve.

## Fine-tuning, step by step

**The idea:** the big model solves practice problems. Only solutions whose tests really pass
are kept. The small 7B model learns from them on a free Kaggle GPU (QLoRA: a small add-on
"adapter" trained on top of the model, instead of retraining the whole model). The adapter is
used only if the model scores better on an exam of problems it never saw.

| # | Step | What happens | Command | Status |
|---|---|---|---|---|
| 1 | Practice problems | small Python bugs with failing tests (`evaluation/training/`, 41) | written by hand | done |
| 2 | Practice runs | AICA solves each one; kept only if its tests pass when re-run separately | `aica --actor mohammed adapt practice` done: 40 kept runs |
| 3 | Collect | screen kept runs for secrets, risky commands and failures | `aica adapt collect` done: 46 found, 9 screened out |
| 4 | Approve | the owner approves or declines each run | `aica adapt candidates`, `aica adapt approve <id>` done: 36 approved, slugify declined |
| 5 | Dataset | turn runs into lessons: one "plan" lesson per run, one "fill in" lesson per deferred step | `aica adapt dataset` done: `1a664cc0b2fdba94`, 87 lessons |
| 6 | Plan | fix the recipe: base model, epochs, adapter size | `aica adapt plan --name aica-coder --base qwen2.5-coder-7b --dataset <v>` | done: job `27890f78eaff5fbe` |
| 7 | Export | put everything to upload in one folder, plus `review.md` (every lesson, readable); uploads nothing | `aica adapt export --job <v> --kaggle-user tabu73 --out .aica/export` | done |
| 8 | Owner check | read `.aica/export/review.md` before anything leaves the PC | read the file | done (scanned: no keys, paths, email) |
| 9 | Train | private dataset and notebook on Kaggle's GPU, about 20-40 minutes | `kaggle datasets create -p .aica/export`, `kaggle kernels push -p .aica/export/kernel` | done: Tesla T4, 3rd attempt |
| 10 | Bring back | download the adapter; load it into Ollama on top of `qwen2.5-coder:7b` | `kaggle kernels output ...`, `ollama create aica-coder-1 -f Modelfile` | done: `aica-coder@1` |
| 11 | Exam | run the 9 exam tasks with and without the adapter | `aica eval run --adapter <id>`, `aica eval run --model qwen2.5-coder-7b` | done: 1 of 9 with, 0 of 9 without |
| 12 | Decide | keep it only if it scores better and passes every security task | `aica adapt evaluate`, `aica adapt promote` (undo: `aica adapt rollback`) | **refused**: quality and all 3 security tasks failed |

## Where things stand (2026-09-27)

- **Done:** Phases 0 to 4, and fine-tuning run 1 end to end (209 of 223 checklist lines proven).
- **Fine-tuning result:** the adapter learned something (the 7B went from 0 to 1 of 9 exam tasks)
  but is nowhere near good enough, and it failed all three security tasks, so the gates refused
  it and nothing served changed. That is the system working as intended. A second try needs more
  and harder practice tasks, or a bigger base model; decide before spending time on it.
- **Models today:** Groq stays the main brain. The fine-tuned model is registered as
  `aica-coder-1`: used only when picked by name (`aica ask --model aica-coder-1 ...`), never
  automatically, because it failed the security tasks.
- **Paused here (2026-09-27)** at the owner's request. Left when work resumes: the business
  sign-offs (end-to-end scenarios the owner confirms). Kimi and DeepSeek stay
  deferred.
- **Demo:** `aica serve --port 8765`, then open <http://127.0.0.1:8765/ui/> and paste the token
  it prints (or set `AICA_API_TOKEN` first). Ollama must be running for the local models.

## When stuck

- **Groq free tier:** 200,000 tokens per day for `qwen/qwen3.8-27b`, refilling continuously
  (about 2.3 tokens a second), not resetting at a fixed time. One practice run uses about
  8,500 tokens. The fallbacks are weak for agent work (GLM is often overloaded, and Gemini failed
  3 of 3 practice tasks), so wait rather than train on bad data.
- **Local 7B context:** Ollama serves `qwen2.5-coder:7b` with 4,096 tokens, and agent planning
  needs 32,000. For an exam (step 11), start Ollama with `OLLAMA_CONTEXT_LENGTH=32768` and raise
  `context_window` in `config/models.toml` to match, **locally only**: put it back to 4096 before
  committing (a test checks it). It runs on the CPU: about 7 GB of memory and 35 minutes per exam,
  so close other apps and run the exam as its own process.
- **Kaggle quirks:** run `kaggle` from inside the folder you upload (a relative path with a folder
  in it fails), set `PYTHONUTF8=1` on Windows, and expect a GPU queue of up to an hour. `kaggle
  kernels output` only fetches the first page of files, so the adapter under `out/` needs paging
  (Entry 041).
- **Keys** live only in user environment variables, never in files: `GROQ_API_KEY`,
  `GEMINI_API_KEY`, `GLM_API_KEY`, `GITHUB_TOKEN`, `SLACK_BOT_TOKEN`, `SLACK_APP_TOKEN`,
  `KAGGLE_USERNAME`, `KAGGLE_KEY`.
- **Check before claiming anything:** `scripts\verify.cmd` (lint, format, types, all tests). CI
  runs the same on Linux and Windows for every pull request. Merge only when it is green.
- **Shell quirk (for agent sessions):** inline `python - <<'EOF'` scripts sometimes turn
  `\n` inside strings into real line breaks. Put scripts with escapes in a scratch file, or use
  the Edit tool.
- **Git:** work on a branch and open a PR. Deleting remote branches is blocked by the
  auto-mode permission check, so the owner does that.

## Setup and reference

### Repository layout

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
src/aica/adaptation/   fine-tuning data, datasets, training jobs, adapters and promotion
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
scripts/verify.*       one-shot lint + format + type + test run
```

### Using it

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

### Local development (Windows / CMD or PowerShell)

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

### Verification commands

Run all of these before claiming any task complete:

```cmd
ruff check src tests
ruff format --check src tests
mypy
pytest --cov=aica --cov-report=term-missing
```

or the wrapper: `scripts\verify.cmd` (Windows) / `scripts/verify.sh` (POSIX).

### Configuration

Copy `.env.example` to `.env` (never committed). Policy is read from
`config/policy.toml` (override with `AICA_POLICY_FILE`); audit logs go to `.aica/audit/`
(override with `AICA_AUDIT_DIR`). Model credentials are supplied only through
environment variables.

### Security posture

- Network access is **deny by default**; hosts must be allowlisted in policy.
- Destructive, privileged, external, production, file-delete, protected-branch-commit,
  database-write and secret-access actions **require approval** by default.
- Everything written to the audit log is passed through secret redaction.
- Content from repositories, tools, logs and models is treated as untrusted data and is
  fenced before it reaches a model.
- The agent refuses to modify files that carry uncommitted developer changes unless
  explicitly authorized, and refuses to change protected branches directly.
