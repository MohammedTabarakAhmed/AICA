# Briefer: start here

The whole project on a few pages, in plain English, with just enough technical detail to
find your way around. It covers what was built from Phase 0 until now, where things stand,
and what to do when stuck. The detail lives in:

| File | What it is for |
|---|---|
| `CLAUDE.md` | the rules for how work is done here: safety, testing, Git |
| `ACCEPTANCE.md` | every BRD requirement, ticked only when proven, plus test records |
| `.claude-progress.md` | the decision log (why things were built the way they were) and the next action |
| `DEPENDENCIES.md` | every library used, and why it is allowed |
| `README.md` | how to install `aica` and the main commands |
| `training/kaggle/README.md` | the Kaggle training walkthrough |
| `docs/brd/*.docx` | the BRD: what the product must do (the source of truth) |

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
  sign-offs in `ACCEPTANCE.md` (end-to-end scenarios the owner confirms). Kimi and DeepSeek stay
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
- **Shell quirk (for Claude Code sessions):** inline `python - <<'EOF'` scripts sometimes turn
  `\n` inside strings into real line breaks. Put scripts with escapes in a scratch file, or use
  the Edit tool.
- **Git:** work on a branch and open a PR. Deleting remote branches is blocked by the
  auto-mode permission check, so the owner does that.
