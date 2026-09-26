# Briefer: start here

A one-page, plain-English map of the project: what AICA is, where things stand and what
comes next. It is for a new session, or for anyone who gets stuck. The detail lives in:

| File | What it is for |
|---|---|
| `CLAUDE.md` | the rules for how work is done here (safety, testing, Git) |
| `ACCEPTANCE.md` | every requirement from the BRD, ticked only when proven |
| `.claude-progress.md` | the decision log (Entry 001 to 040) and the next action |
| `DEPENDENCIES.md` | every library and why it is allowed |
| `README.md` | how to install and use `aica` |
| `training/kaggle/README.md` | the Kaggle training walkthrough |
| `docs/brd/*.docx` | the BRD: what the product must do (the source of truth) |

## What AICA is

**AICA is a coding assistant: a worker that uses an AI model as its brain.** It reads a
repository, answers questions about it, plans a change, edits files, runs the tests, and
reports the result honestly. It never says "done" unless the tests really passed.

- **The brain is swappable.** Today it is mostly Groq's Qwen 27B. GLM, Gemini and a local
  Qwen 7B (through Ollama, on this PC) are backups, tried in order when one fails.
- **Ways to use it:** the terminal (`aica ...`), the VS Code extension, a web page, an HTTP
  API, Slack (approvals, finished-task messages, questions), and GitHub (reviews PRs in CI,
  talks to repositories).
- **Guard rails:** risky actions (deleting, pushing, database writes, secrets) need a human's
  approval. Network access is allowlisted, secrets are redacted, and everything material is
  written to an audit log (`.aica/audit/`).

## Where things stand (2026-09-26)

- **Built and verified:** almost everything in the BRD. See `ACCEPTANCE.md`.
- **Deferred by the owner:** the Kimi and DeepSeek models, because the other providers
  already exercise the same adapter.
- **In progress:** fine-tuning, below.
- **After that:** the remaining Business Acceptance sign-offs in `ACCEPTANCE.md`.

## Fine-tuning, step by step

**The idea:** the big brain solves practice problems. Only the solutions that really pass
their tests are kept. The small local 7B brain learns from them on a free Kaggle GPU. It
replaces the current one only if it scores better on an exam it never saw.

| # | Step | What it means | Command | Status |
|---|---|---|---|---|
| 1 | Practice problems | small Python bugs, each with tests that fail (`evaluation/training/`, 41 of them) | written by hand | done |
| 2 | Practice runs | AICA solves each one, and it is kept only if its tests pass when re-run separately afterwards | `aica --actor mohammed adapt practice` | 19 good runs; ~18 tasks left |
| 3 | Collect | screen the kept runs (secrets, risky commands, failures) into candidates | `aica adapt collect` | not yet: needs `[adaptation] collection_enabled = true` in `config/policy.toml` |
| 4 | Approve | the owner reads each candidate and approves or declines it | `aica adapt candidates`, `aica adapt approve <id>` | owner |
| 5 | Dataset | build the lessons: one "plan" lesson per run plus one "fill in" lesson per step filled in after reading | `aica adapt dataset` | needs 50+ lessons (47 now) |
| 6 | Plan | fix the training recipe (base model, epochs, rank) | `aica adapt plan --name aica-coder --base qwen2.5-coder-7b --dataset <v>` | |
| 7 | Export | stage everything for Kaggle, plus `review.md` with every lesson in plain text; uploads nothing | `aica adapt export --job <v> --kaggle-user tabu73 --out .aica/export` | |
| 8 | Owner review | the owner reads `.aica/export/review.md` before anything leaves the PC | read the file | owner |
| 9 | Upload and train | a private dataset and notebook on Kaggle's GPU, about 20-40 minutes | `kaggle datasets create -p .aica/export`, then `kaggle kernels push -p .aica/export/kernel` | owner runs these |
| 10 | Bring back | download the adapter and load it into Ollama on top of `qwen2.5-coder:7b` | `kaggle kernels output ...`, `ollama create aica-coder-1 -f Modelfile` | |
| 11 | Exam | run the 9 held-out agent tasks with and without the adapter | `aica eval run --adapter <id>`, `aica eval run --model qwen2.5-coder-7b` | |
| 12 | Decide | promote only if it passes the quality gate and every security task | `aica adapt evaluate`, `aica adapt promote` (undo: `aica adapt rollback`) | |

**Next action:** once Groq's daily limit resets, run step 2 for the tasks that have no kept run
yet, then steps 3 to 8, and stop for the owner.

## When stuck

- **Groq free tier:** 200,000 tokens a day for `qwen/qwen3.8-27b`. A run needs about 8k.
  When it is used up, the fallbacks are weak for agent work: GLM is often overloaded, and
  Gemini failed 3 of 3 practice tasks. Wait for the reset rather than training on bad data.
- **Local 7B context:** Ollama serves `qwen2.5-coder:7b` with 4,096 tokens, and agent
  planning needs 32,000. Before the exam (step 11), start Ollama with
  `OLLAMA_CONTEXT_LENGTH=32768` and raise `context_window` in `config/models.toml` to match.
  It runs on CPU, so expect minutes per task.
- **Credentials** live only in user environment variables, never in files: `GROQ_API_KEY`,
  `GEMINI_API_KEY`, `GLM_API_KEY`, `SLACK_BOT_TOKEN`, `SLACK_APP_TOKEN`, `KAGGLE_USERNAME`,
  `KAGGLE_KEY`, `GITHUB_TOKEN`.
- **Verify before claiming anything:** `scripts\verify.cmd` (ruff, format, mypy, pytest). CI
  runs the same on Linux and Windows for every PR.
- **Shell quirk (for Claude Code sessions):** inline `python - <<'EOF'` scripts sometimes turn
  `\n` inside string literals into real newlines. Write the script to a scratch file, or use the
  Edit tool, for anything containing escapes.
- **Git:** deleting remote branches is refused by the auto-mode permission check, so leave that
  to the owner. Work on a branch, open a PR, and merge only when CI is green.
