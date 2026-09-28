# AICA — AI Coding Assistant

**AICA** stands for **AI Coding Assistant**. It is an AI helper for programmers: it reads
your code, answers questions about it, writes and fixes code, runs the tests, and asks
a person before doing anything risky.

## What it does

- **Understands your repository**: searches code by meaning and by name, with file and line
  references.
- **Does multi-step tasks**: plans, edits files, runs the tests and reports honestly. A task
  only counts as done when the tests really passed.
- **Reviews changes** for bugs and security problems.
- **Works with your tools**: Git, GitHub, browsers, databases, MCP servers and Slack.
- **Uses any approved AI model**, with automatic fallback when one is unavailable.
- **Stays safe**: risky actions need human approval, secrets are hidden from logs, and every
  important action is recorded.

Use it from the command line, a web page, an HTTP API or VS Code.

## Quick start

```cmd
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
aica --help
```

Setup details, every command and the project's current state are in
[`BRIEFER.md`](BRIEFER.md).
