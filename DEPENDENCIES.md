# Dependencies & Environment Contract

## Purpose

Track runtime, development, model, tool and environment dependencies. Do not add a
dependency merely because it is convenient; justify material additions.

## Environment Rules

### Python

If Python is used:

```cmd
python -m venv .venv
```

Use the project virtual environment for Python dependencies.

Windows/CMD activation:

```cmd
.venv\Scripts\activate
```

Do not install project packages globally when the project environment is available.

Do not commit:
- `.venv/`
- `.env`
- credentials
- private keys
- generated secret/config files

Use `.env.example` for documented configuration shape where appropriate.

## Dependency Recording

For every material dependency addition record:
- package/tool name;
- version or supported range;
- purpose;
- where it is used;
- security/licensing considerations;
- whether it is runtime or development-only;
- verification performed.

## Model Dependencies

The BRD requires a model abstraction capable of supporting approved model families,
including:
- GLM;
- Kimi;
- DeepSeek;
- future approved models.

The core agent must not be hard-coded to a single model family.

Model records should retain, where available:
- model name;
- exact version;
- capabilities;
- context limit;
- policy/approval state.

## Tool Dependencies

Expected capability families include:
- filesystem;
- Git;
- shell/code execution;
- testing;
- browser automation;
- database/SQL;
- MCP;
- repository indexing/RAG.

Tools must be policy-controlled and argument-validated.

## Development Tooling

Use the project's existing:
- formatter;
- linter;
- type checker;
- test runner;
- package manager;
- build system.

Do not replace existing tooling without a documented reason.

## Reproducibility

Material tasks should record model/version/tool/policy context. Dependency changes
must be reproducible from a clean environment.

## Security

Before adding a package:
- prefer maintained and reputable packages;
- avoid unnecessary dependencies;
- review permissions and network behavior when relevant;
- pin or bound versions appropriately;
- run the project's security/dependency checks when available.

## Dependency Record

### Environment (2026-09-22)
- Python 3.14.7 (`C:\Python314`) in `.venv`; `requires-python >= 3.12`. Python 3.11 is
  also installed but `tomllib`/`StrEnum`/`datetime.UTC` usage needs 3.11+; 3.12 floor chosen
  for `Path.is_relative_to` semantics and current wheel availability.
- Git 2.52.0; Node 24.19.0 present but unused in Phase 0.
- Package manager: pip + `pyproject.toml` (setuptools). Install: `pip install -e ".[dev]"`.

### Runtime
| Package | Range | Purpose | Used in | Notes |
|---|---|---|---|---|
| pydantic | >=2.9,<3 (installed 2.13.5) | Validated policy schema, audit events, tool-argument validation (MCP-003), model/session schemas | `aica.policy`, `aica.audit`, `aica.tools`, `aica.models`, `aica.chat` | MIT; no network behaviour |
| httpx | >=0.27,<1 (installed 0.28.1) | HTTP client for the OpenAI-compatible model adapter, incl. SSE streaming and a mockable transport for tests | `aica.models.openai_compat` | BSD-3; the only component that makes outbound requests, and only to hosts allowed by `[network]` policy |

Standard library carries the rest of Phase 1: `sqlite3` (RAG index), `ast` (Python
chunking), `subprocess` (execution and Git), `difflib` (diffs), `tomllib`, `hashlib`,
`argparse` (CLI). No vector-store, embedding, parser or web framework dependency was
added: semantic retrieval uses deterministic hashing embeddings (see `.claude-progress.md`
Entry 011).

### Development-only
| Package | Range | Purpose | Verified |
|---|---|---|---|
| pytest | >=8.3,<9 (8.4.2) | test runner | 199 tests pass |
| pytest-cov | >=6.0,<7 (6.3.0) | coverage report (TEST-008) | 90% on `aica` |
| ruff | >=0.8,<1 (0.16.8) | lint + format (rules E,F,I,B,UP,S,N,W; E501 delegated to the formatter) | clean |
| mypy | >=1.13,<2 (1.20.2) | strict type check | clean (52 source files) |
| playwright | >=1.48,<2 (1.63.0) | browser automation, `browser` extra (WEB-001..006) | real Chromium login flow, evidence capture and screenshot verified |
| pytest-playwright | >=0.5,<1 (0.9.0) | runs generated E2E tests (WEB-004) | a generated test was executed by pytest and passed |

### Decided during Phase 1 (see `.claude-progress.md` Entries 010-013)
- Model access: OpenAI-compatible HTTP via httpx; DeepSeek default, GLM/Kimi configured but disabled.
- Retrieval: SQLite index + hashing embeddings; `AdapterEmbedder` ready for an approved embedding model.
- Execution: subprocess within the authorized workspace, policy-gated.
- CLI: stdlib `argparse`, entry point `aica = "aica.cli:main"`.

### Decided during Phase 2 (see `.claude-progress.md` Entries 016-019)
- Browser engine: **Playwright**, Chromium + Firefox + WebKit installed. Kept as the optional
  `browser` extra: `pip install -e ".[browser]"`, then `python -m playwright install chromium`.
  The browser binaries live outside the repository (under `%LOCALAPPDATA%`) and are roughly
  300MB; the tools import playwright lazily and print this install hint when it is absent.
- Database dialects: **PostgreSQL and SQLite**. SQLite uses the standard library, so the core
  install needs nothing. PostgreSQL needs the optional `postgres` extra:
  `pip install -e ".[postgres]"` (psycopg 3.3.6 installed and verified against a real
  PostgreSQL 17.11 server on 2026-09-23).
- MCP transport: **local process (stdio) first**, a network transport added later behind the
  same client interface (not yet implemented).

- HTTP API framework: **FastAPI + uvicorn**, optional `api` extra
  (`pip install -e ".[api]"`). Chosen because request validation reuses the pydantic models the
  tools and policy already define, so the API contract cannot drift from the tool contracts,
  and because streaming responses cover API-003 without extra machinery.

### Added for INT-004 Slack (2026-09-26, see `.claude-progress.md` Entry 039)
| Package | Range | Purpose | Used in | Notes |
|---|---|---|---|---|
| slack_sdk | >=3.44,<4 (installed 3.44.1) | Socket Mode client only: the outbound WebSocket Slack delivers button presses and mentions over | `aica.integrations.slack.socket_client` | MIT; **no dependencies of its own**. Optional `slack` extra (`pip install -e ".[slack]"`), imported lazily, so only `aica slack run` needs it. The Web API calls (post, update, ephemeral) use the existing httpx, so they share a mockable transport with the rest of the code. The WebSocket host Slack returns is checked against `[network]` on every (re)connect. Verified: 32 tests, including the host check against the real `SocketModeClient` class |
| kaggle (CLI, owner's machine) | >=1.7,<2 | Uploads the staged training job as a private Kaggle dataset, pushes the private notebook, fetches its output | Run by the owner, never by `aica` (see `training/kaggle/README.md`) | Apache-2.0. Not a project dependency: installed into `.venv` only on a machine that trains. Credentials from `KAGGLE_USERNAME`/`KAGGLE_KEY` environment variables, never a file in the repository |
| Kaggle notebook stack (runs on Kaggle, not here) | transformers==4.56.2, peft==0.17.1, bitsandbytes==0.50.2, accelerate==1.10.1, sentencepiece==0.2.1; base weights `Qwen/Qwen2.5-Coder-7B-Instruct` (revision pinned at run time, recorded in `provenance.json`); llama.cpp `convert_lora_to_gguf.py` at run time | QLoRA training and the GGUF adapter export | `training/kaggle/qlora_adapter.ipynb` | Apache-2.0 (transformers, peft, accelerate, sentencepiece, Qwen2.5-Coder), MIT (bitsandbytes, llama.cpp). Pinned in the notebook so a run is reproducible; never installed on this machine |

### Still not chosen (deferred to their phases)
Web and IDE front-end frameworks (Phase 4 INT-001/003), the identity provider for RBAC, and
the durable store for audit/sessions at multi-user scale (Phase 4).

### Credentials
Never stored in configuration. `config/models.toml` names an environment variable
(`api_key_env`); the adapter reads it at construction and fails loudly if unset. The
endpoint host must also be allowlisted in `config/policy.toml` `[network]`.
