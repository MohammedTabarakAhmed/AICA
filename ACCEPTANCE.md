# Acceptance & Verification Matrix

This file converts the BRD into an implementation checkpoint system. Checkboxes
must only be ticked after implementation and applicable verification.

Priority note: BRD priorities are not repeated per line. The following IDs are
**Should** priority in the BRD; all other BRD IDs are **Must**:
CC-006, CHAT-006, CHAT-007, AG-008, RAG-005, RAG-009, FS-004, FS-007, EXEC-004,
GIT-006, GIT-008, GIT-009, TEST-003, TEST-004, TEST-008, WEB-003, WEB-004,
WEB-005, DB-003, DB-006, MM-004, MM-010, MM-014, MEM-004, MCP-007, INT-004,
INT-005, ADM-010, REV-003, REV-005, EVAL-007.

IDs prefixed `API-`, `NFR-`, `SEC-` and `LANG-` are not BRD-native; they are
derived here from un-numbered BRD sections (15, 17, 16, 9.1) so those
requirements are not lost. The BRD section is cited on each line.

## Phase 0 — Foundation and Controls

- [x] Repository/project structure established (`pyproject.toml`, `src/aica/{policy,safety,audit,workspace}`, `tests/`, `config/`, `scripts/`; 2026-09-22)
- [x] Local development workflow documented (`README.md`; `scripts/verify.cmd|sh`; 2026-09-22)
- [x] Dependency management documented (`DEPENDENCIES.md` Dependency Record; 2026-09-22)
- [x] Python `.venv` rule implemented/documented if Python is used (`.venv` created with Python 3.14.7, git-ignored, documented; 2026-09-22)
- [x] Git working-tree protection implemented (`aica.workspace.GitGuard`: uncommitted-change detection per target path, protected-branch check; 9 tests; library only — wiring into filesystem/Git tools happens in Phase 1 under GIT-010; 2026-09-22)
- [x] Secret handling and `.gitignore` protections established (`.gitignore`, `.env.example`, `aica.safety.redaction` applied to all audit records; 2026-09-22)
- [x] Bounded autonomy policy established (`config/policy.toml` + `aica.policy.AutonomyLimits` + `RunBudget`/`CancellationToken`; 2026-09-22)
- [x] Approval policy established (`aica.policy.ApprovalPolicy`, `aica.safety.commands.decide` -> allow/require_approval/block; 2026-09-22)
- [x] Prompt-injection defense baseline established (`aica.safety.injection`: untrusted-content fencing with nonce + pattern scan; 2026-09-22)
- [x] Audit/observability baseline established (`aica.audit`: redacted `AuditEvent` schema, JSONL sink, `AuditLog` facade; 2026-09-22)

## Phase 1 — MVP Coding Workspace

### Chat / Completion
- [x] CC-001 inline completion (`CodingAssistant.complete`, `aica complete --file --line`; FIM endpoint or chat fallback)
- [x] CC-002 multi-line/function completion (`max_tokens`, block output; fence stripping)
- [x] CC-003 repository context (completion injects retrieved project symbols, excluding the edited file)
- [ ] CC-004 language/framework con- [x] CC-004 language/framework conventions (`workspace.project_context.detect_conventions` reads line length, indent, quote style, frameworks, tooling and test layout from pyproject/package.json/.editorconfig/sources, with the evidence file recorded per item; the block is injected into the chat and completion system prompts and asserted in the prompt the model receives; `aica conventions`)
- [ ] CC-005 accept/reject/partial accept (requires the IDE surface, INT-001 — Phase 4)
- [x] CC-006 completion model policy (completion goes through the same gateway; a distinct model is selectable per call)
- [x] CC-007 credential/secret leakage protection (`_SECRET_LIKE` suppression + redaction of all model output)
- [x] CHAT-001 code questions (`CodingAssistant.ask`, `aica ask`)
- [x] CHAT-002 source-location explanations (retrieval carries `path:line-line`; citations extracted from the answer)
- [x] CHAT-003 editable proposed changes (answers return diffs/file contents applicable via `fs.write`/`fs.edit`)
- [x] CHAT-004 debugging with logs/context (`chat.diagnostics.parse_log` structures Python/Node/Java/compiler/pytest output into frames + error; project frames are separated from library frames; `CodingAssistant.debug` retrieves the implicated code via `RepositoryIndex.search_file`, attaches the log as untrusted and returns the diagnosis; verified against a traceback produced by really running failing code; `aica debug --log`)
- [x] CHAT-005 session context (`Session` + `build_context`, multi-turn, persisted)
- [x] CHAT-006 task-scoped attachments (`Attachment`, fenced as untrusted)
- [ ] CHAT-007 structured plans/diffs/tests/findings (report/diff/test structures exist; rich rendering needs the Web/IDE surface — Phase 4)

### Repository / RAG
- [x] RAG-001 repository indexing (`RepositoryIndex.index_repository`; verified on this repo: 75 files, 915 chunks, 573 symbols)
- [x] RAG-002 syntax/AST-aware chunking (Python via `ast`; brace-language, config, markdown and SQL chunkers; line spans asserted accurate)
- [x] RAG-003 semantic search (hashing embeddings + cosine; `AdapterEmbedder` ready for an approved embedding model)
- [x] RAG-004 lexical/symbol search (BM25-style inverted index + symbol table)
- [x] RAG-005 dependency relationships (imports, importers, references-to-symbol)
- [x] RAG-006 incremental indexing (content-hash skip, changed-file reindex, deleted-file removal)
- [x] RAG-007 authorization boundaries (every result filtered through `WorkspaceGuard`; test proves a restricted guard cannot retrieve other directories)
- [x] RAG-008 source locations (`SearchResult.location` = `path:start-end (symbol)`)
- [x] RAG-009 configurable retrieval depth (shallow/normal/deep)
- [x] RAG-010 RAG exposed as agent tool (`repo.index`, `repo.search`, `repo.dependencies`, `repo.stats`)

### Filesystem / Execution
- [x] FS-001 authorized directory discovery (`fs.list`, recursive + glob, escapes refused)
- [x] FS-002 file reading (`fs.read` with line ranges; sensitive files gated on approval)
- [x] FS-003 create/edit (`fs.write`, `fs.edit` with unique-match requirement; both return diffs)
- [x] FS-004 rename/move (`fs.move`)
- [x] FS-005 protected deletion (`fs.delete` behind the `file_delete` approval category; snapshotted first)
- [x] FS-006 diffs (unified diff returned by every mutation; `fs.diff` against snapshot or proposed content)
- [x] FS-007 snapshots/rollback (`SnapshotStore`, `fs.snapshot`, `fs.rollback`; delete is recoverable)
- [x] EXEC-001 approved shell commands (`shell.run`, classified and policy-checked before launch)
- [x] EXEC-002 stdout/stderr/exit codes (captured and returned; verified with a non-zero exit)
- [x] EXEC-003 command timeout (process killed; capped by `autonomy.max_seconds`)
- [x] EXEC-004 controlled environment variables (allowlisted host vars + task overrides; credentials not inherited)
- [x] EXEC-005 package/build/test execution (verified: AICA runs its own pytest/ruff/mypy)
- [x] EXEC-006 privileged/destructive command controls (5-way classification, chained commands judged by worst segment, block/approve per policy)
- [x] EXEC-007 command audit (command, class, exit code and redacted output tails recorded)

### Git
- [x] GIT-001 authorized repository access (`git.clone` behind network policy + EXTERNAL approval; workspace repo detection)
- [x] GIT-002 status/history/branches (`git.status`, `git.log`, `git.branches`)
- [x] GIT-003 branch creation/switching (`git.create_branch`, `git.switch`; protected names refused, dirty tree refused)
- [x] GIT-004 reviewable code changes (all mutations produce diffs before commit)
- [x] GIT-005 unified/file diffs (`git.diff`, staged/path/base variants)
- [x] GIT-006 meaningful commit messages (`chat.commit_message`: the model writes it, `validate_commit_message` accepts it only if the subject is imperative-length-bounded, non-placeholder and trailer-free, one retry feeds the rejection reason back, and a marked deterministic fallback covers model failure; verified through a real `git.commit`; `aica commit-message`)
- [x] GIT-007 commit policy (`git.commit`; protected-branch commits require approval)
- [x] GIT-008 PR preparation (`git.pr_content`: summary, change stat, tests, risk notes)
- [x] GIT-009 rollback/revert (`git.revert`; `git.discard` behind DESTRUCTIVE approval; plus FS-007 snapshots)
- [x] GIT-010 uncommitted user-change protection (every write checks the target path; overwriting needs explicit `allow_dirty` + approval)

### Testing
- [x] TEST-001 discover test commands (evidence-based across Python/Node/JVM/Go/Rust/Make; each choice records its reason)
- [x] TEST-002 unit tests (`test.run` with parsed counts; verified running this repo's own 199 tests)
- [x] TEST-003 integration tests (`tests/integration/` is a real cross-module suite over a real SQLite index, a real Git repository and real child processes — 6 tests; discovery reports `tests/integration` as the integration command and `test.run --kind integration` executes it; verified in-repo: `aica test --kind integration` -> 6 passed)
- [x] TEST-004 E2E tests (closed by the browser work: `tests/e2e` is discovered as `e2e`, and a generated Playwright test really ran under pytest and passed)
- [x] TEST-005 failure analysis (failures mapped to test name, file and line; `analyze_failures` output)
- [x] TEST-006 bounded correction/retest (closed by the Phase 2 agent loop: a failing test run triggers a bounded correction and a re-run; verified end to end - red suite -> source fix -> green suite -> SUCCESS - and bounded by `max_test_retries`)
- [x] TEST-007 test generation (`testing.generation.generate_tests`: language-correct test path and framework, project conventions and an existing test file as style exemplar, source fenced as untrusted; advisory — nothing is written, applying goes through `fs.write`; verified by writing a generated file and really running it; `aica gen-tests --file`)
- [x] TEST-008 coverage reporting when available (coverage percent parsed into the outcome)
- [x] TEST-009 prevent false success (`VerificationLedger`: success impossible unless every required check passed; failing counts override a zero exit code; skips disclosed)

### User Experience (BRD §14)
- [x] UX-004 show generated diffs (every mutation returns a unified diff; `TaskReport.render(include_diffs=True)`)
- [x] UX-005 show test status (passed/failed/skipped) (parsed counts in `TestOutcome.summary()`)
- [x] UX-009 final summary (outcome, changes, tests, warnings) (`TaskReport.render`)
- [x] NFR-001 progressive/streaming responses (SSE streaming adapter; `ask_stream` yields deltas; CLI streams by default)
- [x] LANG-001 Python: coding, RAG, testing, execution (AST chunking, pytest discovery/run — verified on this repo)
- [ ] LANG-002 Java: coding, RAG, testing, build (chunking + maven/gradle discovery implemented; not verified on a real Java repo)
- [ ] LANG-003 TypeScript/JavaScript (chunking + npm/vitest/jest/playwright discovery implemented; browser testing is Phase 2)
- [ ] LANG-004 Go: (chunking + `go test`/`go vet` discovery implemented; not verified on a real Go repo)
- [ ] LANG-005 Rust: (chunking + cargo discovery implemented; not verified on a real Rust repo)
- [x] LANG-006 SQL (statement chunking plus the database tools: dialect-correct generation, execution against SQLite verified end to end, PostgreSQL dialect statements asserted directly)
- [x] LANG-007 YAML/JSON/TOML and approved configuration formats (section chunking; indexed and retrievable)

## Phase 2 — Agentic Platform

### Agent
- [x] AG-001 high-level coding tasks (`aica.agent.AgentLoop.run`; `aica task "<description>"`; verified end to end on a real project where the agent edited code and made a failing suite pass)
- [x] AG-002 explicit plans (`Planner` -> validated JSON `Plan`; a step naming an unknown or policy-forbidden tool is rejected before anything runs (MCP-004); one retry feeds the rejection back; `aica task --plan-only` shows the plan without executing)
- [x] AG-003 multi-step tool calls (every step goes through `ToolRegistry.call`, so the workspace guard, approval gates, GIT-010 protection and MCP-006 audit apply unchanged; the loop holds no permissions of its own)
- [x] AG-004 observe/adapt (a failed step - raised *or* returned, e.g. a red test suite - is fed back to the model, which replaces/retries/skips/aborts; retries are capped at two identical attempts; verified: the agent saw a real pytest failure, revised the plan, fixed the source and the rerun passed)
- [x] AG-005 long-running/resumable tasks (`AgentState.to_json`/`from_json` carries plan, step statuses, ledger, changes and counters; verified across two separate loop instances and through a saved session file)
- [x] AG-006 cancellation (`CancellationToken` checked before every step; verified that a cancel during planning leaves the workspace untouched and reports CANCELLED)
- [x] AG-007 bounded autonomy (`RunBudget` step/time caps default from policy; adaptations are separately bounded by `max_test_retries`; plan size capped at 40 steps)
- [x] AG-008 specialist/subagents (`aica.agent.subagents`: the four BRD roles - research, implementation, testing, review - each with a fixed tool list, reached through a run-scoped `agent.delegate` tool; a subagent's tools and policy groups are **intersections** with the parent's, its steps are carved from the parent's budget and charged back, it shares the parent's cancellation token, and it cannot delegate further; the child's changes and verification ledger are folded into the parent's, so a check the child failed or could not run leaves the parent INCOMPLETE; verified over a real repository - an implementation subagent really edited the source and a real pytest run proved it, a review subagent's attempt to edit was refused at plan time with `git status` left clean, and a red child suite kept the parent INCOMPLETE)
- [x] AG-009 verification before success (the loop runs any required check the plan skipped, and `TaskReport.succeeded` reads the ledger; verified both ways - a real fix reports SUCCESS, a cosmetic non-fix reports INCOMPLETE with `unit: failed`)
- [x] AG-010 complete task summary (`TaskReport`: outcome, model, file changes with diffs, verification disclosure, warnings, unresolved items, steps and duration)
- [x] UX-001 live task progress (`AgentEvent` stream; the CLI prints `[2/5] tool_called (fs.edit): ...` as it happens)
- [x] UX-002 plan and completed steps visible (`PLAN_CREATED`/`PLAN_REVISED` events carry the rendered plan with a status mark per step)
- [x] UX-003 tool execution status (`StepStatus` on every step/tool event: running, succeeded, failed, skipped)
- [x] UX-006 pause/resume/cancel controls (all three over the API: pause stops at the next step boundary and persists the run state, resume continues it, cancel stops without resuming; the CLI keeps `aica task --resume`)
- [x] NFR-002 tasks survive UI navigation and support resume (BRD §17) (a task runs on the server, not in the client: the event stream replays from the beginning, so disconnecting and reconnecting loses nothing, and pause/resume persists state across processes)
- [x] API-001 create agent session (repository, branch, model, policy) (BRD §15) (`POST /sessions`)
- [x] API-002 run/resume task (BRD §15) (`POST /sessions/{id}/tasks`, `resume: true`)
- [x] API-003 stream events: model output, plan, tool calls, tests, status (BRD §15) (`GET /tasks/{id}/events` (server-sent events, replayed from the start))
- [x] API-004 cancel task (BRD §15) (`POST /tasks/{id}/cancel`)
- [x] API-005 pause/resume with persisted task state (BRD §15) (`POST /tasks/{id}/pause` writes `AgentState` into the session, `/resume` continues it)
- [x] API-006 repository context search (BRD §15) (`POST /context/search`)
- [x] API-007 apply changes to authorized files (BRD §15) (`POST /files`)
- [x] API-008 run approved command in task workspace (BRD §15) (`POST /commands`)
- [x] API-009 run tests (BRD §15) (`POST /tests`)
- [x] API-010 git operation (BRD §15) (`POST /git`)
- [x] API-011 session history (BRD §15) (`GET /sessions`, `GET /sessions/{id}`)

### Browser / Database / MCP
- [x] WEB-001 authorized application navigation (`browser.open`/`browser.navigate`; every URL resolves its host through `BrowserPolicy` - loopback allowed by default, anything else must be allowlisted; a refused host never starts a browser, asserted)
- [x] WEB-002 browser interactions (`browser.click`, `browser.fill`, `browser.press`, `browser.read`; verified by a real login flow in real Chromium against a real local HTTP server)
- [x] WEB-003 page/console/error evidence (`browser.evidence`: screenshot file, console output, page errors, network failures **and HTTP >= 400 responses**; verified against a page that really logs an error, really throws and really 404s)
- [x] WEB-004 E2E regression (`tests/e2e` discovered as the `e2e` kind and run through `test.run`; a generated Playwright test was executed by pytest as a child process and passed)
- [x] WEB-005 browser test generation/update (`aica.testing.browser_tests`: deterministic render from the recorded actions - selectors that demonstrably worked - optionally improved by the model, which falls back to the draft if its reply is not a test; `update_browser_test` refuses to replace a suite with prose; `aica browse --gen-test`)
- [x] WEB-006 external/production approval (a non-local target passes the EXTERNAL gate; a production environment classification adds the PRODUCTION gate; both asserted with a denying approver)
- [x] DB-001 authorized schema inspection (`db.connections`, `db.schema`; connections are **named in configuration and never supplied by a model** - a tool call cannot pass a DSN; verified against a real SQLite database **and against a real PostgreSQL 17 server**, including `information_schema` columns, nullability, primary keys and `pg_indexes`)
- [x] DB-002 dialect-correct SQL (dialect layer verified on **both real engines**: SQLite with `sqlite_master`/`pragma_table_info`/`EXPLAIN QUERY PLAN`/`?`, PostgreSQL 17 with `information_schema`/`pg_indexes`/`EXPLAIN (FORMAT TEXT)`/`%s`; migrations are rejected when they use the other engine's syntax)
- [x] DB-003 query plans/explanations (`db.explain`; verified on a real database - the plan shows the index being used. EXPLAIN ANALYZE is refused for non-read statements because it would execute them)
- [x] DB-004 read-only query automation (`db.query` refuses anything that is not a read; parameters are bound, never interpolated - an injection attempt through a parameter is asserted to change nothing; results are capped by the connection's `max_rows` and truncation is disclosed)
- [x] DB-005 write/destructive protection (three layers, verified on both engines: a read-only connection is opened read-only **at the engine** - bypassing the classifier raises `attempt to write a readonly database` on SQLite and `ReadOnlySqlTransaction` on PostgreSQL; writes need `database_write` approval; DROP/TRUNCATE/unqualified DELETE or UPDATE additionally need `destructive` approval; a production-classified connection adds the `production` gate)
- [x] DB-006 migration generation/review (`aica.database.migrations`: generates, never applies; every statement is classified and the review names each destructive one with its data risk; DROP DATABASE/SCHEMA, TRUNCATE and GRANT/REVOKE are refused outright; `aica db migration`)
- [x] DB-007 database audit (every call records the connection, dialect, statement and classification; asserted that the statement is in the trail and the rows it returned are not)
- [x] MCP-001 MCP servers (`aica.mcp`: newline-delimited JSON-RPC over a child process's stdio, the `initialize`/`notifications/initialized` handshake, `tools/list` and `tools/call`; verified against a real MCP server running as a real child process, including banner lines, unsolicited notifications, a server that dies mid-call and one that never answers)
- [x] MCP-002 tool schema discovery (`Tool.schema()` JSON Schema; `ToolRegistry.schemas`)
- [x] MCP-003 argument validation (pydantic `extra="forbid"` models; malformed calls rejected before execution)
- [x] MCP-004 tool policy (`allowed_tools` groups; disabled tools are not exposed and cannot be called)
- [x] MCP-005 baseline tools (filesystem, Git, execution, retrieval, browser and database are all available natively, and external servers add to them through the same registry - the BRD's "native/MCP mechanisms" in both forms)
- [x] MCP-006 tool-call audit (every invocation records arguments, outcome and duration, redacted)
- [x] MCP-007 organization tools (any approved server's tools appear as `mcp.<server>.<tool>` under the `mcp` policy group; `config/mcp.toml.example` documents an organization-specific server with an allowlisted environment; `aica mcp list|tools|call`)

## Phase 3 — Multi-Model, Memory and Governance

- [ ] MM-001 model registry (config-backed list with capabilities/policy state exists; administration UI/API is ADM-003, Phase 4)
- [x] MM-002 manual selection (`--model`, `ModelGateway.get(name)`)
- [x] MM-003 project default (`default` in `config/models.toml`)
- [ ] MM-004 task-specific model policy (per-call model selection works; declarative per-task policy not yet implemented)
- [ ] MM-005 GLM (configured and reachable through the adapter; NOT verified against a live GLM endpoint)
- [ ] MM-006 Kimi (configured and reachable through the adapter; NOT verified against a live Kimi endpoint)
- [ ] MM-007 DeepSeek (default model configured; adapter verified against a mocked OpenAI-compatible API, NOT against live DeepSeek)
- [x] MM-008 future-model adapter abstraction (`ModelAdapter` protocol; agent core depends on no model family)
- [ ] MM-009 automatic routing
- [ ] MM-010 fallback
- [ ] MM-011 version pinning
- [x] MM-012 model/version recording (exact served model id recorded per response, per session turn and in audit events)
- [x] MM-013 capability information (`ModelInfo` capabilities/context window; `aica models`)
- [ ] MM-014 approved model adapters
- [x] MEM-001 session persistence (`SessionStore`, JSON per session, redacted before write; `aica sessions`)
- [x] MEM-002 history summarization (rolling summary folds older turns past a threshold)
- [x] MEM-003 task-state resume (closed by the Phase 2 agent loop: `AgentState` is persisted into `Session.task_state` and resumed with `aica task --session ID --resume`; verified across two loop instances and a session round trip)
- [x] MEM-004 project context (`ProjectContextStore` persists conventions/preferences/notes in `.aica/project.json`, survives new sessions, tolerates a corrupt file, and is merged into the prompt with the detected conventions; `aica conventions --record/--set`)
 [x] SAFE-001 sensitive-action approval (approval categories enforced in `ToolContext.require_approval`; deny-by-default approver)
- [x] SAFE-002 proposed command visibility (`ConsoleApprover` prints tool, categories, action and classification before asking)
- [x] SAFE-003 protected-commit diff review (staged diff passed to the approver for protected-branch commits)
- [x] SAFE-004 repository authorization (`WorkspaceGuard` on every path; retrieval filtered; RBAC identity model is ADM-001, Phase 4)
- [x] SAFE-005 network policy (deny-by-default allowlist; enforced for model endpoints and `git.clone`)
- [x] SAFE-006 secret protection (redaction at the audit schema boundary, on model output, on session writes; secrets never indexed; credentials not inherited into subprocess env)
- [x] SAFE-007 prompt-injection defense (nonce-fenced untrusted content for retrieval and attachments; severity-ranked scanner; permissions never parsed from content)
- [x] SAFE-008 emergency stop (`CancellationToken` checked before every tool call and enforced on running subprocesses)
- [ ] UX-007 model selection before execution with capability information
- [ ] UX-008 approval requests displayed prominently
- [ ] API-012 list approved models and capabilities (BRD §15)
- [ ] API-013 select model: pin or policy-based routing (BRD §15)
- [ ] API-014 approval request/approve/reject (BRD §15)
- [ ] SEC-001 environment classification: development/test/production (BRD §16)
- [ ] SEC-002 tool allow/deny policies (BRD §16)
- [ ] SEC-003 network destination policy for browser and execution tools (BRD §16)
- [ ] SEC-004 controlled secret injection (BRD §16)

## Phase 4 — Integrations, Administration and Evaluation

- [ ] INT-001 IDE integration (not started — Phase 4)
- [x] INT-002 CLI (`aica`: index, search, deps, ask, complete, test, run, git, models, sessions, policy, audit)
- [ ] INT-003 Web application
- [ ] INT-004 approved collaboration integration
- [ ] INT-005 approved CI/CD integration
- [ ] INT-006 repository-provider integration
- [ ] ADM-001 RBAC
- [ ] ADM-002 project/repository administration
- [ ] ADM-003 model administration
- [ ] ADM-004 tool administration
- [ ] ADM-005 quotas
- [ ] ADM-006 usage reporting
- [ ] ADM-007 audit search
- [ ] ADM-008 policy management/versioning
- [ ] ADM-009 retention management
- [ ] ADM-010 configuration history
- [ ] REV-001 diff review
- [ ] REV-002 bug/edge-case review
- [ ] REV-003 convention review
- [ ] REV-004 test adequacy
- [ ] REV-005 security review
- [ ] REV-006 review summary
- [ ] REV-007 source locations
- [ ] EVAL-001 golden tasks
- [ ] EVAL-002 correctness
- [ ] EVAL-003 completion rate
- [ ] EVAL-004 tool reliability
- [ ] EVAL-005 RAG quality
- [ ] EVAL-006 model comparison
- [ ] EVAL-007 latency/resource metrics
- [ ] EVAL-008 regression gates
- [ ] EVAL-009 reproducibility metadata
- [ ] API-015 audit retrieval (BRD §15)
- [ ] SEC-005 configurable retention/deletion of sessions, source-derived context, trajectories (BRD §16)
- [ ] SEC-006 administrative separation of duties for model/tool approval (BRD §16)
- [ ] SEC-007 immediate disable of a model, tool or integration (BRD §16)
- [ ] NFR-003 concurrency-aware behavior for multi-user/multi-repository sessions (BRD §8)
- [ ] NFR-004 material actions attributable to user/session/agent/tool (BRD §17 Auditability)

## Phase 5 — Fine-Tuning / Adaptation

- [ ] Approved trajectory/data collection
- [ ] Unsafe/low-quality data filtering
- [ ] SFT support where appropriate
- [ ] QLoRA/adapters where appropriate
- [ ] Base-model/adapter separation
- [ ] Dataset/config/adapter versioning
- [ ] Golden-task evaluation
- [ ] Security and quality promotion gates
- [ ] Rollback
- [ ] Secret/restricted-data exclusion

## Business Acceptance

- [ ] Approved model selection including DeepSeek
- [ ] Same task can run against another approved model
- [ ] Chat/completion/RAG/agent experiences integrated
- [ ] Repository understanding → edit → test → report works
- [ ] Filesystem/Git/terminal/browser/database are policy controlled
- [ ] Agent recovers from failures within limits
- [ ] Protected changes are reviewable
- [ ] Pause/resume/cancel works
- [ ] Retrieval respects authorization
- [ ] Sensitive operations can require approval
- [ ] Model/version/tool/material action records exist
- [ ] Admins can approve/disable models/tools
- [ ] Models can be evaluated on the same task suite
- [ ] Model/adapter promotion is controlled
- [ ] Final reports contain outcome, changes, verification and unresolved issues

## Verification Record

For each completed phase, record:
- date;
- commands/checks executed;
- result;
- important failures and fixes;
- unresolved issues;
- commit/branch if applicable.

### Phase 1 (MVP) — 2026-09-22
- Commands: `scripts/verify.sh` (ruff check; ruff format --check; mypy strict; pytest --cov).
- Result: ruff clean, 54 files formatted, **mypy 0 issues in 42 source files**, **199 passed**, **90% coverage**, zero warnings.
- Live end-to-end on this repository via the installed `aica` CLI:
  - `aica index` -> 75 files, 915 chunks, 573 symbols, 6 languages;
  - `aica search` (hybrid and symbol modes) -> correct `path:line-line` locations;
  - `aica deps --symbol classify_command` -> definition plus 5 cross-file references;
  - `aica test --kind unit|lint|typecheck` -> AICA runs its own pytest/ruff/mypy and reports PASSED;
  - `aica run rm -rf src` -> approval gate fired, denied non-interactively, `src/` intact;
  - `aica audit` -> full trail of the above with outcomes.
- Bugs found and fixed during verification: audit context blanked by explicit `None`;
  Windows `list2cmdline` mangling quoted commands; ledger update rule wrong on fix-after-fail;
  cargo/maven counts shadowed by the pytest parser; named sections merged away in chunking;
  TOML section keys lost to bracket stripping; `unchanged` conflated with `skipped`;
  argparse consuming the target command's flags; `ConsoleApprover` crashing without stdin;
  SQLite connections leaked; discovered commands using POSIX separators on Windows.
- Unresolved: see the unticked Phase 1 items above, each annotated with why.
- Commit/branch: no commit made (awaiting authorization).

### Phase 0 — 2026-09-22
- Commands: `ruff check src tests`; `ruff format --check src tests`; `mypy` (strict);
  `pytest --cov=aica --cov-report=term-missing`; `scripts/verify.sh`; `scripts/verify.cmd`.
- Result: ruff clean, 19 files formatted, mypy 0 issues in 15 files, **72 passed**, 97% coverage.
- Failures and fixes: initial ruff run reported E501/N818/S105/S607 — resolved by
  `ruff format`, ignoring N818 project-wide (exception naming), and justified `noqa` on
  the enum literal `"secret_access"` and the fixed-argv `git` subprocess call.
- Unresolved: Phase 0 modules are libraries; they are not yet enforced on a tool path
  because no tools exist. Enforcement is verified per requirement in Phase 1+.
- Commit/branch: Git initialized; no commit made (awaiting authorization).
