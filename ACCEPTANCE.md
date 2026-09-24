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
- [x] CC-004 language/framework conventions (`workspace.project_context.detect_conventions` reads line length, indent, quote style, frameworks, tooling and test layout from pyproject/package.json/.editorconfig/sources, with the evidence file recorded per item; the block is injected into the chat and completion system prompts and asserted in the prompt the model receives; `aica conventions`)
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

- [x] MM-001 model registry (`config/models.toml` is the registry: name, family, exact version, context limit, declared capabilities and an approval **status** per entry; `approved`/`deprecated` are usable and `pending`/`blocked` are refused at the gateway, so status is an enforcement point rather than a label; duplicate names and rules referencing a model that does not exist are rejected at load time; `aica models` and `GET /models` expose it. The administration UI is still ADM-003, Phase 4)
- [x] MM-002 manual selection (`--model`, `ModelGateway.get(name)`)
- [x] MM-003 project default (`default` in `config/models.toml`)
- [x] MM-004 task-specific model policy (`[[routing.rules]]` per `TaskKind`: completion, chat, coding, planning, review, testing, commit_message, embeddings, general - each may name a model, a fallback chain, extra required capabilities and a minimum context; every CLI command declares the kind of work it is about to do, and `POST /sessions/{id}/tasks` takes `task_kind`)
- [ ] MM-005 GLM (configured as a first-class family with status `pending` until approved and deployed; reachable through the OpenAI-compatible adapter and exercised against a mocked endpoint, but NOT verified against a live GLM endpoint)
- [ ] MM-006 Kimi (configured as a first-class family with status `pending` until approved and deployed; reachable through the OpenAI-compatible adapter and exercised against a mocked endpoint, but NOT verified against a live Kimi endpoint)
- [ ] MM-007 DeepSeek (default model configured; adapter verified against a mocked OpenAI-compatible API, NOT against live DeepSeek)
- [x] MM-008 future-model adapter abstraction (`ModelAdapter` protocol; agent core depends on no model family)
- [x] MM-009 automatic routing (`ModelRouter.select` builds the candidate order - named model, then rule, then default, then fallbacks - filters out anything that is not approved, enabled, capable of the work or large enough in context, and **records why each rejected candidate was rejected**; a model that cannot do the job is never tried in the hope it manages anyway)
- [x] MM-010 fallback (`FallbackAdapter` is itself a `ModelAdapter`, so the agent core is unchanged; it falls back only on **unavailability** - 500/502/503/429/408, a transport failure, or a credential not configured on this machine - and never on a 400 or a malformed answer, because that would hide a real fault behind a second opinion. Streaming falls back only before the first chunk reaches the caller, so two models' answers are never spliced together. Verified against real HTTP responses through an httpx transport, including a stream that dies halfway)
- [x] MM-011 version pinning (`pinned = true` fixes the exact served version: a pinned entry may not name a moving alias such as `latest`/`preview`/`stable` - it is rejected at load time - and the router never substitutes another model for a pinned one, so a pin beats the fallback chain)
- [x] MM-012 model/version recording (exact served model id recorded per response, per session turn and in audit events)
- [x] MM-013 capability information (`ModelInfo` capabilities/context window; `aica models`)
- [x] MM-014 approved model adapters (`adapter = "..."` names an approved LoRA/domain adapter; the provider serves it under its own id, so it replaces the request's `model` field while `version` still records the base model it sits on, and an adapter may only be configured for an `approved` base)
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
- [x] UX-007 model selection before execution with capability information (`aica models` prints each model's family, version, context window, capabilities, status, pin and adapter, plus the routing table; `GET /models` returns the same and additionally **which model each kind of work resolves to today** and why any candidate is unavailable. Graphical rendering belongs to the IDE/Web surfaces, Phase 4)
- [ ] UX-008 approval requests displayed prominently
- [x] API-012 list approved models and capabilities (`GET /models`, with `?include_unusable=true` to show entries that exist but may not be used together with the status that explains why - so a client shows "pending approval" instead of a model that silently is not there)
- [x] API-013 select model: pin or policy-based routing (`POST /sessions/{id}/tasks` takes `model` to pin one by name or `task_kind` to let the routing policy choose; the 202 response returns the chosen name, the exact version, the reason and the fallback chain, and the session records what answered for it)
- [ ] API-014 approval request/approve/reject (partial and deliberately so: `GET /approvals` publishes the contract and `POST /approvals/{id}` records an audited decision, but there is **no server-side pending queue** - an action needing approval is refused with 409 and the client re-sends it with `auto_approve`. A real queue needs identity and RBAC, which is ADM-001)
- [x] SEC-001 environment classification: development/test/production (BRD §16) (`Environment` on the policy, and it now **does** something: every tool declares `mutating`, and `Tool.invoke` puts any mutating call behind the PRODUCTION approval gate once the environment says production - so an ordinary `fs.write`, which was ungated in every environment before, is gated there. Read-only tools are not gated, or the classification would be unusable. `tools.deny_in_production` additionally withdraws named tools in that environment only. A test asserts the mutating/read-only split is complete, so a new write tool cannot silently escape the gate)
- [x] SEC-002 tool allow/deny policies (BRD §16) (`ToolPolicy`: `deny` **always wins** - over `allow`, over the group allowlist, over everything - because switching a tool off must not depend on remembering every list that might turn it back on; `allow` narrows *within* the permitted groups and provably cannot widen them; patterns are an exact tool name, a group, or a prefix. Enforced in `ToolRegistry`, the same point every call already passes through, and denied tools are absent from the advertised tool list so a model is never offered a tool policy will refuse. `denial_reason` names which list refused, rather than a bare "not permitted")
- [x] SEC-003 network destination policy for browser and execution tools (BRD §16) (the browser has enforced a destination allowlist since WEB-001; **execution had not** - a network command was classified EXTERNAL and sent to the approval gate, but nothing checked *where* it was going, so one approval let `curl` reach any host. `aica.safety.network` extracts destinations from URLs, scp/ssh targets and bare host arguments, and `shell.run` refuses a host outside `[network].allowed_hosts` **before** the approval gate, because approving "this talks to the network" was never approval of the destination. Only commands that actually invoke a network client are checked, loopback is allowed as the dev-server case, and a command whose host cannot be read (`git push`) keeps the gate it already had rather than being guessed at)
- [x] SEC-004 controlled secret injection (BRD §16) (`SecretPolicy`/`SecretStore`: a caller **names** a secret and can never supply one, because a value passed as a tool argument has already travelled through the prompt, plan and session file before any gate runs; only secrets declared in policy exist, each naming which tools may receive it; the value is read from the host environment at the moment of use and never stored, cached, returned or logged; injection is an audited SECRET_ACCESS approval recorded **by name**; and the injected values are scrubbed literally from stdout/stderr, since pattern redaction only catches formats it recognises. A declared-but-unset secret fails loudly rather than injecting an empty string that would fail far away looking like a bug in the command)

## Phase 4 — Integrations, Administration and Evaluation

- [ ] INT-001 IDE integration (not started — Phase 4)
- [x] INT-002 CLI (`aica`: index, search, deps, ask, complete, test, run, git, models, sessions, policy, audit)
- [ ] INT-003 Web application
- [ ] INT-004 approved collaboration integration
- [ ] INT-005 approved CI/CD integration
- [ ] INT-006 repository-provider integration
- [x] ADM-001 RBAC (`RbacPolicy`/`Principal`: four roles - viewer, developer, approver, admin - assigned per principal in `config/policy.toml`. **Roles only ever narrow**: a principal's permissions are intersected with what policy already allows, so the admin role cannot grant a tool the policy file withholds and identity can never be a way around the existing controls. Approving is deliberately *not* implied by administering - they are different jobs, and merging them turns four eyes into one pair. Enforced in `ToolRegistry` (read vs write by the tool's own `mutating` flag), at the approval gate, and on every administrative change. An unlisted principal gets `default_role` (viewer), so a misconfiguration fails closed. Off by default so an existing single-developer workspace is unchanged: the whole suite passes identically with it disabled)
- [ ] ADM-002 project/repository administration
- [x] ADM-003 model administration (approval status, exact version pinning and retirement already live in the model registry `config/models.toml` (MM-001/MM-013); the **immediate** half is the control plane: `aica admin disable model <name>` stops it being served on the next call. The check runs *before* the adapter cache on purpose - a model already built for a long-running server must stop being served at once, or "immediately" means "after the next restart")
- [x] ADM-004 tool administration (policy approves tools (SEC-002); `aica admin disable tool <name|group>` withdraws one now, enforced in `ToolRegistry` on every call, covering a whole group so an operator does not have to enumerate five database tools mid-incident. Disabled tools also disappear from the advertised tool list)
- [ ] ADM-005 quotas
- [ ] ADM-006 usage reporting
- [ ] ADM-007 audit search
- [ ] ADM-008 policy management/versioning
- [ ] ADM-009 retention management
- [x] ADM-010 configuration history (every administrative change is appended to `.aica/admin/history.jsonl` with actor, timestamp, target and reason, and is never rewritten - so "why is this off?" is answerable months later, and so is "who turned it back on". `aica admin history`, `GET /admin/history`. A damaged line is skipped rather than hiding the rest of the record)
- [x] REV-001 diff review (`src/aica/review/`: the diff is parsed into files and post-image line numbers first, then reviewed by four checks; `aica review`, `POST /review`. New, untracked files are included by default - `git diff` cannot see them, and a new module is what an agent most often produces - by synthesising an all-added diff from the file rather than staging it, so a read-only question leaves the index untouched (GIT-010))
- [x] REV-002 bug/edge-case review (the correctness check prompts for the defect classes worth naming: boundary and off-by-one errors, unreleased resources, errors swallowed or reported as success, state mutated while iterated, a contract whose callers were not updated)
- [x] REV-003 convention review (the conventions detected for CC-004/MEM-004 are supplied to a check of their own, instructed to report a real departure and not anything a formatter or linter would fix)
- [x] REV-004 test adequacy (two layers: a **deterministic** one that decides whether the change altered logic at all and whether any test covers the file - by a test changed in the same diff, matched on path *or* on the test's contents, or by a test in the repository that names the module - and a model check given that evidence and asked only for the part it cannot decide, which branch is unexercised. Comment, import and docstring-only changes are not reported as untested)
- [x] REV-005 security review (a CWE-tagged pattern scan of the **added** lines only - SQL and shell injection, dynamic evaluation, unsafe deserialisation, disabled TLS verification, broken hashes, hardcoded credentials, path traversal, XSS, predictable randomness, swallowed exceptions - suppressible per line with `# nosec`, plus a model check asked for what a single-line pattern cannot see)
- [x] REV-006 review summary (`ReviewReport` groups findings by severity and by file, renders text and JSON, and records provenance per finding: which check produced it and which model, or `None` for a deterministic one. The prose summary is prefixed with the deterministic counts, which cannot drift from the findings actually in the report; if the summary call fails the counts still stand)
- [x] REV-007 source locations (**enforced, not hoped for**: every model-proposed finding is resolved against the parsed diff before it enters the report - exact line, or re-anchored to the nearest visible line within 6 rows and *marked* as re-anchored, or dropped with a recorded reason. A finding naming a file outside the diff, or a line outside its hunks, never reaches the reader, and the report states how many were discarded)
- [x] EVAL-001 golden tasks (`evaluation/tasks/*.toml`: each task is one versioned, self-contained file - the repository it runs in is inline, so a task's history is visible in Git and running the suite never depends on a fixture someone edited by hand. Every task carries `id@vN` and a content checksum, and the suite has a checksum of its own. Four tasks ship: two bug/feature tasks, one retrieval task, and a control task that **cannot pass**, kept so the harness is shown to report failure)
- [x] EVAL-002 correctness (a task's own `verify` command decides, run as a separate process in the workspace after the agent says it is finished; the agent's report is recorded beside it and never consulted for the verdict. Verified: the agent really edits the source and a real pytest child process confirms it)
- [x] EVAL-003 completion rate (share of agent tasks that behaved as the suite expects; a control task meant to fail counts as correct when it fails, so adding honesty checks does not depress the score)
- [x] EVAL-004 tool reliability (counted from the agent's own event stream - calls made, calls failed, and arguments rejected before execution - excluding control tasks whose deliberate red test run is a correct call reporting a correct failure)
- [x] EVAL-005 RAG quality (a retrieval task names the files that genuinely answer its query; the harness indexes the workspace for real, searches, and reports precision, recall and reciprocal rank - the last because putting the right file *first* is what matters when the result is fed to a model with a limited context)
- [x] EVAL-006 model comparison (`Comparison` runs several reports side by side, **refuses** to compare different suite revisions rather than caveating it, ranks on correctness then reliability then speed, lists the tasks where models disagree, and excludes any model with a false success from winning at all. Verified against real report objects; **no two live models have been compared**, because none has answered)
- [x] EVAL-007 latency (measured per task; p50 and p95 by nearest rank, so a small suite reports a real measurement rather than an interpolation between runs that never happened. A gate can refuse a candidate that is too slow)
- [x] EVAL-008 regression gates (`evaluate_gate`: thresholds, plus a baseline comparison that catches a candidate still above the bar but clearly worse; a task the baseline passed and the candidate fails is a regression whatever the aggregate says; **one false success fails the gate outright** at any score; and a gate may only be evaluated against the same suite revision. `aica eval gate` exits non-zero on failure so CI can use it)
- [x] EVAL-009 reproducibility metadata (every report carries model name, exact served version, adapter, suite revision checksum, prompt checksum, policy version and the harness's own commit; reports round-trip to JSON with all of it)
- [x] API-016 review a change (`POST /review`; derived here from BRD §11, which has no API section of its own). Takes a diff or reviews the working tree, optional `checks`/`focus`, and returns the grouped findings plus `complete` - so a client cannot read an empty `findings` list from a half-failed review as approval
- [ ] API-015 audit retrieval (BRD §15)
- [ ] SEC-005 configurable retention/deletion of sessions, source-derived context, trajectories (BRD §16)
- [x] SEC-006 administrative separation of duties for model/tool approval (BRD §16) (enforced on the **actor**, checked against the recorded disabler rather than trusted from the request: the principal who switched a model or tool off may not be the one who turns it back on. Deliberately asymmetric - *disabling* needs no second pair of eyes, because switching something off is the safe direction and gating it is how an incident gets longer; *re-enabling* restores capability, so that is what a second principal must do. Configurable, and inert when RBAC is off)
- [x] SEC-007 immediate disable of a model, tool or integration (BRD §16) (`ControlPlane`: a small file the enforcement points re-read **per call**, so a disable takes effect on the next call with no policy edit, no reload and no restart - the policy file is the right instrument for a standing rule and the wrong one for an incident. It only ever subtracts: "enable" undoes a disable made here and can never grant what policy withholds, so the control plane is not a way around the policy file. Writes are atomic, and a corrupt control file **raises** rather than being read as "nothing is disabled", because the failure mode of guessing is that something switched off during an incident quietly comes back. `aica admin`, `GET|POST /admin/controls`)
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

### Phase 3 step 3 — code review capability (REV-001..007) — 2026-09-24
- New package `src/aica/review/`: `diff.py` (unified-diff parsing with post-image line
  numbers, file classification), `findings.py` (`Severity`, `Category`, `Finding`,
  `ReviewReport` grouped by severity and file), `adequacy.py` (deterministic REV-004),
  `security.py` (CWE-tagged pattern scan, REV-005), `reviewer.py` (`CodeReviewer`, four
  checks, anchoring, summary). Surfaces: `aica review` and `POST /review`.
- Design decision: **a finding must resolve to a line in the diff or it is not reported.**
  Model output is anchored against the parsed diff - exact, re-anchored within 6 rows and
  marked as such, or dropped with a recorded reason and a count in the report. REV-007 is
  therefore a property of the system rather than a hope about the model's arithmetic.
- Design decision: **test adequacy and the security scan are deterministic first.** Both
  run without a model, their findings carry `model=None`, and the model checks are given
  that evidence instead of being asked to reconstruct it. A review with no model is a
  narrower review, not a failed one, and the report's provenance shows which is which.
- Design decision: **an incomplete review is not a clean one** (the TEST-009 rule applied
  to review). A model error, unparseable output or a truncated diff sets `complete=False`;
  `aica review` exits 6 for that, distinct from 2 (findings) and 0 (clean), so a pre-merge
  hook cannot read a half-failed review as a pass.
- Commands run: `ruff check`, `ruff format --check`, `mypy` (79 files, clean), `pytest`
  (796 tests, all passing; 68 new). Review package line coverage 95%.
- **Two real bugs found by running the reviewer on its own change**, which is the only
  verification that matters for a tool like this:
  1. The test-adequacy logic detector matched bare English words (`for`, `or`, `not`), so a
     line of the CLI's *module docstring* was reported as untested changed logic. Keywords
     are now matched only where code puts them - opening a statement - and both the false
     positives and the true positives are pinned by parametrised tests.
  2. `git diff` cannot see untracked files, so every new file in the change - the whole new
     package - was invisible to the review. `git.diff` gained `include_untracked`, which
     synthesises an all-added diff from the file's contents rather than running `git add -N`,
     because writing to the index to answer a read-only question is what GIT-010 forbids. A
     test asserts nothing is staged.
  A third, milder one: the scanner flagged its own TLS pattern definitions. Fixed with the
  `# nosec` suppression the module already supports, and a test asserts the scanner stays
  clean against its own source.
- The reviewer also correctly reported that `git_tool.py` had changed with no test changed
  alongside it. That was true; `tests/test_tools_exec_git.py` gained four tests for the new
  untracked-diff path, and the finding then cleared.
- Unresolved: **no model has reviewed anything.** Every model-facing claim here rests on the
  scripted adapter. The four model checks are exercised for prompt content, parsing,
  anchoring, failure handling and summarisation, but the quality of a real model's findings
  is unmeasured until `DEEPSEEK_API_KEY` is set. A run without a model reports `model: none`
  and marks the model-dependent checks as not run.
- Known limit, stated in the report rather than hidden: a diff over 60,000 characters is
  truncated and the review is marked incomplete. Reviewing this very change hit that limit.
- Branch: `feat/agent-platform`.

### Phase 3 step 2 — evaluation harness (EVAL-001..009) — 2026-09-23
- Chosen over the review capability as the more future-proof next step: review is one feature,
  while evaluation is what makes every later change to prompts, routing, models or the agent
  loop measurable instead of anecdotal, and EVAL-008 protects what already exists.
- New package `src/aica/evaluation/`: `tasks.py` (golden tasks, checksums, verification),
  `metrics.py` (`TaskResult`, `SuiteReport`, `Provenance`, retrieval scoring), `runner.py`
  (`Evaluator`, scripted and router model factories), `gates.py` (`ReleaseGate`,
  `evaluate_gate`, `Comparison`). CLI: `aica eval run|gate|compare`.
- The design rule throughout: **the agent's report never decides anything.** Success comes
  from the task's own command, run as a separate process afterwards. Where the two disagree,
  the run is recorded as a false success - which fails the gate outright and disqualifies a
  model from winning a comparison, at any score.
- The suite ships a control task that **cannot pass** (two tests demanding different answers).
  If it ever passes, the scoring is wrong; if the agent reports SUCCESS on it, that is a
  false success rather than a low score.
- **Two bugs this found immediately, in code that was already "verified":**
  1. `_python_runner` fell back to the bare word `python` when a project had no `.venv`. On
     this machine that resolved to an interpreter without pytest, so **every discovered Python
     test command failed in a fresh workspace** - and on a Linux box with only `python3` it
     would not resolve at all. Now falls back to `sys.executable`, which is always real.
  2. A test in `tests/test_agent.py` asserted the *consequence* of that bug ("the check is
     recorded as skipped because the interpreter cannot run pytest"). It was rewritten to
     assert the actual AG-009 property: the forgotten check really ran and its outcome is in
     the ledger.
  A third was mine, caught by my own test: the task-path validator used `Path.is_absolute()`,
  which is False for `/etc/passwd` on Windows, so a task authored there would escape its
  workspace when the suite ran on Linux. It now checks both path flavours.
- Also corrected a flaw in my own metric: the control task's deliberate red test run was
  counted as a tool failure, so the default gate could never pass and every honesty check
  added to the suite would have lowered the score.
- Commands: `scripts/verify.sh` -> **724 passed, 2 skipped**, ruff and format clean, mypy
  strict 0 issues in 73 source files, 89% coverage, zero warnings. 46 unit tests and 10
  integration tests that run the real suite with real pytest child processes.
- `aica eval run --scripted` on the shipped suite: completion 100%, correctness 100%, tool
  reliability 100%, retrieval recall 1.00 (precision 0.33 over 5 returned), no false
  successes. **A scripted run measures the harness and the tools, not a model**, and both the
  report and the gate say so.
- Unresolved: unchanged - no live provider call, so no model has actually been evaluated.
- Commit/branch: feat/agent-platform.

### Phase 3 step 1 — multi-model routing, fallback and pinning — 2026-09-23
- Scope: MM-001..MM-014, then the HTTP and CLI surface for them (API-012, API-013, UX-007).
- New: `src/aica/models/routing.py` - `TaskKind`, `REQUIRED_CAPABILITIES`, `RoutingRule`,
  `RoutingConfig`, `ModelRouter`, `FallbackAdapter`, `Selection`. The registry entries grew
  `status`, `pinned`, `adapter` and `notes`, with validation at load time.
- Four decisions, each a place this could have gone quietly wrong:
  1. **Fallback is for unavailability only.** 500/502/503/429/408, a transport failure, or a
     credential not configured here. A 400 or a malformed reply does not fall back, because
     that would hide a real fault behind a second opinion.
  2. **A stream falls back only before its first chunk.** After that the error propagates:
     splicing two models' answers together is worse than an honest failure.
  3. **`info` keeps reporting the model that was asked for**, never whichever answered; the
     response carries the exact served version (MM-012). Otherwise the reported context
     window changes under the caller mid-run.
  4. **Selection is eager.** Building an adapter does no I/O but is where a missing key or a
     denied host is found; deferring it to the first call moved a configuration error into
     the middle of a run and past the caller's error handling.
- MM-001 status is an enforcement point: `pending`/`blocked` are refused by the gateway,
  `deprecated` works by explicit name but is never routed to, so an existing pin keeps working
  while nothing new drifts onto it. A pinned entry may not name a moving alias (MM-011).
- Verified: `tests/test_routing.py` (62 tests) drives real HTTP responses through an httpx
  transport - 503s, a connection refusal, a malformed body, an SSE stream that dies halfway -
  plus 8 new API tests over the real ASGI app. 100% coverage of the routing module.
- Commands: `scripts/verify.sh` -> **667 passed, 2 skipped**, ruff and format clean, mypy
  strict 0 issues in 68 source files, 90% coverage, zero warnings.
- Unresolved: **no live provider call has been made.** GLM and Kimi stay `pending`; DeepSeek's
  adapter is exercised only against a mocked endpoint. Fallback between two *live* providers
  is therefore unproven; fallback against real HTTP responses is proven.
- Commit/branch: feat/agent-platform.

### Phase 2 step 7 — specialist subagents (AG-008) — 2026-09-23
- `src/aica/agent/subagents.py`: the four BRD roles (research, implementation, testing,
  review), each with a fixed tool list, reached through a run-scoped `agent.delegate`.
- Three properties, asserted rather than asserted-in-prose: a subagent's tools and policy
  groups are **intersections** with the parent's; its steps are carved from the parent's
  budget and charged back, sharing the parent's cancellation token; its ledger folds into the
  parent's, so a check the child failed or could not run leaves the parent INCOMPLETE.
- Nesting is bounded twice: no role's tool list contains `agent.delegate`, and a subagent's
  loop is constructed without the capability.
- Verified over a real Git repository with real pytest child processes: an implementation
  subagent edited the source and a real run proved it; a review subagent's edit attempt was
  refused at plan time with `git status` clean; a red child suite kept the parent INCOMPLETE;
  a parent capped at 3 steps gave its child exactly 2.
- Commands: `scripts/verify.sh` -> **598 passed, 2 skipped**, 89% coverage overall and 100% on
  the new module, zero warnings. 41 unit tests plus 4 integration tests.
- Commit/branch: feat/agent-platform (6acf5db).

### Phase 2 step 6 — closing the verification gaps — 2026-09-23
- **PostgreSQL: closed.** A throwaway `postgres:17-alpine` container was started with the
  user's authorization, the Postgres path verified against it, and the container removed.
  `tests/integration/test_postgres.py` (14 tests) is skipped unless `AICA_TEST_POSTGRES_DSN`
  is set, so the suite still runs on a machine with no database.
- **The bug this found, which nothing else could have:** `SET statement_timeout = %s` -
  PostgreSQL's `SET` takes no bound parameters, so **every PostgreSQL connection failed at
  startup** with `syntax error at or near "$1"`. Fixed with `SELECT set_config(...)`, which
  does take parameters, rather than by interpolating the value into the statement.
- Verified against the real server: `information_schema` tables and columns; primary keys
  through the correlated subquery; `pg_indexes`; `%s` binding; a real join and aggregate; a
  real `EXPLAIN` and `EXPLAIN ANALYZE` with actual timings; **server-side read-only
  enforcement** (`ReadOnlySqlTransaction` when the classifier is bypassed); the statement
  timeout really cancelling `pg_sleep(5)`; an approved `UPDATE` confirmed with the driver
  independently of the tool; and the password absent from the configuration file.
- **Live model: harness ready, not run.** `tests/integration/test_live_model.py` needs both
  `DEEPSEEK_API_KEY` and `AICA_TEST_LIVE_MODEL=1` - the opt-in is separate from the key so a
  test run cannot spend someone's credit by accident.
- Policy change, with the user's authorization: `config/policy.toml` `[network]` moved from
  `deny` to `allowlist` with the single host `api.deepseek.com`.
- `tests/test_policy.py` asserted the literal `DENY` mode and correctly failed on that change.
  It now asserts the **invariant**: the mode is deny or allowlist, an allowlist is non-empty
  and wildcard-free, and an unlisted host is still refused.
- Commands: `scripts/verify.sh` twice - without a database (**553 passed, 2 skipped**) and
  with the live server (**566 passed**).

### Phase 2 steps 1–5 — agent loop, browser, database, MCP, HTTP API — 2026-09-22
Recorded in full in `.claude-progress.md` (Decision Log entries 016–020); summarised here so
this file stands on its own.
- **Step 1, the agent loop (AG-001..AG-010).** Planner producing an explicit ordered plan,
  executor consuming `RunBudget`/`CancellationToken` per step, observing tool results and
  adapting on failure, finishing through `VerificationLedger` into `TaskReport`. Verified end
  to end: a red suite, a replan, a real edit, a green suite, and the rerun confirmed
  independently of the agent. **Bug found:** a tool that *returns* failure (a red test suite)
  rather than raising was being treated as success.
- **Step 2, browser (WEB-001..006, TEST-004).** Playwright, 8 tools, verified in real Chromium
  against a real loopback server, including a generated E2E test that pytest then really ran.
  **Two bugs found:** HTTP >= 400 responses were invisible to evidence capture, and the
  generated-test verification was silently skipping for a missing `pytest-playwright`.
- **Step 3, database (DB-001..007, LANG-006).** 5 tools. Connections are named in
  configuration and never model-supplied; read-only is enforced at the driver; writes and
  destructive statements pass approval; migrations are generated, reviewed and never
  auto-applied. Verified against real SQLite.
- **Step 4, MCP (MCP-001..007).** stdio JSON-RPC client, tools namespaced `mcp.<server>.<tool>`
  under a policy group that is off by default, untrusted servers gated by approval, arguments
  validated locally before they are sent, and a hostile server proved unable to shadow a
  built-in tool.
- **Step 5, HTTP API (API-001..011).** FastAPI over the real ASGI app: token auth enforced, a
  session created, repository search returning real citations, a destructive command refused
  with 409, and SSE event streaming. **Bug found:** a cross-thread SQLite failure plus a leaked
  connection per HTTP task, traced with `PYTHONTRACEMALLOC` and fixed with an explicit
  thread-handoff flag and an `on_finish` close.

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
