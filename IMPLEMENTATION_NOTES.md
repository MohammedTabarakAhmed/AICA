# Implementation Notes & Traceability

## Source

Primary functional source:
`docs/brd/Enhanced_AI_Coding_Agent_BRD_Functional_v3.docx`

The BRD defines the functional baseline for the enterprise AI coding agent.

## How Claude Code Should Use These Files

- `CLAUDE.md` — primary project instructions and operating rules.
- `AGENTS.md` — concise agent operating contract.
- `ACCEPTANCE.md` — executable requirement/verification checklist.
- `DEPENDENCIES.md` — environment and dependency contract.
- `.claude-progress.md` — resumability and phase checkpoints.
- `PROJECT_BRIEF.md` — concise product context.
- `SECURITY_GUARDRAILS.md` — operational security contract.
- `IMPLEMENTATION_NOTES.md` — traceability and document-use guidance.

## Requirement Mapping

### Coding
CC-* and CHAT-* → chat/completion experience.

### Agentic Execution
AG-* → planning, execution, observation, bounded autonomy and verification.

### Repository Intelligence
RAG-* → indexing, retrieval, source locations and authorization.

### Workspace
FS-* and EXEC-* → safe filesystem and execution capabilities.

### Source Control
GIT-* → Git workflow and user-change protection.

### Verification
TEST-* → testing and false-success prevention.

### Browser
WEB-* → controlled browser/E2E capability.

### Database
DB-* → controlled SQL/schema/database operations.

### Models
MM-* → model registry, selection, routing, fallback and reproducibility.

### Memory
MEM-* → sessions, context and resumability.

### Extensibility
MCP-* → tool-server integration and tool policy.

### Safety
SAFE-* → approvals, authorization, network, secrets, prompt injection and stop.

### Integration
INT-* → IDE, CLI, Web, collaboration, CI/CD and repository providers.

### Governance
ADM-* → RBAC, policy, quota, audit and retention.

### Review
REV-* → correctness, security, maintainability and test review.

### Evaluation
EVAL-* → golden tasks, model comparison and promotion gates.

### User Experience
UX-* (BRD §14) → progress, plan, tool status, diffs, test status, pause/resume/
cancel, model selection, approval display and final summary.

### Derived IDs (not BRD-native)
API-* → BRD §15 API-level capabilities.
NFR-* → BRD §17 product-behavior NFRs and §8 concurrency.
SEC-* → BRD §16 governance bullets without a native ID.
LANG-* → BRD §9.1 language/ecosystem support.

### Un-numbered BRD sections still binding
§5 end-to-end workflow, §10 skills catalog, §13 fine-tuning bullets
(tracked in ACCEPTANCE Phase 5), §18 business acceptance (tracked in
ACCEPTANCE Business Acceptance).

## Requirement Overlaps

The following IDs describe one behavior from several angles and should map to a
single implementation, verified once and ticked together:
- Cancel/stop: AG-006, UX-006, SAFE-008, API-004
- Final summary: AG-010, UX-009
- Diff display: FS-006, GIT-005, UX-004
- Pause/resume: AG-005, MEM-003, UX-006, API-005, NFR-002
- Reproducibility record: MM-012, MEM-006, EVAL-009
- No false success: TEST-009, AG-009

## Source Boundary

The BRD explicitly excludes infrastructure sizing and detailed architecture.
Do not treat this file set as permission to invent GPU, CPU, RAM, storage or
Kubernetes specifications.

## Change Discipline

If a new requirement is discovered during implementation:
1. determine whether it is already represented in the BRD;
2. if it is implementation detail, document it without altering the BRD;
3. if it materially changes product scope, stop and request product-owner
   confirmation before treating it as a new requirement.
