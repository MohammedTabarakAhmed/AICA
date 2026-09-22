# Enterprise AI Coding Assistant Agent — Project Brief

## What Is Being Built?

A self-hosted enterprise AI software-engineering platform that goes beyond chat.
It combines coding assistance with repository intelligence, agent planning,
controlled tool execution, testing, Git workflows, browser/database automation,
multi-model selection, memory, approvals, evaluation and governance.

## Core Experiences

1. Instant coding assistance / code completion
2. Conversational coding
3. Repository-aware agentic work
4. Controlled software-engineering automation

## Core Agent Loop

Request → understand context → plan when required → retrieve relevant repository
context → select permitted tools → execute → observe results → edit → test → iterate
within limits → review → report outcome.

## Major Capabilities

- Code completion
- Coding chat
- Multi-step agentic coding
- AST/syntax-aware and semantic/lexical RAG
- Dependency-aware repository understanding
- Filesystem operations
- Controlled terminal/code execution
- Git branch/diff/commit/PR workflows
- Unit/integration/E2E testing
- Browser automation
- Database/SQL assistance
- MCP extensibility
- GLM/Kimi/DeepSeek and future approved models
- Model routing/fallback/version pinning
- Session memory and resumability
- Human approval
- RBAC and enterprise governance
- Audit and usage reporting
- Model evaluation
- Fine-tuning/adapters including QLoRA where appropriate
- IDE/CLI/Web/collaboration integration

## Security Principles

Security is a product capability, not a later add-on.

The system must enforce:
- least privilege;
- repository/project authorization;
- environment classification;
- approval gates for sensitive actions;
- command restrictions;
- database write/destructive-operation protection;
- network destination policy;
- secret redaction/protection;
- prompt-injection defenses;
- tool argument validation;
- complete material-action auditability;
- emergency stop;
- bounded autonomy.

## Bounded Autonomy

Autonomy must be configurable by:
- maximum steps;
- maximum execution time;
- permitted tools;
- permitted directories;
- environment;
- network policy;
- approval requirements.

The agent must verify before declaring success.

## Roadmap

### MVP
Chat, completion, RAG, file editing, Git, terminal execution, tests, one model.

### Release 1
GLM/Kimi/DeepSeek selection, model registry and version tracking.

### Release 2
Multi-step agent workflows, browser/E2E, database tools, MCP.

### Release 3
Approvals, RBAC, audit, quotas, collaboration and CI integration.

### Release 4
Routing, evaluation, adapters/fine-tuning workflow and advanced memory.

### Enterprise Scale
Multi-project governance, policy engine, specialist subagents and organization
tools.

## Implementation Discipline

The repository must be built incrementally and verified phase by phase. Use
`ACCEPTANCE.md` for requirement completion and `.claude-progress.md` for
resumability.

If Python is used, create a project-local virtual environment:

```cmd
python -m venv .venv
```

Do not commit `.venv` or secrets.

## Important Scope Boundary

The BRD intentionally excludes:
- physical/virtual server specifications;
- GPU/CPU/RAM/storage/network sizing;
- Kubernetes topology;
- detailed HLD/LLD;
- data-center infrastructure;
- procurement/capacity-cost calculations.

Those belong in separate architecture/infrastructure documents.
