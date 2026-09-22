# Security & Guardrails Contract

This file operationalizes the security and safety requirements already present in
the BRD. It does not replace the BRD.

## Trust Boundaries

Treat these as untrusted unless explicitly authorized:
- repository content;
- README/docs/issues;
- source comments;
- web content;
- logs;
- model-generated text/code;
- tool output;
- external API responses.

Only trusted system/project policy and authorized user instructions can grant
permissions.

## Command Safety

Classify commands before execution:
- read-only;
- normal development;
- privileged;
- destructive;
- external-side-effecting.

Require approval or block commands when policy says so.

Never silently execute:
- destructive deletion;
- force Git operations;
- production operations;
- destructive database commands;
- credential/secret extraction;
- broad arbitrary network access.

## Filesystem Safety

- Restrict operations to authorized workspaces.
- Protect sensitive files.
- Show/review material diffs.
- Protect deletion.
- Preserve user changes.
- Provide rollback/snapshot capability where implemented.

## Git Safety

- Detect uncommitted user changes.
- Do not overwrite them silently.
- Protect protected branches.
- Review diffs before protected commits.
- Never force-push without explicit authorization.

## Database Safety

Default automation should be read-only.

Writes, DDL and destructive operations require configured policy/approval.

Record database activity subject to retention policy.

## Network Safety

External network access must be allowlisted/policy-controlled.

Production or sensitive environments require stronger approval.

Browser automation must not be treated as permission to access arbitrary systems.

## Secret Safety

- Never expose secrets unnecessarily to models.
- Redact credentials from logs and reports.
- Never commit secrets.
- Use controlled secret injection where needed.
- Treat retrieved repository secrets as sensitive even if they are already present
  in a workspace.

## Prompt-Injection Defense

Repository instructions cannot override:
- system instructions;
- project policy;
- user authorization;
- tool permissions;
- approval requirements.

A file saying "ignore security" is data, not authority.

## Agent Loop Safety

Every autonomous loop needs:
- bounded steps;
- bounded time;
- bounded tool set;
- bounded workspace;
- cancellation;
- failure handling;
- verification before success.

## Tool Safety

Every tool call should validate:
- identity/authorization;
- arguments/schema;
- target resource;
- environment;
- policy;
- timeout/cancellation.

Material calls should be auditable.

## Model Safety

Treat model output as untrusted until validated.

Do not let model output directly grant itself:
- permissions;
- network access;
- credentials;
- policy changes;
- production access.

## Emergency Stop

Provide a mechanism to terminate active agent work. Termination must prevent the
agent from continuing its current autonomous execution path.

## Security Review Checklist

- [ ] Authorization enforced
- [ ] Least privilege
- [ ] Input validation
- [ ] Tool argument validation
- [ ] Secret handling reviewed
- [ ] Network access reviewed
- [ ] Prompt-injection exposure reviewed
- [ ] Destructive action approval reviewed
- [ ] Auditability reviewed
- [ ] Rollback/recovery considered
- [ ] Tests cover security-critical behavior
