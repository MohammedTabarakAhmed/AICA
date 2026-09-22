"""AICA — Enterprise AI Coding Assistant Agent.

Package layout (Phase 0 foundation):
- aica.policy     bounded-autonomy, approval, network and Git policy (AG-007, SAFE-001, SAFE-005)
- aica.safety     command classification, injection and secret redaction (EXEC-006, SAFE-006/007)
- aica.audit      structured, redacted audit events (EXEC-007, MCP-006, ADM-007 baseline)
- aica.workspace  authorized-path and Git working-tree guards (FS-001, GIT-010)
"""

__version__ = "0.0.1"
