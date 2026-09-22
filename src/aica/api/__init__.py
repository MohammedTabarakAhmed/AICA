"""HTTP API surface (API-001..API-011, BRD section 15).

A second surface over the same tools, guards and audit the CLI uses - never a second
implementation of them. Bearer-token authenticated, loopback by default.
"""

from aica.api.app import ApiSettings, create_app
from aica.api.tasks import TaskManager, TaskRecord, TaskState, event_payload

__all__ = [
    "ApiSettings",
    "TaskManager",
    "TaskRecord",
    "TaskState",
    "create_app",
    "event_payload",
]
