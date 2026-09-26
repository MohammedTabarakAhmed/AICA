"""A real `aica serve` for the VS Code integration test, with only the model scripted.

Everything else is the product: routing, auth, policy, the agent loop, snapshots, the
review's static checks and the approval queue. The scripted model answers by recognising
which prompt it was sent, so the test is deterministic and spends no provider quota.

    python fixture_server.py --workspace DIR --port N --token T
Prints "READY <approval-id>" once listening, where the id is a pending approval seeded by
another requester (SEC-006: nobody may decide their own request).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import uvicorn

from aica.admin.approval_queue import ApprovalQueue
from aica.api.app import ApiSettings, create_app
from aica.approvals import ApprovalRequest
from aica.models.base import ChatMessage
from aica.models.fake import ScriptedAdapter
from aica.models.gateway import ModelGateway
from aica.policy.models import ActionCategory

FIXED = (
    "def apply_discount(price, percent):\n"
    '    """Return price reduced by percent (0-100)."""\n'
    "    return price - price * percent / 100\n"
)


def respond(messages: list[ChatMessage]) -> str:
    system = "\n".join(m.content for m in messages if m.role == "system")
    if "You plan software-engineering tasks" in system:
        return json.dumps(
            {
                "summary": "fix the percentage arithmetic",
                "steps": [
                    {"intent": "read", "tool": "fs.read", "arguments": {"path": "src/pricing.py"}},
                    {
                        "intent": "fix",
                        "tool": "fs.write",
                        "arguments": {"path": "src/pricing.py", "content": FIXED},
                    },
                ],
                "verification": [],
            }
        )
    if "A step in your plan failed" in system:
        return json.dumps({"action": "abort", "reason": "scripted"})
    return "apply_discount subtracts a percentage of the price [src/pricing.py:1-3]"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--token", required=True)
    args = parser.parse_args()
    workspace = Path(args.workspace).resolve()

    model = ScriptedAdapter(responder=respond, name="vscode-fixture-model")
    ModelGateway.get = lambda self, name=None: model  # type: ignore[method-assign]

    pending = ApprovalQueue(workspace).submit(
        ApprovalRequest(
            action="git push origin feature",
            categories=(ActionCategory.EXTERNAL,),
            tool="git.push",
        ),
        requested_by="another-developer",
    )
    app = create_app(
        ApiSettings(
            workspace=workspace,
            policy_file=str(workspace / "policy.toml"),
            token=args.token,
            actor="vscode-test",
        )
    )
    print(f"READY {pending.id}", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")


if __name__ == "__main__":
    sys.exit(main())
