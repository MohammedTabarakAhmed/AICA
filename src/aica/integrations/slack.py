"""Slack collaboration integration (INT-004, BRD 7.15).

BRD INT-004 asks that "users can initiate or receive task updates where approved". This
bridge gives a Slack channel three things: approval requests with Approve/Reject buttons,
a message when an agent task finishes, and questions about the repository answered in a
thread. It is a *surface*, like the CLI and the web page, and adds no second path:

* **Approving from Slack is the same act as approving at a terminal.** A button press
  resolves the Slack user to a principal and calls ``decide_and_record`` - the function
  the API and the CLI use - so RBAC (ADM-001), separation of duties (SEC-006), expiry and
  the audit record are identical. As everywhere else, deciding runs nothing: the queue
  holds records, and the requester re-sends the action through every gate (API-014).
* **A Slack account is not an identity until it is mapped.** ``users`` in
  ``config/slack.toml`` maps Slack user IDs to principals; anyone unmapped is refused and
  the attempt is audited. This matters even with RBAC off, where every principal holds
  every permission: without the mapping, anyone who can see the channel could approve.
* **Identity comes from Slack, per person.** The HTTP API acts as one principal (its
  token holder), so a bridge built on it would make every Slack user the same person
  and separation of duties meaningless. The bridge therefore calls the library directly,
  exactly as the CLI does, with the principal of whoever pressed the button.
* **Nothing needs a public URL.** Socket Mode opens an outbound WebSocket to Slack, and
  both it and the Web API host must pass the network policy (SAFE-005). The WebSocket
  URL Slack hands back is checked too, not assumed.
* **Tokens are SEC-004 secrets**, named in config and read from the environment when the
  bridge starts, behind an audited SECRET_ACCESS approval. They are never written to a
  file, a log or a message, and ``xoxb-``/``xapp-`` values are redacted everywhere.
* **Everything posted is redacted and escaped.** Action text and model answers can carry
  repository content; secrets are masked (SAFE-006) and ``& < >`` are escaped, so text
  cannot smuggle ``<!channel>`` pings or disguised links into the channel.
* **An administrator can switch it off at once** (SEC-007: ``aica admin disable
  integration slack``). The bridge then posts nothing and refuses every button and
  question until it is enabled again.

Task-finished messages are read from the audit trail rather than hooked into one
surface, so a task started from the CLI, the web app or VS Code is reported the same way.
"""

from __future__ import annotations

import os
import re
import tempfile
import threading
import tomllib
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from aica.admin.approval_queue import (
    ApprovalError,
    ApprovalQueue,
    DecisionState,
    PendingApproval,
    decide_and_record,
)
from aica.admin.controls import ControlPlane, Disabled, TargetKind
from aica.admin.rbac import Permission
from aica.audit.events import AuditEvent, EventCategory, Outcome
from aica.audit.sink import AuditLog, JsonlAuditSink
from aica.policy.models import NetworkPolicy, Policy
from aica.safety.redaction import redact
from aica.safety.secrets import scrub

DEFAULT_SLACK_PATH = Path("config/slack.toml")
INTEGRATION = "slack"  # the SEC-007 integration name
TOOL = "integration.slack"  # what secrets permit and what the audit trail names
APPROVE_ACTION = "aica_approve"
REJECT_ACTION = "aica_reject"
# Slack's section-block limit is 3000 characters; message text allows far more, but a
# wall of text in a channel helps nobody.
MAX_BLOCK_TEXT = 2800
MAX_MESSAGE_TEXT = 3500
MAX_REMEMBERED = 1000  # bounded memory of posted approvals, announced tasks, seen events
TASK_FINISHED_PREFIX = "task finished:"
# The hosts Socket Mode normally connects to. Checked up front for a clear error; the URL
# Slack actually returns is checked again when the connection is opened.
SOCKET_HOSTS = ("wss-primary.slack.com",)
_LOOPBACK = {"localhost", "127.0.0.1", "::1"}
_SLACK_USER = re.compile(r"^[UW][A-Z0-9]{4,}$")
_MENTION = re.compile(r"<@[UW][A-Z0-9]+>")


class SlackError(RuntimeError):
    """Slack is misconfigured, switched off, refused a call, or is unreachable."""


# ------------------------------------------------------------------ configuration


class SlackConfig(BaseModel):
    """``config/slack.toml``. IDs, not names: a channel can be renamed, an ID cannot."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    api_url: str = "https://slack.com/api"
    # SEC-004 secret names declared in config/policy.toml, never values.
    bot_token_secret: str = "slack_bot_token"  # noqa: S105 - a secret's name, not a secret
    app_token_secret: str = "slack_app_token"  # noqa: S105 - a secret's name, not a secret
    # The channel approvals and task updates go to, and the only channel whose buttons
    # and mentions are honoured. "C..." public, "G..." private.
    channel: str = Field(default="", pattern=r"^([CG][A-Z0-9]{4,})?$")
    # Slack user ID -> principal name (ADM-001). Unmapped users are refused.
    users: dict[str, str] = Field(default_factory=dict)
    post_approvals: bool = True
    post_task_finished: bool = True
    questions: bool = True
    direct_messages: bool = True  # answer questions sent to the bot directly
    poll_seconds: float = Field(default=5.0, ge=1.0, le=300.0)

    @field_validator("users")
    @classmethod
    def _user_ids(cls, value: dict[str, str]) -> dict[str, str]:
        for slack_id, principal in value.items():
            if not _SLACK_USER.match(slack_id):
                raise ValueError(
                    f"{slack_id!r} is not a Slack user ID (U... or W...); map IDs, not "
                    "display names, which anyone can change"
                )
            if not principal.strip():
                raise ValueError(f"Slack user {slack_id} maps to an empty principal name")
        return value

    @model_validator(mode="after")
    def _checks(self) -> SlackConfig:
        url = urlparse(self.api_url)
        if url.scheme != "https" and not (url.scheme == "http" and url.hostname in _LOOPBACK):
            raise ValueError(
                "api_url must be https (a token would otherwise travel in clear text); "
                "plain http is accepted only for loopback test servers"
            )
        if self.enabled and not self.channel:
            raise ValueError("an enabled Slack integration needs a channel ID")
        return self

    @property
    def host(self) -> str:
        return urlparse(self.api_url).hostname or ""

    def principal_for(self, slack_user: str) -> str | None:
        return self.users.get(slack_user)


def load_slack(path: str | Path | None = None) -> SlackConfig:
    """Read the Slack configuration. A missing file is an error, not 'disabled'."""
    target = Path(path) if path is not None else DEFAULT_SLACK_PATH
    try:
        raw = tomllib.loads(target.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SlackError(
            f"no Slack configuration at {target}; copy config/slack.toml.example to start (INT-004)"
        ) from exc
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise SlackError(f"{target} could not be read: {exc}") from exc
    try:
        return SlackConfig.model_validate(raw)
    except ValidationError as exc:
        raise SlackError(f"{target} is not a valid Slack configuration: {exc}") from exc


def required_hosts(config: SlackConfig) -> list[str]:
    """The hosts the network policy must allow for this configuration (SAFE-005)."""
    if config.host in _LOOPBACK:
        return [config.host]  # a loopback test server; no WebSocket is opened to Slack
    return [config.host, *SOCKET_HOSTS]


def check_network(config: SlackConfig, network: NetworkPolicy) -> None:
    missing = [h for h in required_hosts(config) if not network.is_host_allowed(h)]
    if missing:
        raise SlackError(
            f"the network policy does not allow {', '.join(missing)}; Slack needs them in "
            "[network].allowed_hosts in config/policy.toml (SAFE-005)"
        )


# ------------------------------------------------------------------ formatting


def escape(text: str, limit: int = MAX_BLOCK_TEXT) -> str:
    """Redact, then escape for Slack mrkdwn, then bound the length.

    Slack treats ``<...>`` as a link, mention or broadcast; escaping the three control
    characters is what stops posted text from pinging a channel or disguising a link.
    """
    clean = redact(text).text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    if len(clean) > limit:
        clean = clean[: limit - 20].rstrip() + "\n… (truncated)"
    return clean


def approval_message(entry: PendingApproval) -> tuple[str, list[dict[str, Any]]]:
    """UX-008 in Slack: the categories first, since they are why a human is asked."""
    categories = ", ".join(c.value for c in entry.categories) or "uncategorised"
    body = (
        f"*Approval requested* ({escape(categories, 200)})\n"
        f"*Tool:* {escape(entry.tool or '-', 100)}\n"
        f"*Action:* {escape(entry.action, 2000)}\n"
        f"*Requested by:* {escape(entry.requested_by, 200)} · id `{entry.id}`"
    )
    text = f"Approval requested: {escape(entry.describe(), 300)}"
    blocks: list[dict[str, Any]] = [
        {"type": "section", "text": {"type": "mrkdwn", "text": body}},
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": (
                        "Deciding records a decision; nothing runs from Slack. The requester "
                        "re-sends the action, and it passes every check again (API-014)."
                    ),
                }
            ],
        },
        {
            "type": "actions",
            "block_id": f"aica_approval_{entry.id}",
            "elements": [
                {
                    "type": "button",
                    "action_id": APPROVE_ACTION,
                    "style": "primary",
                    "text": {"type": "plain_text", "text": "Approve"},
                    "value": entry.id,
                },
                {
                    "type": "button",
                    "action_id": REJECT_ACTION,
                    "style": "danger",
                    "text": {"type": "plain_text", "text": "Reject"},
                    "value": entry.id,
                },
            ],
        },
    ]
    return text, blocks


_STATE_ICON = {
    DecisionState.APPROVED: ":white_check_mark:",
    DecisionState.REJECTED: ":x:",
    DecisionState.EXPIRED: ":hourglass:",
}


def decided_message(entry: PendingApproval, via: str = "") -> tuple[str, list[dict[str, Any]]]:
    """The approval message once decided: the buttons are gone, the decision is shown."""
    icon = _STATE_ICON.get(entry.state, "")
    who = f" by {escape(entry.decided_by or '?', 200)}" if entry.decided_by else ""
    where = f" ({via})" if via else ""
    note = f"\n*Note:* {escape(entry.note, 500)}" if entry.note else ""
    body = (
        f"{icon} *{entry.state.value.capitalize()}*{who}{where} · id `{entry.id}`\n"
        f"{escape(entry.describe(), 2000)}{note}"
    )
    return f"{entry.state.value}: {escape(entry.describe(), 300)}", [
        {"type": "section", "text": {"type": "mrkdwn", "text": body}}
    ]


def gone_message(request_id: str) -> tuple[str, list[dict[str, Any]]]:
    body = (
        f":hourglass: Approval request `{request_id}` is no longer in the queue "
        "(it expired and was cleared). Nothing was decided; re-request it if it still matters."
    )
    return f"approval {request_id} expired", [
        {"type": "section", "text": {"type": "mrkdwn", "text": body}}
    ]


def task_finished_message(event: AuditEvent) -> str:
    details = event.details
    task = event.action[len(TASK_FINISHED_PREFIX) :].strip() or "(unnamed task)"
    outcome = str(details.get("outcome", event.outcome.value))
    icon = ":white_check_mark:" if event.outcome is Outcome.SUCCESS else ":warning:"
    lines = [
        f"{icon} *Task finished* - {escape(outcome, 200)}",
        f"*Task:* {escape(task, 1000)}",
        f"*By:* {escape(event.actor, 200)} · steps {details.get('steps', '?')} · "
        f"files changed {details.get('changes', '?')}"
        + (f" · session `{event.session_id}`" if event.session_id else ""),
    ]
    verification = str(details.get("verification", "")).strip()
    if verification:
        lines.append(f"*Verification:* {escape(verification, 1000)}")
    return "\n".join(lines)


# ------------------------------------------------------------------ Slack Web API


class SlackApi(Protocol):
    """The Web API calls the bridge makes. A protocol, so tests can record them."""

    def post_message(
        self,
        channel: str,
        text: str,
        blocks: list[dict[str, Any]] | None = None,
        thread_ts: str | None = None,
    ) -> str: ...

    def update_message(
        self, channel: str, ts: str, text: str, blocks: list[dict[str, Any]] | None = None
    ) -> None: ...

    def post_ephemeral(
        self, channel: str, user: str, text: str, thread_ts: str | None = None
    ) -> None: ...


class SlackWebApi:
    """Slack's Web API over httpx. The token lives in this object and nowhere else."""

    def __init__(
        self,
        api_url: str,
        token: str,
        *,
        transport: httpx.BaseTransport | None = None,
        timeout: float = 15.0,
    ) -> None:
        self._token = token
        self._client = httpx.Client(
            base_url=api_url.rstrip("/") + "/",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json; charset=utf-8",
            },
            transport=transport,
            timeout=timeout,
        )

    def close(self) -> None:
        self._client.close()

    def call(self, method: str, **payload: Any) -> dict[str, Any]:
        try:
            response = self._client.post(method, json=payload)
        except httpx.HTTPError as exc:
            raise SlackError(scrub(f"{method}: {exc}", (self._token,))) from exc
        if response.status_code == 429:
            wait = response.headers.get("Retry-After", "?")
            raise SlackError(f"{method}: rate limited by Slack; retry after {wait}s")
        if response.status_code >= 400:
            raise SlackError(f"{method}: HTTP {response.status_code}")
        try:
            data: dict[str, Any] = response.json()
        except ValueError as exc:
            raise SlackError(f"{method}: Slack returned something that is not JSON") from exc
        if not data.get("ok"):
            raise SlackError(f"{method}: {data.get('error', 'unknown error')}")
        return data

    def auth_test(self) -> dict[str, Any]:
        return self.call("auth.test")

    def post_message(
        self,
        channel: str,
        text: str,
        blocks: list[dict[str, Any]] | None = None,
        thread_ts: str | None = None,
    ) -> str:
        payload: dict[str, Any] = {"channel": channel, "text": text, "unfurl_links": False}
        if blocks:
            payload["blocks"] = blocks
        if thread_ts:
            payload["thread_ts"] = thread_ts
        return str(self.call("chat.postMessage", **payload).get("ts", ""))

    def update_message(
        self, channel: str, ts: str, text: str, blocks: list[dict[str, Any]] | None = None
    ) -> None:
        self.call("chat.update", channel=channel, ts=ts, text=text, blocks=blocks or [])

    def post_ephemeral(
        self, channel: str, user: str, text: str, thread_ts: str | None = None
    ) -> None:
        payload: dict[str, Any] = {"channel": channel, "user": user, "text": text}
        if thread_ts:
            payload["thread_ts"] = thread_ts
        self.call("chat.postEphemeral", **payload)


# ------------------------------------------------------------------ bridge state


class PostedApproval(BaseModel):
    model_config = ConfigDict(extra="forbid")

    channel: str
    ts: str
    state: str = DecisionState.PENDING.value


class BridgeState(BaseModel):
    """What the bridge has already done, so a restart neither re-posts nor forgets."""

    model_config = ConfigDict(extra="forbid")

    # Task-finished events before this are history, not news: the first run starts here.
    since: datetime | None = None
    approvals: dict[str, PostedApproval] = Field(default_factory=dict)
    announced: list[str] = Field(default_factory=list)  # audit event ids
    events: list[str] = Field(default_factory=list)  # Slack event ids (retries arrive twice)
    threads: dict[str, str] = Field(default_factory=dict)  # channel:thread:user -> session


@dataclass(frozen=True)
class SlackAnswer:
    text: str
    session_id: str
    model: str
    sources: list[str] = field(default_factory=list)


# (principal name, question, session to continue or None) -> the answer. Built by the CLI
# from the same assistant `aica ask` uses, with that principal as the actor.
Answerer = Callable[[str, str, str | None], SlackAnswer]


@dataclass
class SyncResult:
    posted: int = 0
    updated: int = 0
    announced: int = 0
    errors: list[str] = field(default_factory=list)
    skipped: str = ""


# ------------------------------------------------------------------ the bridge


class SlackBridge:
    """Turns queue records and audit events into Slack messages, and Slack actions back
    into the same calls every other surface makes. Holds no authority of its own."""

    def __init__(
        self,
        root: str | Path,
        config: SlackConfig,
        api: SlackApi,
        *,
        policy_loader: Callable[[], Policy],
        answerer: Answerer | None = None,
        actor: str = "slack-bridge",
    ) -> None:
        self.root = Path(root)
        self.config = config
        self.api = api
        self._policy_loader = policy_loader
        self._answer = answerer
        self.actor = actor
        self.queue = ApprovalQueue(self.root)
        self._audit_dir = self.root / ".aica" / "audit"
        self._sink = JsonlAuditSink(self._audit_dir)
        self._state_path = self.root / ".aica" / "integrations" / "slack.json"
        self._lock = threading.RLock()
        self.bot_user_id: str | None = None

    # ---------------------------------------------------------------- plumbing
    def audit(self, actor: str | None = None) -> AuditLog:
        return AuditLog(self._sink, actor=actor or self.actor)

    def disabled(self) -> Disabled | None:
        """SEC-007: consulted on every sync and every action, so a disable is immediate."""
        return ControlPlane(self.root).is_disabled(TargetKind.INTEGRATION, INTEGRATION)

    def load_state(self) -> BridgeState:
        if not self._state_path.is_file():
            return BridgeState()
        try:
            return BridgeState.model_validate_json(self._state_path.read_text(encoding="utf-8"))
        except (OSError, ValidationError) as exc:
            # Starting from nothing would re-post every pending approval; refuse instead.
            raise SlackError(
                f"{self._state_path} could not be read ({exc}); fix or remove it"
            ) from exc

    def _save(self, state: BridgeState) -> None:
        state.announced = state.announced[-MAX_REMEMBERED:]
        state.events = state.events[-MAX_REMEMBERED:]
        if len(state.approvals) > MAX_REMEMBERED:
            resolved = [k for k, v in state.approvals.items() if v.state != "pending"]
            for key in resolved[: len(state.approvals) - MAX_REMEMBERED]:
                del state.approvals[key]
        if len(state.threads) > MAX_REMEMBERED:
            for key in list(state.threads)[: len(state.threads) - MAX_REMEMBERED]:
                del state.threads[key]
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        handle, temp = tempfile.mkstemp(dir=self._state_path.parent, suffix=".tmp")
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as fh:
                fh.write(state.model_dump_json(indent=2))
            os.replace(temp, self._state_path)
        except OSError:
            Path(temp).unlink(missing_ok=True)
            raise

    def _record_post(self, action: str, target: str, **details: Any) -> None:
        """Posting to Slack sends data outside the system, so each post is audited."""
        self.audit().record(
            category=EventCategory.TOOL_CALL,
            action=action,
            outcome=Outcome.SUCCESS,
            tool=TOOL,
            target=target,
            details=details,
        )

    # ---------------------------------------------------------------- outbound
    def sync(self, now: datetime | None = None) -> SyncResult:
        """One pass: post new approvals, retire decided ones, announce finished tasks."""
        result = SyncResult()
        switched_off = self.disabled()
        if switched_off is not None:
            result.skipped = f"disabled by an administrator: {switched_off.describe()}"
            return result
        with self._lock:
            state = self.load_state()
            if state.since is None:
                state.since = (now or datetime.now(UTC)).astimezone(UTC)
                self._save(state)
            if self.config.post_approvals:
                self._sync_approvals(state, result)
            if self.config.post_task_finished:
                self._sync_tasks(state, result)
        return result

    def _sync_approvals(self, state: BridgeState, result: SyncResult) -> None:
        try:
            entries = self.queue.all()
        except ApprovalError as exc:
            result.errors.append(str(exc))
            return
        by_id = {e.id: e for e in entries}
        for entry in reversed(entries):  # oldest first, so the channel reads in order
            posted = state.approvals.get(entry.id)
            try:
                if posted is None and entry.state is DecisionState.PENDING:
                    text, blocks = approval_message(entry)
                    ts = self.api.post_message(self.config.channel, text, blocks)
                    state.approvals[entry.id] = PostedApproval(channel=self.config.channel, ts=ts)
                    self._save(state)
                    self._record_post(f"posted approval request {entry.id}", self.config.channel)
                    result.posted += 1
                elif posted is not None and posted.state == "pending" and entry.resolved:
                    # Decided at the terminal, in the web app, or expired: retire the
                    # buttons so nobody presses one for a question already answered.
                    text, blocks = decided_message(entry, "elsewhere")
                    self.api.update_message(posted.channel, posted.ts, text, blocks)
                    posted.state = entry.state.value
                    self._save(state)
                    result.updated += 1
            except SlackError as exc:
                result.errors.append(f"approval {entry.id}: {exc}")
        for request_id, posted in state.approvals.items():
            if posted.state == "pending" and request_id not in by_id:
                try:
                    text, blocks = gone_message(request_id)
                    self.api.update_message(posted.channel, posted.ts, text, blocks)
                    posted.state = DecisionState.EXPIRED.value
                    self._save(state)
                    result.updated += 1
                except SlackError as exc:
                    result.errors.append(f"approval {request_id}: {exc}")

    def _recent_events(self, since: datetime) -> Iterator[AuditEvent]:
        """Audit events from ``since`` on, reading only the day files that can hold them."""
        first = f"audit-{since.astimezone(UTC):%Y-%m-%d}.jsonl"
        for path in sorted(self._audit_dir.glob("audit-*.jsonl")):
            if path.name < first:
                continue
            with path.open(encoding="utf-8") as fh:
                for line in fh:
                    if not line.strip():
                        continue
                    try:
                        event = AuditEvent.model_validate_json(line)
                    except ValidationError:
                        continue  # one bad line must not stop every later announcement
                    if event.timestamp >= since:
                        yield event

    def _sync_tasks(self, state: BridgeState, result: SyncResult) -> None:
        assert state.since is not None  # set by sync()
        seen = set(state.announced)
        for event in self._recent_events(state.since):
            if (
                event.category is not EventCategory.TASK
                or not event.action.startswith(TASK_FINISHED_PREFIX)
                or event.event_id in seen
            ):
                continue
            try:
                self.api.post_message(self.config.channel, task_finished_message(event))
            except SlackError as exc:
                result.errors.append(f"task event {event.event_id}: {exc}")
                continue
            state.announced.append(event.event_id)
            seen.add(event.event_id)
            self._save(state)
            self._record_post(
                f"announced finished task ({event.actor})",
                self.config.channel,
                audit_event=event.event_id,
            )
            result.announced += 1

    # ---------------------------------------------------------------- inbound
    def handle(self, kind: str, payload: dict[str, Any]) -> None:
        """Dispatch one Socket Mode request (already acknowledged by the caller)."""
        if kind == "interactive" and payload.get("type") == "block_actions":
            for action in payload.get("actions", []):
                if action.get("action_id") in (APPROVE_ACTION, REJECT_ACTION):
                    self._decide(payload, action)
        elif kind == "events_api":
            event = payload.get("event", {})
            if not self._first_delivery(str(payload.get("event_id", ""))):
                return  # Slack retries a delivery it thinks was missed
            if event.get("type") == "app_mention":
                self._question(event)
            elif (
                event.get("type") == "message"
                and event.get("channel_type") == "im"
                and self.config.direct_messages
            ):
                self._question(event)

    def _first_delivery(self, event_id: str) -> bool:
        if not event_id:
            return True
        with self._lock:
            state = self.load_state()
            if event_id in state.events:
                return False
            state.events.append(event_id)
            self._save(state)
            return True

    def _tell(self, channel: str, user: str, text: str, thread_ts: str | None = None) -> None:
        """A reply only the person sees; in a direct message there is no one else anyway."""
        try:
            if channel.startswith("D"):
                self.api.post_message(channel, text, thread_ts=thread_ts)
            else:
                self.api.post_ephemeral(channel, user, text, thread_ts=thread_ts)
        except SlackError:
            pass  # a refusal that cannot be delivered is still a refusal, and it is audited

    def _refuse(
        self, channel: str, user: str, what: str, reason: str, thread_ts: str | None = None
    ) -> None:
        self.audit(self.config.principal_for(user) or f"slack:{user}").record(
            category=EventCategory.POLICY_DECISION,
            action=f"slack {what} refused",
            outcome=Outcome.BLOCKED,
            tool=TOOL,
            target=channel,
            details={"slack_user": user, "reason": reason},
        )
        self._tell(channel, user, f":no_entry: {reason}", thread_ts)

    def _decide(self, payload: dict[str, Any], action: dict[str, Any]) -> None:
        user = str(payload.get("user", {}).get("id", ""))
        channel = str(
            payload.get("channel", {}).get("id")
            or payload.get("container", {}).get("channel_id", "")
        )
        message_ts = str(payload.get("container", {}).get("message_ts", ""))
        request_id = str(action.get("value", ""))
        approved = action.get("action_id") == APPROVE_ACTION
        what = f"{'approval' if approved else 'rejection'} of {request_id}"
        switched_off = self.disabled()
        if switched_off is not None:
            self._refuse(
                channel,
                user,
                what,
                f"The Slack integration is switched off (SEC-007): {switched_off.describe()}",
            )
            return
        if channel != self.config.channel:
            self._refuse(
                channel, user, what, "Approvals are only honoured in the configured channel."
            )
            return
        name = self.config.principal_for(user)
        if name is None:
            self._refuse(
                channel,
                user,
                what,
                "Your Slack account is not mapped to a principal in config/slack.toml, "
                "so it cannot decide approvals. Nothing was decided.",
            )
            return
        principal = self._policy_loader().principal(name)
        try:
            entry = decide_and_record(
                self.queue,
                request_id,
                principal,
                approved,
                self.audit(name),
                via="slack",
                slack_user=user,
            )
        except (PermissionError, ApprovalError) as exc:
            # decide_and_record has already audited the refusal.
            self._tell(channel, user, f":no_entry: Not decided: {escape(str(exc), 1000)}")
            return
        text, blocks = decided_message(entry, "via Slack")
        with self._lock:
            state = self.load_state()
            posted = state.approvals.get(request_id)
            ts = message_ts or (posted.ts if posted else "")
            if ts:
                try:
                    self.api.update_message(channel, ts, text, blocks)
                except SlackError:
                    pass  # the decision stands; the next sync retires the buttons
                else:
                    if posted is not None:
                        posted.state = entry.state.value
                        self._save(state)

    def _question(self, event: dict[str, Any]) -> None:
        user = str(event.get("user", ""))
        channel = str(event.get("channel", ""))
        if (
            not user
            or event.get("bot_id")
            or event.get("subtype")
            or (self.bot_user_id and user == self.bot_user_id)
        ):
            return  # the bot's own messages, edits, joins: not questions
        thread = str(event.get("thread_ts") or event.get("ts") or "") or None
        what = "question"
        if not self.config.questions or self._answer is None:
            self._tell(channel, user, "Questions are not enabled for this workspace.", thread)
            return
        switched_off = self.disabled()
        if switched_off is not None:
            self._refuse(
                channel,
                user,
                what,
                f"The Slack integration is switched off (SEC-007): {switched_off.describe()}",
                thread,
            )
            return
        if not channel.startswith("D") and channel != self.config.channel:
            self._refuse(
                channel,
                user,
                what,
                "Questions are only answered in the configured channel or in a direct message.",
                thread,
            )
            return
        name = self.config.principal_for(user)
        if name is None:
            self._refuse(
                channel,
                user,
                what,
                "Your Slack account is not mapped to a principal in config/slack.toml.",
                thread,
            )
            return
        principal = self._policy_loader().principal(name)
        if not principal.can(Permission.READ):
            self._refuse(
                channel,
                user,
                what,
                f"{name!r} does not hold the read permission (ADM-001).",
                thread,
            )
            return
        question = _MENTION.sub("", str(event.get("text", ""))).strip()
        if not question:
            self._tell(channel, user, "Ask me a question about the repository.", thread)
            return
        key = f"{channel}:{thread}:{user}"
        with self._lock:
            session_id = self.load_state().threads.get(key)
        audit = self.audit(name)
        try:
            answer = self._answer(name, question, session_id)
        except Exception as exc:  # noqa: BLE001 - any failure is reported, never swallowed
            audit.record(
                category=EventCategory.TASK,
                action="slack question failed",
                outcome=Outcome.FAILURE,
                tool=TOOL,
                target=channel,
                details={"slack_user": user, "error": str(exc)[:500]},
            )
            self._post_reply(
                channel, f":warning: I could not answer: {escape(str(exc), 1000)}", thread
            )
            return
        with self._lock:
            state = self.load_state()
            state.threads[key] = answer.session_id
            self._save(state)
        sources = ""
        if answer.sources:
            listed = ", ".join(f"`{escape(s, 200)}`" for s in answer.sources[:6])
            sources = f"\n\n_Sources:_ {listed}"
        footer = f"\n_model {escape(answer.model, 100)} · session `{answer.session_id}`_"
        self._post_reply(channel, escape(answer.text, MAX_MESSAGE_TEXT) + sources + footer, thread)
        audit.record(
            category=EventCategory.TASK,
            action="slack question answered",
            outcome=Outcome.SUCCESS,
            tool=TOOL,
            target=channel,
            model=answer.model,
            session_id=answer.session_id,
            details={"slack_user": user, "sources": len(answer.sources)},
        )

    def _post_reply(self, channel: str, text: str, thread: str | None) -> None:
        try:
            self.api.post_message(channel, text, thread_ts=thread)
        except SlackError as exc:
            self.audit().record(
                category=EventCategory.TOOL_CALL,
                action="slack reply failed",
                outcome=Outcome.FAILURE,
                tool=TOOL,
                target=channel,
                details={"error": str(exc)},
            )


# ------------------------------------------------------------------ Socket Mode


def make_listener(
    bridge: SlackBridge,
    respond: Callable[[Any, str], None],
    on_error: Callable[[Exception], None],
) -> Callable[[Any, Any], None]:
    """The Socket Mode listener: acknowledge first, then handle.

    Slack expects an acknowledgement within three seconds and re-delivers otherwise, and
    answering a question takes longer than that. So the envelope is acknowledged before
    any work starts; a failure while handling is reported, never raised into the socket
    client's thread.
    """

    def listener(client: Any, request: Any) -> None:
        respond(client, str(request.envelope_id))
        try:
            bridge.handle(str(request.type), dict(request.payload or {}))
        except Exception as exc:  # noqa: BLE001 - see docstring
            on_error(exc)

    return listener


def socket_client(app_token: str, api_url: str, network: NetworkPolicy) -> Any:
    """A Socket Mode client that checks the WebSocket host Slack hands it (SAFE-005).

    ``apps.connections.open`` returns a fresh ``wss://`` URL on every (re)connect. The
    host is checked each time rather than trusted, so a reconnect cannot quietly go
    somewhere the network policy does not allow.
    """
    try:
        from slack_sdk import WebClient
        from slack_sdk.socket_mode.builtin import SocketModeClient
    except ImportError as exc:  # pragma: no cover - depends on the install
        raise SlackError(
            'Socket Mode needs the optional Slack dependency: pip install -e ".[slack]"'
        ) from exc

    # The ignores cover both installs: without slack_sdk its classes are Any.
    class _CheckedClient(SocketModeClient):  # type: ignore[misc,unused-ignore]
        def issue_new_wss_url(self, *args: Any, **kwargs: Any) -> str:
            url = str(super().issue_new_wss_url(*args, **kwargs))
            host = urlparse(url).hostname or ""
            if urlparse(url).scheme != "wss" or not network.is_host_allowed(host):
                raise SlackError(
                    f"Slack asked for a WebSocket to {host or url!r}, which the network "
                    "policy does not allow (SAFE-005)"
                )
            return url

    web = WebClient(base_url=api_url.rstrip("/") + "/")
    return _CheckedClient(app_token=app_token, web_client=web)


def run_socket_mode(
    bridge: SlackBridge,
    app_token: str,
    network: NetworkPolicy,
    stop: threading.Event,
    on_error: Callable[[Exception], None],
    on_sync: Callable[[SyncResult], None] | None = None,
) -> None:
    """Connect to Slack over Socket Mode and run until ``stop`` is set."""
    client = socket_client(app_token, bridge.config.api_url, network)
    from slack_sdk.socket_mode.response import SocketModeResponse

    def respond(socket: Any, envelope_id: str) -> None:
        socket.send_socket_mode_response(SocketModeResponse(envelope_id=envelope_id))

    client.socket_mode_request_listeners.append(make_listener(bridge, respond, on_error))
    client.connect()
    try:
        while not stop.is_set():
            try:
                result = bridge.sync()
            except Exception as exc:  # noqa: BLE001 - one failed pass must not end the bridge
                on_error(exc)
            else:
                if on_sync is not None:
                    on_sync(result)
            stop.wait(bridge.config.poll_seconds)
    finally:
        client.close()
