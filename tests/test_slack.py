"""Slack collaboration integration (INT-004).

The bridge is tested against the real approval queue, the real RBAC policy, the real
control plane and real audit files; only Slack itself is replaced - by a recorder for the
bridge, by httpx's mock transport for the Web API client, and by a real loopback HTTP
server for the CLI, so the command is exercised over actual HTTP.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import httpx
import pytest

from aica.admin.approval_queue import ApprovalQueue, DecisionState
from aica.admin.controls import ControlPlane, TargetKind
from aica.admin.rbac import Role, RoleBinding
from aica.approvals import ApprovalRequest
from aica.audit.events import AuditEvent, EventCategory, Outcome
from aica.audit.sink import AuditLog, JsonlAuditSink
from aica.cli import main
from aica.integrations.slack import (
    APPROVE_ACTION,
    REJECT_ACTION,
    SlackAnswer,
    SlackBridge,
    SlackConfig,
    SlackError,
    SlackWebApi,
    check_network,
    escape,
    load_slack,
    make_listener,
)
from aica.policy.models import ActionCategory, NetworkMode, NetworkPolicy, Policy, RbacPolicy

CHANNEL = "C0CHANNEL1"
ALICE, BOB, DAVE, MALLORY = "UALICE0001", "UBOB000001", "UDAVE00001", "UMALLORY01"
BOT_TOKEN = "xoxb-1111111111-2222222222-abcdefghijklmnop"
REQUEST = ApprovalRequest(
    action="rm -rf build/",
    categories=(ActionCategory.DESTRUCTIVE,),
    tool="shell.run",
)


# ------------------------------------------------------------------ doubles and fixtures


@dataclass
class FakeSlack:
    """Records every Web API call the bridge makes."""

    posts: list[dict[str, Any]] = field(default_factory=list)
    updates: list[dict[str, Any]] = field(default_factory=list)
    ephemerals: list[dict[str, Any]] = field(default_factory=list)
    fail: bool = False

    def post_message(
        self,
        channel: str,
        text: str,
        blocks: list[dict[str, Any]] | None = None,
        thread_ts: str | None = None,
    ) -> str:
        if self.fail:
            raise SlackError("chat.postMessage: channel_not_found")
        ts = f"1700000000.{len(self.posts):06d}"
        self.posts.append(
            {"channel": channel, "text": text, "blocks": blocks, "thread_ts": thread_ts, "ts": ts}
        )
        return ts

    def update_message(
        self, channel: str, ts: str, text: str, blocks: list[dict[str, Any]] | None = None
    ) -> None:
        self.updates.append({"channel": channel, "ts": ts, "text": text, "blocks": blocks})

    def post_ephemeral(
        self, channel: str, user: str, text: str, thread_ts: str | None = None
    ) -> None:
        self.ephemerals.append({"channel": channel, "user": user, "text": text})


def _policy(rbac: bool = True) -> Policy:
    return Policy(
        rbac=RbacPolicy(
            enabled=rbac,
            bindings=[
                RoleBinding(principal="alice", roles=[Role.APPROVER]),
                RoleBinding(principal="bob", roles=[Role.APPROVER]),
                RoleBinding(principal="dave", roles=[Role.DEVELOPER]),
            ],
        )
    )


def _config(**overrides: Any) -> SlackConfig:
    base: dict[str, Any] = {
        "enabled": True,
        "channel": CHANNEL,
        "users": {ALICE: "alice", BOB: "bob", DAVE: "dave"},
    }
    return SlackConfig.model_validate({**base, **overrides})


@dataclass
class Harness:
    root: Path
    slack: FakeSlack
    bridge: SlackBridge
    questions: list[tuple[str, str, str | None]]

    @property
    def queue(self) -> ApprovalQueue:
        return ApprovalQueue(self.root)

    def audit(self) -> list[AuditEvent]:
        return list(JsonlAuditSink(self.root / ".aica" / "audit").read_all())

    def press(self, user: str, request_id: str, approve: bool = True, **extra: Any) -> None:
        payload = {
            "type": "block_actions",
            "user": {"id": user},
            "channel": {"id": extra.get("channel", CHANNEL)},
            "container": {"channel_id": CHANNEL, "message_ts": extra.get("ts", "1700000000.1")},
            "actions": [
                {"action_id": APPROVE_ACTION if approve else REJECT_ACTION, "value": request_id}
            ],
        }
        self.bridge.handle("interactive", payload)

    def say(self, user: str, text: str, **event: Any) -> None:
        body = {
            "type": "app_mention",
            "user": user,
            "text": text,
            "channel": CHANNEL,
            "ts": "1700000100.000100",
            **event,
        }
        envelope_id = event.pop("event_id", None) or f"Ev{len(self.questions)}{text[:5]}"
        self.bridge.handle("events_api", {"event_id": envelope_id, "event": body})


def _harness(
    tmp_path: Path,
    *,
    rbac: bool = True,
    answer: str = "It computes the invoice total.",
    **config: Any,
) -> Harness:
    slack = FakeSlack()
    questions: list[tuple[str, str, str | None]] = []

    def answerer(principal: str, question: str, session_id: str | None) -> SlackAnswer:
        questions.append((principal, question, session_id))
        if question == "explode":
            raise RuntimeError("model unavailable: no key")
        return SlackAnswer(
            text=answer,
            session_id=session_id or f"s-{len(questions)}",
            model="scripted-model-v0",
            sources=["src/invoice.py:1-3"],
        )

    bridge = SlackBridge(
        tmp_path,
        _config(**config),
        slack,
        policy_loader=lambda: _policy(rbac),
        answerer=answerer,
        actor="operator",
    )
    return Harness(tmp_path, slack, bridge, questions)


# ------------------------------------------------------------------ configuration


def test_config_requires_https_ids_and_a_channel(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="https"):
        _config(api_url="http://slack.example.com/api")
    assert _config(api_url="http://127.0.0.1:9/api").host == "127.0.0.1"  # loopback tests
    with pytest.raises(ValueError, match="not a Slack user ID"):
        _config(users={"alice": "alice"})  # a display name, which anyone can change
    with pytest.raises(ValueError, match="channel ID"):
        SlackConfig(enabled=True)
    with pytest.raises(ValueError):
        _config(channel="#general")
    assert SlackConfig().enabled is False  # off unless configured

    with pytest.raises(SlackError, match="slack.toml.example"):
        load_slack(tmp_path / "missing.toml")
    bad = tmp_path / "bad.toml"
    bad.write_text("enabled = true\nchannel = 'C0CHANNEL1'\nsurprise = 1\n", encoding="utf-8")
    with pytest.raises(SlackError, match="not a valid Slack configuration"):
        load_slack(bad)


def test_the_shipped_example_parses_and_is_disabled() -> None:
    config = load_slack(Path(__file__).parents[1] / "config" / "slack.toml.example")
    assert config.enabled is False and config.users == {}


def test_network_policy_must_allow_slack() -> None:
    config = _config()
    with pytest.raises(SlackError, match="slack.com"):
        check_network(config, NetworkPolicy())  # deny by default (SAFE-005)
    with pytest.raises(SlackError, match="wss-primary.slack.com"):
        check_network(
            config, NetworkPolicy(mode=NetworkMode.ALLOWLIST, allowed_hosts=["slack.com"])
        )
    check_network(
        config,
        NetworkPolicy(mode=NetworkMode.ALLOWLIST, allowed_hosts=["slack.com", "*.slack.com"]),
    )


def test_escape_redacts_neutralises_mentions_and_bounds_length() -> None:
    text = escape(f"<!channel> see <https://evil.example|docs> token {BOT_TOKEN} & more")
    assert "<!channel>" not in text and "&lt;!channel&gt;" in text
    assert "<https://" not in text
    assert BOT_TOKEN not in text and "[REDACTED" in text
    assert "&amp; more" in text
    assert len(escape("x" * 10_000, 100)) <= 100


# ------------------------------------------------------------------ Web API client


def test_web_api_sends_the_token_as_a_header_and_reports_slack_errors() -> None:
    seen: list[httpx.Request] = []

    def slack(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        body = json.loads(request.content)
        if request.url.path.endswith("chat.postMessage"):
            if body["channel"] == "C0MISSING1":
                return httpx.Response(200, json={"ok": False, "error": "channel_not_found"})
            return httpx.Response(200, json={"ok": True, "ts": "1.2"})
        return httpx.Response(429, headers={"Retry-After": "7"}, json={"ok": False})

    api = SlackWebApi("https://slack.com/api", BOT_TOKEN, transport=httpx.MockTransport(slack))
    assert api.post_message(CHANNEL, "hi", blocks=[{"type": "divider"}], thread_ts="9.9") == "1.2"
    request = seen[0]
    assert request.headers["Authorization"] == f"Bearer {BOT_TOKEN}"
    assert request.url == httpx.URL("https://slack.com/api/chat.postMessage")
    sent = json.loads(request.content)
    assert sent == {
        "channel": CHANNEL,
        "text": "hi",
        "unfurl_links": False,
        "blocks": [{"type": "divider"}],
        "thread_ts": "9.9",
    }
    assert BOT_TOKEN not in request.content.decode()  # the token travels only as a header

    with pytest.raises(SlackError, match="channel_not_found"):
        api.post_message("C0MISSING1", "hi")
    with pytest.raises(SlackError, match="retry after 7s"):
        api.update_message(CHANNEL, "1.2", "edited")


def test_web_api_never_echoes_the_token_in_a_transport_error() -> None:
    def broken(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"refused while sending {BOT_TOKEN}", request=request)

    api = SlackWebApi("https://slack.com/api", BOT_TOKEN, transport=httpx.MockTransport(broken))
    with pytest.raises(SlackError) as excinfo:
        api.auth_test()
    assert BOT_TOKEN not in str(excinfo.value)


# ------------------------------------------------------------------ approvals out


def test_a_pending_approval_is_posted_once_with_buttons(tmp_path: Path) -> None:
    h = _harness(tmp_path)
    entry = h.queue.submit(REQUEST, requested_by="dana")

    result = h.bridge.sync()
    assert (result.posted, result.errors) == (1, [])
    post = h.slack.posts[0]
    assert post["channel"] == CHANNEL
    body = post["blocks"][0]["text"]["text"]
    assert "destructive" in body and "rm -rf build/" in body and "dana" in body
    buttons = post["blocks"][-1]["elements"]
    assert [(b["action_id"], b["value"]) for b in buttons] == [
        (APPROVE_ACTION, entry.id),
        (REJECT_ACTION, entry.id),
    ]
    assert h.bridge.sync().posted == 0  # remembered, including across a restart
    assert len(h.slack.posts) == 1
    assert any(
        e.category is EventCategory.TOOL_CALL and e.action.startswith("posted approval")
        for e in h.audit()
    )


def test_action_text_cannot_ping_the_channel_or_leak_a_secret(tmp_path: Path) -> None:
    h = _harness(tmp_path)
    h.queue.submit(
        ApprovalRequest(
            action=f"curl -H 'Authorization: {BOT_TOKEN}' <!here>",
            categories=(ActionCategory.EXTERNAL,),
            tool="shell.run",
        ),
        requested_by="dana",
    )
    h.bridge.sync()
    posted = json.dumps(h.slack.posts)
    assert BOT_TOKEN not in posted
    assert "<!here>" not in posted


def test_a_decision_made_elsewhere_retires_the_buttons(tmp_path: Path) -> None:
    h = _harness(tmp_path, rbac=False)
    entry = h.queue.submit(REQUEST, requested_by="dana")
    h.bridge.sync()

    # Decided at the terminal: the same audited path (via=cli).
    assert main(["-w", str(tmp_path), "--actor", "carol", "approvals", "approve", entry.id]) == 0
    result = h.bridge.sync()
    assert result.updated == 1
    update = h.slack.updates[0]
    assert update["ts"] == h.slack.posts[0]["ts"]
    assert all(block["type"] != "actions" for block in update["blocks"])
    assert "Approved" in update["blocks"][0]["text"]["text"] and "carol" in update["text"] + str(
        update["blocks"]
    )
    decisions = [e for e in h.audit() if e.category is EventCategory.APPROVAL]
    assert decisions[-1].details["via"] == "cli" and decisions[-1].actor == "carol"
    assert h.bridge.sync().updated == 0


def test_an_approval_cleared_from_the_queue_is_marked_expired(tmp_path: Path) -> None:
    h = _harness(tmp_path)
    entry = h.queue.submit(REQUEST, requested_by="dana")
    h.bridge.sync()
    h.queue.path.write_text(json.dumps({"version": 1, "approvals": []}), encoding="utf-8")
    assert h.bridge.sync().updated == 1
    assert entry.id in h.slack.updates[0]["blocks"][0]["text"]["text"]
    assert "no longer in the queue" in h.slack.updates[0]["blocks"][0]["text"]["text"]


def test_a_failed_post_is_reported_and_retried(tmp_path: Path) -> None:
    h = _harness(tmp_path)
    h.queue.submit(REQUEST, requested_by="dana")
    h.slack.fail = True
    result = h.bridge.sync()
    assert result.posted == 0 and "channel_not_found" in result.errors[0]
    h.slack.fail = False
    assert h.bridge.sync().posted == 1


# ------------------------------------------------------------------ approvals in


def test_a_mapped_approver_decides_through_the_shared_path(tmp_path: Path) -> None:
    h = _harness(tmp_path)
    entry = h.queue.submit(REQUEST, requested_by="dana")
    h.bridge.sync()

    h.press(ALICE, entry.id, ts=h.slack.posts[0]["ts"])

    decided = h.queue.get(entry.id)
    assert decided.state is DecisionState.APPROVED and decided.decided_by == "alice"
    record = [e for e in h.audit() if e.category is EventCategory.APPROVAL][-1]
    assert record.actor == "alice" and record.outcome is Outcome.SUCCESS
    assert record.details["via"] == "slack" and record.details["slack_user"] == ALICE
    assert h.slack.updates[-1]["ts"] == h.slack.posts[0]["ts"]
    assert "via Slack" in h.slack.updates[-1]["blocks"][0]["text"]["text"]
    assert h.bridge.sync().updated == 0  # already retired by the button handler


def test_a_rejection_is_recorded_as_rejected(tmp_path: Path) -> None:
    h = _harness(tmp_path)
    entry = h.queue.submit(REQUEST, requested_by="dana")
    h.press(BOB, entry.id, approve=False)
    assert h.queue.get(entry.id).state is DecisionState.REJECTED


@pytest.mark.parametrize(
    ("user", "requester", "reason"),
    [
        (MALLORY, "dana", "not mapped"),  # anyone in the channel who is not configured
        (DAVE, "dana", "approve"),  # a developer cannot approve (ADM-001)
        (ALICE, "alice", "SEC-006"),  # nobody approves their own request
    ],
)
def test_refused_decisions_change_nothing_and_are_audited(
    tmp_path: Path, user: str, requester: str, reason: str
) -> None:
    h = _harness(tmp_path)
    entry = h.queue.submit(REQUEST, requested_by=requester)
    h.press(user, entry.id)

    assert h.queue.get(entry.id).state is DecisionState.PENDING
    assert reason in h.slack.ephemerals[-1]["text"]
    assert h.slack.ephemerals[-1]["user"] == user
    blocked = [e for e in h.audit() if e.outcome is Outcome.BLOCKED]
    assert blocked, "a refused attempt must leave an audit record"
    assert blocked[-1].details.get("slack_user") == user


def test_buttons_outside_the_configured_channel_are_ignored(tmp_path: Path) -> None:
    h = _harness(tmp_path)
    entry = h.queue.submit(REQUEST, requested_by="dana")
    h.press(ALICE, entry.id, channel="C0ELSEWHERE")
    assert h.queue.get(entry.id).state is DecisionState.PENDING
    assert "configured channel" in h.slack.ephemerals[-1]["text"]


def test_with_rbac_off_the_mapping_is_still_the_gate(tmp_path: Path) -> None:
    h = _harness(tmp_path, rbac=False)
    entry = h.queue.submit(REQUEST, requested_by="dana")
    h.press(MALLORY, entry.id)
    assert h.queue.get(entry.id).state is DecisionState.PENDING
    h.press(DAVE, entry.id)  # mapped; with RBAC off every principal may approve
    assert h.queue.get(entry.id).state is DecisionState.APPROVED


def test_the_kill_switch_stops_posting_and_deciding(tmp_path: Path) -> None:
    h = _harness(tmp_path)
    entry = h.queue.submit(REQUEST, requested_by="dana")
    ControlPlane(tmp_path, actor="admin").disable(TargetKind.INTEGRATION, "slack", "incident")

    result = h.bridge.sync()
    assert result.skipped.startswith("disabled") and h.slack.posts == []
    h.press(ALICE, entry.id)
    assert h.queue.get(entry.id).state is DecisionState.PENDING
    assert "SEC-007" in h.slack.ephemerals[-1]["text"]

    ControlPlane(tmp_path, actor="admin2").enable(TargetKind.INTEGRATION, "slack", "over")
    assert h.bridge.sync().posted == 1


# ------------------------------------------------------------------ finished tasks


def _task_finished(root: Path, task: str, outcome: Outcome, when: datetime | None = None) -> None:
    JsonlAuditSink(root / ".aica" / "audit").write(
        AuditEvent(
            category=EventCategory.TASK,
            action=f"task finished: {task}",
            outcome=outcome,
            actor="dana",
            session_id="sess-1",
            timestamp=when or datetime.now(UTC),
            details={"outcome": "SUCCESS", "steps": 7, "changes": 1, "verification": "4 passed"},
        )
    )


def test_finished_tasks_are_announced_once_and_history_is_not_replayed(tmp_path: Path) -> None:
    h = _harness(tmp_path)
    _task_finished(tmp_path, "old work", Outcome.SUCCESS, datetime.now(UTC) - timedelta(hours=2))
    assert h.bridge.sync().announced == 0  # the first run starts now

    _task_finished(tmp_path, "fix <!channel> the pricing bug", Outcome.SUCCESS)
    assert h.bridge.sync().announced == 1
    text = h.slack.posts[-1]["text"]
    assert "Task finished" in text and "pricing bug" in text and "4 passed" in text
    assert "<!channel>" not in text and "dana" in text
    assert h.bridge.sync().announced == 0


def test_other_audit_events_are_not_announced(tmp_path: Path) -> None:
    h = _harness(tmp_path)
    h.bridge.sync()
    AuditLog(JsonlAuditSink(tmp_path / ".aica" / "audit"), actor="dana").record(
        category=EventCategory.TASK, action="review.completed", outcome=Outcome.SUCCESS
    )
    assert h.bridge.sync().announced == 0


# ------------------------------------------------------------------ questions


def test_a_mapped_user_gets_an_answer_in_the_thread(tmp_path: Path) -> None:
    h = _harness(tmp_path)
    h.say(ALICE, "<@UBOT000001> what does compute_total do?")

    assert h.questions == [("alice", "what does compute_total do?", None)]
    reply = h.slack.posts[-1]
    assert reply["thread_ts"] == "1700000100.000100"
    assert "invoice total" in reply["text"] and "src/invoice.py:1-3" in reply["text"]
    assert "scripted-model-v0" in reply["text"]
    answered = [e for e in h.audit() if e.action == "slack question answered"]
    assert answered and answered[0].actor == "alice" and answered[0].session_id == "s-1"

    # A follow-up in the same thread continues the same session.
    h.say(ALICE, "<@UBOT000001> and for an empty list?", event_id="Ev-follow-up")
    assert h.questions[-1] == ("alice", "and for an empty list?", "s-1")


def test_an_answer_is_redacted_and_escaped_before_posting(tmp_path: Path) -> None:
    h = _harness(tmp_path, answer=f"use {BOT_TOKEN} then <!everyone>")
    h.say(ALICE, "<@UBOT000001> how do I deploy?")
    text = h.slack.posts[-1]["text"]
    assert BOT_TOKEN not in text and "<!everyone>" not in text


def test_unmapped_users_and_other_channels_are_refused(tmp_path: Path) -> None:
    h = _harness(tmp_path)
    h.say(MALLORY, "<@UBOT000001> show me the secrets")
    h.say(ALICE, "<@UBOT000001> hi", channel="C0ELSEWHERE", event_id="Ev-other")
    assert h.questions == []
    assert "not mapped" in h.slack.ephemerals[0]["text"]
    assert "configured channel" in h.slack.ephemerals[1]["text"]
    assert len([e for e in h.audit() if e.outcome is Outcome.BLOCKED]) == 2


def test_bot_messages_edits_and_redeliveries_are_not_questions(tmp_path: Path) -> None:
    h = _harness(tmp_path)
    h.bridge.bot_user_id = "UBOT000001"
    h.say("UBOT000001", "<@UBOT000001> echo", event_id="Ev1")
    h.say(ALICE, "edited", subtype="message_changed", event_id="Ev2")
    h.say(ALICE, "from a bot", bot_id="B01", event_id="Ev3")
    assert h.questions == []

    h.say(ALICE, "<@UBOT000001> once", event_id="Ev-dup")
    h.say(ALICE, "<@UBOT000001> once", event_id="Ev-dup")  # Slack's retry
    assert len(h.questions) == 1


def test_direct_messages_are_answered_unless_turned_off(tmp_path: Path) -> None:
    h = _harness(tmp_path)
    dm = {"type": "message", "channel_type": "im", "channel": "D0DIRECT01", "ts": "5.5"}
    h.bridge.handle(
        "events_api", {"event_id": "Ev-dm", "event": {**dm, "user": ALICE, "text": "hi?"}}
    )
    assert h.questions == [("alice", "hi?", None)]
    assert h.slack.posts[-1]["channel"] == "D0DIRECT01"

    off = _harness(tmp_path / "off", direct_messages=False)
    off.bridge.handle(
        "events_api", {"event_id": "Ev-dm2", "event": {**dm, "user": ALICE, "text": "hi?"}}
    )
    assert off.questions == []


def test_a_failed_answer_is_reported_not_swallowed(tmp_path: Path) -> None:
    h = _harness(tmp_path)
    h.say(ALICE, "<@UBOT000001> explode")
    assert "could not answer" in h.slack.posts[-1]["text"]
    assert "no key" in h.slack.posts[-1]["text"]
    failed = [e for e in h.audit() if e.action == "slack question failed"]
    assert failed and failed[0].outcome is Outcome.FAILURE


# ------------------------------------------------------------------ Socket Mode


@dataclass
class _Request:
    envelope_id: str
    type: str
    payload: dict[str, Any]


def test_the_listener_acknowledges_before_handling_and_survives_errors(tmp_path: Path) -> None:
    order: list[str] = []
    errors: list[Exception] = []

    class Exploding(SlackBridge):
        def handle(self, kind: str, payload: dict[str, Any]) -> None:
            order.append(f"handle {kind}")
            raise RuntimeError("boom")

    bridge = Exploding(tmp_path, _config(), FakeSlack(), policy_loader=_policy)
    listener = make_listener(bridge, lambda _c, eid: order.append(f"ack {eid}"), errors.append)
    listener(object(), _Request("env-1", "events_api", {"event": {}}))
    assert order == ["ack env-1", "handle events_api"]
    assert [str(e) for e in errors] == ["boom"]


def test_the_socket_client_refuses_a_websocket_host_the_policy_does_not_allow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    builtin = pytest.importorskip("slack_sdk.socket_mode.builtin", reason="the slack extra")
    from aica.integrations.slack import socket_client

    urls = iter(["wss://wss-primary.slack.com/link/?ticket=t", "wss://evil.example/link"])
    monkeypatch.setattr(
        builtin.SocketModeClient, "issue_new_wss_url", lambda self, *a, **k: next(urls)
    )
    network = NetworkPolicy(mode=NetworkMode.ALLOWLIST, allowed_hosts=["*.slack.com"])
    client = socket_client("xapp-1-A0-1-abcdefghijkl", "https://slack.com/api", network)
    try:
        assert client.issue_new_wss_url().startswith("wss://wss-primary.slack.com/")
        with pytest.raises(SlackError, match="evil.example"):
            client.issue_new_wss_url()
    finally:
        client.close()


# ------------------------------------------------------------------ the CLI, over real HTTP


class _SlackServer:
    """A loopback stand-in for slack.com/api that records what reached it."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any]]] = []
        calls = self.calls

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802 - http.server's naming
                length = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(length) or b"{}")
                method = self.path.rsplit("/", 1)[-1]
                calls.append((method, self.headers.get("Authorization", ""), body))
                reply: dict[str, Any] = {"ok": True, "ts": f"1.{len(calls)}"}
                if method == "auth.test":
                    reply.update(user="aica", user_id="UBOT000001", team="Test Team")
                data = json.dumps(reply).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args: Any) -> None:
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/api"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def slack_server() -> Iterator[_SlackServer]:
    server = _SlackServer()
    yield server
    server.close()


def _workspace(tmp_path: Path, server: _SlackServer, *, network: bool = True) -> Path:
    (tmp_path / "config").mkdir(parents=True)
    hosts = "allowed_hosts = ['127.0.0.1']\n" if network else ""
    (tmp_path / "config" / "policy.toml").write_text(
        "version = 1\n"
        f"[network]\nmode = 'allowlist'\n{hosts}"
        "[[secrets.definitions]]\nname = 'slack_bot_token'\nenv_var = 'TEST_SLACK_BOT'\n"
        "allowed_tools = ['integration.slack']\n",
        encoding="utf-8",
    )
    (tmp_path / "config" / "slack.toml").write_text(
        f"enabled = true\napi_url = '{server.url}'\nchannel = '{CHANNEL}'\n"
        f"[users]\n{ALICE} = 'alice'\n",
        encoding="utf-8",
    )
    return tmp_path


def _slack_cli(root: Path, *args: str) -> int:
    return main(
        [
            "-w",
            str(root),
            "--policy",
            str(root / "config" / "policy.toml"),
            "--yes",
            "slack",
            *args,
            "--slack-file",
            str(root / "config" / "slack.toml"),
        ]
    )


def test_cli_check_and_sync_reach_slack_over_http(
    tmp_path: Path,
    slack_server: _SlackServer,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = _workspace(tmp_path, slack_server)
    monkeypatch.setenv("TEST_SLACK_BOT", BOT_TOKEN)

    assert _slack_cli(root, "check", "--post") == 0
    out = capsys.readouterr().out
    assert "connected as aica (UBOT000001) in workspace Test Team" in out
    assert "UALICE0001 -> alice" in out and "test message posted" in out
    assert [c[0] for c in slack_server.calls] == ["auth.test", "chat.postMessage"]
    assert all(auth == f"Bearer {BOT_TOKEN}" for _, auth, _ in slack_server.calls)

    entry = ApprovalQueue(root).submit(REQUEST, requested_by="dana")
    assert _slack_cli(root, "sync") == 0
    method, _, body = slack_server.calls[-1]
    assert method == "chat.postMessage" and body["channel"] == CHANNEL
    assert body["blocks"][-1]["elements"][0]["value"] == entry.id
    assert "1 approval request(s) posted" in capsys.readouterr().out

    events = list(JsonlAuditSink(root / ".aica" / "audit").read_all())
    assert BOT_TOKEN not in "".join(e.to_json_line() for e in events)
    # SEC-004: the secret was reached behind an audited approval, recorded by name only.
    access = [e for e in events if e.category is EventCategory.APPROVAL]
    assert access and access[0].tool == "integration.slack"
    assert "slack_bot_token" in access[0].action and access[0].details["approved"] is True


def test_cli_refuses_without_the_token_the_network_or_being_enabled(
    tmp_path: Path,
    slack_server: _SlackServer,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = _workspace(tmp_path / "a", slack_server)
    monkeypatch.delenv("TEST_SLACK_BOT", raising=False)
    assert _slack_cli(root, "check") == 3
    assert "TEST_SLACK_BOT is not set" in capsys.readouterr().err

    monkeypatch.setenv("TEST_SLACK_BOT", BOT_TOKEN)
    closed = _workspace(tmp_path / "b", slack_server, network=False)
    assert _slack_cli(closed, "check") == 3
    assert "network policy does not allow 127.0.0.1" in capsys.readouterr().err

    off = root / "config" / "slack.toml"
    off.write_text(off.read_text(encoding="utf-8").replace("enabled = true", "enabled = false"))
    assert _slack_cli(root, "check") == 3
    assert "not enabled" in capsys.readouterr().err

    ControlPlane(closed, actor="admin").disable(TargetKind.INTEGRATION, "slack")
    assert _slack_cli(closed, "check") == 5
    assert slack_server.calls == []  # nothing reached Slack in any of these


def test_the_cli_answerer_asks_the_real_assistant_as_that_principal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from aica import cli
    from aica.chat.session import SessionStore
    from aica.models.fake import ScriptedAdapter

    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "invoice.py").write_text(
        "def compute_total(items):\n    return sum(items)\n", encoding="utf-8"
    )
    scripted = ScriptedAdapter(["It sums the items.", "Zero."])
    monkeypatch.setattr(cli, "_adapter", lambda args, ctx, task=None: (scripted, None))
    args = cli.build_parser().parse_args(["-w", str(tmp_path), "slack", "run"])
    answer = cli._slack_answerer(args)

    first = answer("alice", "what does compute_total do?", None)
    assert first.text == "It sums the items." and first.model == "scripted-model-v0"
    session = SessionStore(tmp_path).load(first.session_id)
    assert session.owner == "alice"

    second = answer("alice", "and for an empty list?", first.session_id)
    assert second.session_id == first.session_id and second.text == "Zero."
    assert len(SessionStore(tmp_path).load(first.session_id).turns) == 4
    assert cli._OPEN_INDEXES == []  # a long-running bridge must not leak indexes
