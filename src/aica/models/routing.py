"""Model routing, fallback and pinning (MM-004, MM-009, MM-010, MM-011, MM-012).

The agent core never picks a model. It asks for one *for a kind of work* - completion, chat,
coding, planning, review, testing, embeddings - and this module answers with an adapter,
having applied the rules in ``config/models.toml``. That indirection is what MM-008 asks for:
adding a provider, changing which model reviews code, or pinning a version for reproducibility
is a configuration change, not an agent-core change.

Four behaviours are worth stating precisely, because each one can go wrong quietly:

* **Routing** (MM-009) picks the first candidate that is approved, enabled, capable of the
  work and large enough in context. A model that cannot do the job is never selected in the
  hope that it manages anyway.
* **Fallback** (MM-010) is only for *unavailability*: a refused connection, a 5xx, a timeout,
  a rate limit, or a credential that is not configured on this machine. A model that answers
  badly is not a fallback trigger - that would hide a real failure behind a second opinion.
* **Manual selection** (MM-002) is respected. Asking for a model by name gets that model; the
  fallback chain is appended only when the request is not pinned, because a pin means "this
  exact version or nothing" (MM-011).
* **Streaming falls back only before the first chunk reaches the caller.** Once one token has
  been delivered, switching models would splice two different answers together. After that
  point the error propagates, as it should.

Every selection and every fallback is recorded with the exact model and version (MM-012).
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field, model_validator

from aica.audit import AuditLog, EventCategory, Outcome
from aica.models.base import (
    Capability,
    ChatMessage,
    ModelAdapter,
    ModelError,
    ModelInfo,
    ModelResponse,
    ModelUnavailable,
    StreamChunk,
)

if TYPE_CHECKING:  # gateway.py imports RoutingConfig from here, so this import is types-only
    from aica.models.gateway import ModelGateway

MAX_CANDIDATES = 8


class TaskKind(StrEnum):
    """The kinds of work a model can be routed for (MM-004).

    BRD MM-004 names "completion, chat, coding, review and other tasks"; the rest are the
    other places this system actually calls a model, so a rule can address each of them.
    """

    COMPLETION = "completion"  # CC-001: inline code completion
    CHAT = "chat"  # CHAT-001: coding conversation
    CODING = "coding"  # the editing steps of an agent task
    PLANNING = "planning"  # AG-002: producing a plan
    REVIEW = "review"  # REV-*: reviewing a change
    TESTING = "testing"  # TEST-007: writing tests
    COMMIT_MESSAGE = "commit_message"  # GIT-006
    EMBEDDINGS = "embeddings"  # RAG-002
    GENERAL = "general"  # anything without a rule of its own


# What a model must be able to do before it may be routed to a kind of work. A rule can add
# to this, never subtract: a model that cannot stream is no use for interactive chat.
REQUIRED_CAPABILITIES: dict[TaskKind, tuple[Capability, ...]] = {
    TaskKind.COMPLETION: (Capability.CHAT,),  # FIM is preferred, not required (see _score)
    TaskKind.CHAT: (Capability.CHAT, Capability.STREAMING),
    TaskKind.CODING: (Capability.CHAT,),
    TaskKind.PLANNING: (Capability.CHAT,),
    TaskKind.REVIEW: (Capability.CHAT,),
    TaskKind.TESTING: (Capability.CHAT,),
    TaskKind.COMMIT_MESSAGE: (Capability.CHAT,),
    TaskKind.EMBEDDINGS: (Capability.EMBEDDINGS,),
    TaskKind.GENERAL: (Capability.CHAT,),
}


class RoutingRule(BaseModel):
    """One ``[[routing.rules]]`` entry: which model handles which kind of work."""

    model_config = ConfigDict(extra="forbid")

    task: TaskKind
    model: str | None = None
    fallbacks: list[str] = Field(default_factory=list)
    require: list[Capability] = Field(default_factory=list)
    min_context: int | None = Field(default=None, gt=0)

    @model_validator(mode="after")
    def _model_or_requirements(self) -> RoutingRule:
        if not self.model and not (self.require or self.min_context or self.fallbacks):
            raise ValueError(
                f"routing rule for {self.task.value!r} says nothing: give it a model, a "
                "fallback chain, a required capability or a minimum context size"
            )
        return self


class RoutingConfig(BaseModel):
    """The ``[routing]`` table. An empty one means "always use the configured default"."""

    model_config = ConfigDict(extra="forbid")

    # Tried, in order, after a rule's own chain. Named models must exist in the registry.
    fallbacks: list[str] = Field(default_factory=list)
    rules: list[RoutingRule] = Field(default_factory=list)

    @model_validator(mode="after")
    def _one_rule_per_task(self) -> RoutingConfig:
        seen: set[TaskKind] = set()
        for rule in self.rules:
            if rule.task in seen:
                raise ValueError(f"more than one routing rule for task {rule.task.value!r}")
            seen.add(rule.task)
        return self

    def rule_for(self, task: TaskKind) -> RoutingRule | None:
        return next((r for r in self.rules if r.task is task), None)


class RoutingError(ModelError):
    """No approved model can do the work that was asked for."""


@dataclass
class Selection:
    """What the router chose, and why. Carries enough to record MM-012 accurately."""

    task: TaskKind
    name: str
    version: str
    adapter: ModelAdapter
    reason: str
    candidates: list[str] = field(default_factory=list)
    rejected: dict[str, str] = field(default_factory=dict)

    @property
    def fallbacks(self) -> list[str]:
        return self.candidates[1:]

    def describe(self) -> str:
        text = f"{self.task.value}: {self.name} ({self.version}) - {self.reason}"
        if self.fallbacks:
            text += f"; fallback: {', '.join(self.fallbacks)}"
        return text


class FallbackAdapter:
    """An adapter that tries several models in order when one is unavailable (MM-010).

    It is itself a ``ModelAdapter``, so nothing in the agent core knows this is happening
    (MM-008). ``info`` reports the primary candidate: that is what the caller asked for, and
    reporting whichever model happened to answer would change the reported context window
    under the caller's feet mid-run.
    """

    def __init__(
        self,
        chain: list[tuple[str, ModelAdapter]],
        info: ModelInfo,
        *,
        audit: AuditLog | None = None,
        task: TaskKind = TaskKind.GENERAL,
        session_id: str | None = None,
        versions: dict[str, str] | None = None,
    ) -> None:
        if not chain:
            raise RoutingError("a fallback chain needs at least one model")
        self._chain = chain[:MAX_CANDIDATES]
        self._info = info
        self._audit = audit
        self._task = task
        self._session_id = session_id
        self._versions = versions or {}
        # MM-012: what actually answered, and everything that did not.
        self.last_used: str | None = None
        self.attempts: list[str] = []

    @property
    def info(self) -> ModelInfo:
        return self._info

    @property
    def names(self) -> list[str]:
        return [name for name, _ in self._chain]

    def _record(self, name: str, outcome: Outcome, action: str, **details: object) -> None:
        if self._audit is None:
            return
        version = self._versions.get(name, name)
        self._audit.record(
            category=EventCategory.MODEL_CALL,
            action=action,
            outcome=outcome,
            model=f"{name}@{version}",
            details={"task": self._task.value, **details},
            session_id=self._session_id,
        )

    # ------------------------------------------------------------------ protocol
    def chat(
        self,
        messages: list[ChatMessage],
        *,
        temperature: float = 0.2,
        max_tokens: int | None = None,
    ) -> ModelResponse:
        errors: list[str] = []
        for name, adapter in self._chain:
            self.attempts.append(name)
            try:
                response = adapter.chat(messages, temperature=temperature, max_tokens=max_tokens)
            except ModelUnavailable as exc:
                errors.append(f"{name}: {exc}")
                self._record(name, Outcome.FAILURE, "model unavailable", error=str(exc)[:300])
                continue
            self.last_used = name
            self._record(name, Outcome.SUCCESS, "chat", served=response.model, after=len(errors))
            return response
        raise ModelUnavailable(self._exhausted(errors))

    def stream(
        self,
        messages: list[ChatMessage],
        *,
        temperature: float = 0.2,
        max_tokens: int | None = None,
    ) -> Iterator[StreamChunk]:
        errors: list[str] = []
        for name, adapter in self._chain:
            self.attempts.append(name)
            iterator = adapter.stream(messages, temperature=temperature, max_tokens=max_tokens)
            try:
                first = next(iterator)
            except StopIteration:  # an empty stream: nothing was delivered, so falling back is safe
                errors.append(f"{name}: empty stream")
                self._record(name, Outcome.FAILURE, "empty stream")
                continue
            except ModelUnavailable as exc:
                errors.append(f"{name}: {exc}")
                self._record(name, Outcome.FAILURE, "model unavailable", error=str(exc)[:300])
                continue
            self.last_used = name
            self._record(name, Outcome.SUCCESS, "stream", after=len(errors))
            yield first
            # Past this point a failure propagates: the caller already has part of an answer
            # from this model, and continuing from another would splice two replies together.
            yield from iterator
            return
        raise ModelUnavailable(self._exhausted(errors))

    def complete(self, prefix: str, suffix: str = "", *, max_tokens: int = 256) -> ModelResponse:
        errors: list[str] = []
        for name, adapter in self._chain:
            self.attempts.append(name)
            try:
                response = adapter.complete(prefix, suffix, max_tokens=max_tokens)
            except ModelUnavailable as exc:
                errors.append(f"{name}: {exc}")
                self._record(name, Outcome.FAILURE, "model unavailable", error=str(exc)[:300])
                continue
            self.last_used = name
            self._record(name, Outcome.SUCCESS, "complete", served=response.model)
            return response
        raise ModelUnavailable(self._exhausted(errors))

    def embed(self, texts: list[str]) -> list[list[float]]:
        errors: list[str] = []
        for name, adapter in self._chain:
            self.attempts.append(name)
            try:
                vectors = adapter.embed(texts)
            except ModelUnavailable as exc:
                errors.append(f"{name}: {exc}")
                self._record(name, Outcome.FAILURE, "model unavailable", error=str(exc)[:300])
                continue
            self.last_used = name
            self._record(name, Outcome.SUCCESS, "embed", count=len(texts))
            return vectors
        raise ModelUnavailable(self._exhausted(errors))

    def _exhausted(self, errors: list[str]) -> str:
        return (
            f"every model for {self._task.value} was unavailable "
            f"({len(errors)} tried): " + "; ".join(errors)
        )


class ModelRouter:
    """Chooses a model for a kind of work, under the registry's own rules (MM-009)."""

    def __init__(
        self,
        gateway: ModelGateway,
        config: RoutingConfig | None = None,
        *,
        audit: AuditLog | None = None,
        session_id: str | None = None,
    ) -> None:
        self.gateway = gateway
        self.config = config or RoutingConfig()
        self.audit = audit
        self.session_id = session_id

    # ------------------------------------------------------------------ selection
    def requirements(self, task: TaskKind, rule: RoutingRule | None) -> list[Capability]:
        needed = list(REQUIRED_CAPABILITIES.get(task, (Capability.CHAT,)))
        for capability in rule.require if rule else []:
            if capability not in needed:
                needed.append(capability)
        return needed

    def _usable(
        self, name: str, needed: list[Capability], min_context: int | None
    ) -> tuple[bool, str]:
        """Can this model do this work? Returns (usable, why not)."""
        try:
            config = self.gateway.config_for(name)
        except ModelError as exc:
            return False, str(exc)
        info = config.info()
        missing = [c.value for c in needed if not info.supports(c)]
        if missing:
            return False, f"lacks {', '.join(missing)}"
        if min_context and info.context_window < min_context:
            return False, f"context window {info.context_window} < {min_context}"
        return True, ""

    def candidates(
        self,
        task: TaskKind = TaskKind.GENERAL,
        *,
        requested: str | None = None,
        min_context: int | None = None,
    ) -> tuple[list[str], dict[str, str], str]:
        """The ordered candidate list, what was rejected and why, and the reason chosen."""
        rule = self.config.rule_for(task)
        needed = self.requirements(task, rule)
        floor = min_context or (rule.min_context if rule else None)

        order: list[str] = []
        reason: str
        if requested:
            order.append(requested)
            reason = "requested by name (MM-002)"
            # A pinned model means this exact version or nothing: no silent substitution.
            if not self._is_pinned(requested):
                order += rule.fallbacks if rule else []
                order += self.config.fallbacks
        elif rule and rule.model:
            order.append(rule.model)
            reason = f"routing rule for {task.value} (MM-009)"
            order += rule.fallbacks
            order += self.config.fallbacks
        else:
            default = self.gateway.default_name()
            if default:
                order.append(default)
            reason = "configured default (MM-003)"
            order += rule.fallbacks if rule else []
            order += self.config.fallbacks

        ordered: list[str] = []
        for name in order:  # first mention wins; a name repeated later adds nothing
            if name not in ordered:
                ordered.append(name)
        usable: list[str] = []
        rejected: dict[str, str] = {}
        for name in ordered:
            ok, why = self._usable(name, needed, floor)
            if ok:
                usable.append(name)
            else:
                rejected[name] = why
        return usable[:MAX_CANDIDATES], rejected, reason

    def _is_pinned(self, name: str) -> bool:
        try:
            return self.gateway.config_for(name).pinned
        except ModelError:
            return False

    def select(
        self,
        task: TaskKind = TaskKind.GENERAL,
        *,
        requested: str | None = None,
        min_context: int | None = None,
    ) -> Selection:
        """Pick a model for ``task``. The returned adapter carries the fallback chain."""
        usable, rejected, reason = self.candidates(
            task, requested=requested, min_context=min_context
        )
        if not usable:
            detail = "; ".join(f"{n}: {why}" for n, why in rejected.items()) or "none configured"
            if self.audit is not None:
                self.audit.record(
                    category=EventCategory.MODEL_CALL,
                    action=f"no model for {task.value}",
                    outcome=Outcome.FAILURE,
                    details={"task": task.value, "rejected": detail[:500]},
                    session_id=self.session_id,
                )
            raise RoutingError(f"no approved model can handle {task.value}: {detail}")

        # Build the chain now. Construction does no I/O, but it is where a missing
        # credential or an endpoint the network policy refuses is discovered, and that is a
        # configuration error the caller should see at selection rather than mid-run.
        chain: list[tuple[str, ModelAdapter]] = []
        versions: dict[str, str] = {}
        first_error: Exception | None = None
        for name in usable:
            try:
                chain.append((name, self.gateway.get(name)))
                versions[name] = self.gateway.config_for(name).version
            except (ModelError, PermissionError) as exc:
                rejected[name] = f"{type(exc).__name__}: {exc}"
                first_error = first_error or exc
        if not chain:
            assert first_error is not None  # noqa: S101 - usable was non-empty
            if len(usable) == 1:
                raise first_error  # one candidate: its own error is the clearest answer
            raise RoutingError(
                f"no model for {task.value} could be used: "
                + "; ".join(f"{n}: {why}" for n, why in rejected.items())
            )
        usable = [name for name, _ in chain]
        primary = self.gateway.config_for(usable[0])
        # The reason describes the model that was *meant* to serve. When that one was skipped
        # (no credential, refused endpoint, too small a window), whatever serves instead came
        # from the fallback chain, and saying "routing rule" would misreport where it came from.
        rule = self.config.rule_for(task)
        intended = requested or (rule.model if rule and rule.model else None)
        intended = intended or self.gateway.default_name()
        if intended and intended != primary.name and intended in rejected:
            reason = f"fallback (MM-010): {intended} skipped - {rejected[intended]}"
        adapter = FallbackAdapter(
            chain,
            primary.info(),
            audit=self.audit,
            task=task,
            session_id=self.session_id,
            versions=versions,
        )
        selection = Selection(
            task=task,
            name=primary.name,
            version=primary.version,
            adapter=adapter,
            reason=reason,
            candidates=usable,
            rejected=rejected,
        )
        if self.audit is not None:
            self.audit.record(
                category=EventCategory.MODEL_CALL,
                action=f"route {task.value}",
                outcome=Outcome.SUCCESS,
                model=f"{primary.name}@{primary.version}",
                details={
                    "task": task.value,
                    "reason": reason,
                    "fallbacks": ", ".join(selection.fallbacks),
                    "skipped": "; ".join(f"{n}: {why}" for n, why in rejected.items())[:500],
                    "pinned": primary.pinned,
                },
                session_id=self.session_id,
            )
        return selection

    def get(
        self,
        task: TaskKind = TaskKind.GENERAL,
        *,
        requested: str | None = None,
        min_context: int | None = None,
    ) -> ModelAdapter:
        """``select`` when only the adapter is wanted."""
        return self.select(task, requested=requested, min_context=min_context).adapter
