// AICA web application (INT-003). Plain JavaScript over the HTTP API, no build step.
//
// Two rules hold throughout:
//  * Everything shown is inserted with textContent, never innerHTML. File contents, diffs,
//    plans and model output are untrusted data (SAFE-007), and a diff that contains
//    "<script>" must render as those characters.
//  * The page holds no authority of its own. Every action is an API call carrying the
//    bearer token, so every rule the API enforces applies here unchanged.
"use strict";

const TOKEN_KEY = "aica.token";
const state = {
  token: null,
  session: null,
  task: null,
  stream: null,
  pollTimer: null,
};

// ------------------------------------------------------------------ helpers
const $ = (id) => document.getElementById(id);

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (key === "class") node.className = value;
    else if (key === "on") for (const [ev, fn] of Object.entries(value)) node.addEventListener(ev, fn);
    else if (value !== undefined && value !== null) node.setAttribute(key, value);
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function readToken() {
  try { return sessionStorage.getItem(TOKEN_KEY); } catch { return null; }
}

function writeToken(value) {
  try {
    if (value) sessionStorage.setItem(TOKEN_KEY, value);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch { /* private mode: the token lives in memory only */ }
}

class ApiError extends Error {
  constructor(status, detail) {
    super(detail);
    this.status = status;
  }
}

async function api(path, options = {}) {
  const init = { method: options.method || "GET", headers: { Authorization: `Bearer ${state.token}` } };
  if (options.body !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(options.body);
  }
  const response = await fetch(path, init);
  if (response.status === 401) {
    signOut("The token was not accepted.");
    throw new ApiError(401, "unauthorised");
  }
  const text = await response.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = { detail: text }; }
  if (!response.ok) {
    const detail = data && data.detail !== undefined ? data.detail : response.statusText;
    throw new ApiError(response.status, typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  return data;
}

function showError(target, error) {
  target.textContent = error ? `${error.status ? error.status + ": " : ""}${error.message}` : "";
}

// ------------------------------------------------------------------ sign in
function signOut(message) {
  writeToken(null);
  state.token = null;
  stopStream();
  clearInterval(state.pollTimer);
  $("app").hidden = true;
  $("logout").hidden = true;
  $("login").hidden = false;
  $("login-error").textContent = message || "";
}

async function signIn(token) {
  state.token = token;
  try {
    const policy = await api("/policy");
    writeToken(token);
    $("login").hidden = true;
    $("app").hidden = false;
    $("logout").hidden = false;
    $("workspace").textContent = `${policy.actor} - ${policy.environment} - policy v${policy.version}`;
    await Promise.all([loadSessions(), loadModels(), refreshStatus()]);
    clearInterval(state.pollTimer);
    state.pollTimer = setInterval(refreshStatus, 5000);
  } catch (error) {
    if (error.status !== 401) signOut(`Could not connect: ${error.message}`);
  }
}

// ------------------------------------------------------------------ status bar
async function refreshStatus() {
  try {
    const [lease, approvals] = await Promise.all([api("/admin/lease"), api("/approvals")]);
    const badge = $("lease");
    badge.hidden = !lease.busy;
    badge.textContent = lease.busy
      ? `Repository busy${lease.lease ? `: ${lease.lease.actor}` : ""}`
      : "";
    badge.title = lease.lease ? `${lease.lease.task} (until ${lease.lease.expires_at})` : (lease.detail || "");
    renderApprovalBanner(approvals);
    if (!$("view-approvals").hidden) renderApprovals(approvals);
  } catch { /* the next poll will try again */ }
}

function renderApprovalBanner(approvals) {
  const count = approvals.count || 0;
  const banner = $("approvals-banner");
  const badge = $("approvals-badge");
  $("approvals-count").textContent = count ? `(${count})` : "";
  badge.hidden = banner.hidden = count === 0;
  if (!count) return;
  badge.textContent = `${count} approval${count === 1 ? "" : "s"} waiting`;
  banner.replaceChildren(
    el("strong", {}, `${count} request${count === 1 ? "" : "s"} waiting for a decision. `),
    el("span", {}, approvals.summaries[0] || ""),
    " ",
    el("button", { class: "small", on: { click: () => showView("approvals") } }, "Review"),
  );
}

// ------------------------------------------------------------------ views
function showView(name) {
  for (const view of ["task", "review", "approvals", "models"]) $(`view-${view}`).hidden = view !== name;
  for (const button of document.querySelectorAll(".nav")) {
    button.classList.toggle("active", button.dataset.view === name);
  }
  if (name === "approvals") api("/approvals").then(renderApprovals).catch(() => {});
}

// ------------------------------------------------------------------ sessions
async function loadSessions() {
  const data = await api("/sessions");
  const list = $("sessions");
  list.replaceChildren(
    ...data.sessions.map((s) =>
      el(
        "li",
        {
          class: state.session === s.session_id ? "item selected" : "item",
          on: { click: () => selectSession(s.session_id) },
        },
        el("div", {}, s.title),
        el("div", { class: "muted small-text" }, `${s.session_id} - ${s.updated}`),
      ),
    ),
  );
  if (!data.sessions.length) list.append(el("li", { class: "muted" }, "No sessions yet."));
}

async function createSession() {
  const title = `Session ${new Date().toLocaleString()}`;
  const created = await api("/sessions", { method: "POST", body: { title } });
  await loadSessions();
  await selectSession(created.session_id);
}

async function selectSession(id) {
  state.session = id;
  stopStream();
  $("no-session").hidden = true;
  $("session-pane").hidden = false;
  $("task-detail").hidden = true;
  showView("task");
  await loadSessions();
  await loadTasks();
}

async function loadTasks() {
  if (!state.session) return;
  const data = await api(`/tasks?session_id=${encodeURIComponent(state.session)}`);
  const list = $("tasks");
  list.replaceChildren(
    ...data.tasks.map((t) =>
      el(
        "li",
        { class: state.task === t.task_id ? "item selected" : "item", on: { click: () => selectTask(t.task_id) } },
        el("div", {}, t.task),
        el("div", { class: "muted small-text" }, `${t.state}${t.outcome ? " - " + t.outcome : ""}`),
      ),
    ),
  );
  if (!data.tasks.length) list.append(el("li", { class: "muted" }, "No tasks in this session."));
}

// ------------------------------------------------------------------ models (UX-007)
async function loadModels() {
  const data = await api("/models?include_unusable=true");
  const select = $("task-model");
  select.replaceChildren(el("option", { value: "" }, "Routed automatically"));
  for (const m of data.models.filter((m) => m.usable)) {
    select.append(el("option", { value: m.name }, `${m.name} (${m.family} ${m.version})`));
  }
  $("models").replaceChildren(
    ...data.models.map((m) =>
      el(
        "tr",
        {},
        el("td", {}, m.name + (m.name === data.default ? " (default)" : "")),
        el("td", {}, m.family),
        el("td", {}, m.version),
        el("td", {}, m.context_window.toLocaleString()),
        el("td", {}, m.capabilities.join(", ")),
        el("td", { class: m.usable ? "ok" : "warn" }, m.status),
      ),
    ),
  );
  const resolved = data.routing.resolves_to || {};
  $("routing").replaceChildren(
    ...Object.entries(resolved).map(([kind, r]) =>
      el(
        "tr",
        {},
        el("td", {}, kind),
        el("td", {}, r.model || r.error || "none available"),
        el("td", {}, (r.fallbacks || []).join(", ")),
      ),
    ),
  );
}

// ------------------------------------------------------------------ tasks
async function runTask(event) {
  event.preventDefault();
  showError($("task-error"), null);
  const body = { task: $("task-text").value.trim(), task_kind: $("task-kind").value };
  if ($("task-model").value) body.model = $("task-model").value;
  const steps = parseInt($("task-steps").value, 10);
  if (steps > 0) body.max_steps = steps;
  try {
    const started = await api(`/sessions/${encodeURIComponent(state.session)}/tasks`, { method: "POST", body });
    $("task-text").value = "";
    await loadTasks();
    await selectTask(started.task_id);
  } catch (error) {
    showError($("task-error"), error);
  }
}

async function selectTask(id) {
  state.task = id;
  stopStream();
  $("task-detail").hidden = false;
  $("task-events").replaceChildren();
  await loadTasks();
  const detail = await renderTask();
  // Always stream: the server replays a task's history first and closes at once when it has
  // finished, so a task that ended before this point still shows its progress (UX-001).
  if (detail) startStream(id, detail.state === "queued" || detail.state === "running");
}

async function renderTask() {
  if (!state.task) return null;
  const detail = await api(`/tasks/${encodeURIComponent(state.task)}`);
  $("task-title").textContent = detail.task;
  const badge = $("task-state");
  badge.textContent = detail.state;
  badge.className = `state state-${detail.state}`;
  const active = detail.state === "queued" || detail.state === "running";
  $("btn-pause").disabled = !active;
  $("btn-cancel").disabled = !active;
  $("btn-resume").disabled = detail.state !== "paused";
  $("task-plan").textContent = detail.plan || "(no plan yet)";

  const report = detail.report;
  $("task-report").hidden = !report;
  if (report) {
    const outcome = $("report-outcome");
    outcome.textContent = `${report.outcome} - ${report.model} - ${(report.duration_ms / 1000).toFixed(1)}s`;
    outcome.className = `outcome ${report.succeeded ? "ok" : "warn"}`;
    $("report-verification").textContent = report.verification;
    $("report-warnings").replaceChildren(
      ...report.warnings.map((w) => el("li", { class: "warn" }, w)),
      ...report.unresolved.map((u) => el("li", {}, `Unresolved: ${u}`)),
    );
  }
  if (detail.error) $("report-warnings").append(el("li", { class: "warn" }, detail.error));
  if (!active) await renderChanges();
  else $("task-changes").hidden = true;
  return detail;
}

async function control(action) {
  try {
    const result = await api(`/tasks/${encodeURIComponent(state.task)}/${action}`, { method: "POST" });
    if (action === "resume" && result.task_id) {
      await loadTasks();
      await selectTask(result.task_id);
      return;
    }
  } catch (error) {
    alertInline(error);
  }
  await renderTask();
  await loadTasks();
}

function alertInline(error) {
  $("task-events").append(el("li", { class: "event failed" }, `${error.status || ""} ${error.message}`));
}

// ------------------------------------------------------------------ live events (UX-001..003)
function stopStream() {
  if (state.stream) state.stream.abort();
  state.stream = null;
}

async function startStream(taskId, refreshWhenDone = true) {
  stopStream();
  const controller = new AbortController();
  state.stream = controller;
  try {
    // EventSource cannot send an Authorization header, so the stream is read with fetch.
    const response = await fetch(`/tasks/${encodeURIComponent(taskId)}/events`, {
      headers: { Authorization: `Bearer ${state.token}` },
      signal: controller.signal,
    });
    if (!response.ok || !response.body) throw new ApiError(response.status, "event stream unavailable");
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let boundary;
      while ((boundary = buffer.indexOf("\n\n")) >= 0) {
        handleMessage(buffer.slice(0, boundary));
        buffer = buffer.slice(boundary + 2);
      }
    }
  } catch (error) {
    if (error.name !== "AbortError") alertInline(error);
  }
  if (state.stream === controller) {
    state.stream = null;
    // A finished task is already rendered; redrawing it would reset the change checkboxes.
    if (refreshWhenDone && state.task === taskId) {
      await renderTask();
      await loadTasks();
    }
  }
}

function handleMessage(raw) {
  let type = "message";
  const data = [];
  for (const line of raw.split("\n")) {
    if (line.startsWith("event: ")) type = line.slice(7);
    else if (line.startsWith("data: ")) data.push(line.slice(6));
  }
  let payload;
  try { payload = JSON.parse(data.join("\n")); } catch { return; }
  if (type === "state") return;
  const total = payload.total_steps ? `/${payload.total_steps}` : "";
  const step = payload.step_number ? `[${payload.step_number}${total}] ` : "";
  const tool = payload.tool ? ` (${payload.tool})` : "";
  $("task-events").append(
    el(
      "li",
      { class: `event ${payload.status || ""} type-${type}` },
      el("span", { class: "event-type" }, `${step}${type}${tool}`),
      " ",
      el("span", {}, payload.message || ""),
    ),
  );
  if ((type === "plan_created" || type === "plan_revised") && payload.data && payload.data.plan) {
    $("task-plan").textContent = payload.data.plan;
  }
  if (type === "approval_requested") refreshStatus();
}

// ------------------------------------------------------------------ changes (CC-005, UX-004)
async function renderChanges() {
  const data = await api(`/tasks/${encodeURIComponent(state.task)}/changes`);
  const container = $("changes");
  $("task-changes").hidden = data.files.length === 0;
  container.replaceChildren(...data.files.map(renderFile));
}

function renderFile(file) {
  const pending = file.decision === "pending";
  const header = el(
    "div",
    { class: "file-head" },
    el("strong", {}, file.path),
    el("span", { class: "muted" }, ` ${file.action}`),
    el("span", { class: `decision decision-${file.decision}` }, file.decision),
  );
  const box = el("div", { class: "file" }, header);
  if (!file.unchanged_since_task && pending) {
    box.append(el("p", { class: "warn" }, "This file has changed since the task finished, so it can only be accepted as it is."));
  }
  const ticks = [];
  if (file.hunks) {
    for (const hunk of file.hunks) {
      const tick = el("input", { type: "checkbox", checked: "", "aria-label": `Keep hunk ${hunk.index + 1}` });
      tick.disabled = !pending || !file.decidable;
      ticks.push({ index: hunk.index, tick });
      box.append(
        el(
          "div",
          { class: "hunk" },
          el("label", { class: "hunk-head" }, tick, ` Hunk ${hunk.index + 1} - line ${hunk.old_start}`),
          el(
            "pre",
            { class: "diff" },
            ...hunk.old_lines.map((l) => el("span", { class: "del" }, `-${l}\n`)),
            ...hunk.new_lines.map((l) => el("span", { class: "add" }, `+${l}\n`)),
          ),
        ),
      );
    }
  } else if (file.diff) {
    box.append(el("pre", { class: "diff" }, ...file.diff.split("\n").map(diffLine)));
  }
  if (pending) {
    const error = el("p", { class: "error", role: "alert" });
    const decide = async (accept) => {
      try {
        await api(`/tasks/${encodeURIComponent(state.task)}/changes/decide`, {
          method: "POST",
          body: { path: file.path, accept },
        });
        await renderChanges();
      } catch (e) {
        showError(error, e);
      }
    };
    const actions = el(
      "div",
      { class: "row" },
      el("button", { class: "small primary", on: { click: () => decide("all") } }, "Accept all"),
    );
    if (file.decidable) {
      actions.append(el("button", { class: "small danger", on: { click: () => decide("none") } }, "Reject"));
      if (file.hunks && file.hunks.length > 1) {
        actions.append(
          el(
            "button",
            { class: "small", on: { click: () => decide(ticks.filter((t) => t.tick.checked).map((t) => t.index)) } },
            "Keep ticked hunks",
          ),
        );
      }
    }
    box.append(actions, error);
  }
  return box;
}

function diffLine(line) {
  const cls = line.startsWith("+") && !line.startsWith("+++") ? "add"
    : line.startsWith("-") && !line.startsWith("---") ? "del"
    : line.startsWith("@@") ? "hunk-marker" : "";
  return el("span", { class: cls }, `${line}\n`);
}

// ------------------------------------------------------------------ approvals (API-014, UX-008)
function renderApprovals(data) {
  const list = $("approvals");
  list.replaceChildren(
    ...data.approvals.map((a) => {
      const note = el("input", { type: "text", placeholder: "Note (optional)", "aria-label": "Note" });
      const error = el("p", { class: "error", role: "alert" });
      const decide = async (approved) => {
        try {
          await api(`/approvals/${encodeURIComponent(a.id)}`, { method: "POST", body: { approved, note: note.value } });
          renderApprovals(await api("/approvals"));
          refreshStatus();
        } catch (e) {
          showError(error, e);
        }
      };
      return el(
        "li",
        { class: "approval" },
        el("div", { class: "categories" }, ...a.categories.map((c) => el("span", { class: "chip" }, c))),
        el("div", {}, el("strong", {}, a.tool || "action"), ": ", a.action),
        el("div", { class: "muted small-text" }, `requested by ${a.requested_by} at ${a.requested_at}`),
        el(
          "div",
          { class: "row" },
          note,
          el("button", { class: "small primary", on: { click: () => decide(true) } }, "Approve"),
          el("button", { class: "small danger", on: { click: () => decide(false) } }, "Reject"),
        ),
        error,
      );
    }),
  );
  if (!data.approvals.length) list.append(el("li", { class: "muted" }, "Nothing is waiting for a decision."));
}

// ------------------------------------------------------------------ review (CHAT-007, REV-001..007)
const SEVERITIES = ["critical", "high", "medium", "low", "info"];

async function runReview(event) {
  event.preventDefault();
  const error = $("review-error");
  showError(error, null);
  const checks = [...document.querySelectorAll("input[name=review-check]:checked")].map((c) => c.value);
  if (!checks.length) {
    error.textContent = "Choose at least one check.";
    return;
  }
  const body = { checks, staged: $("review-staged").checked };
  const diff = $("review-diff").value;
  if (diff.trim()) body.diff = diff;
  const base = $("review-base").value.trim();
  if (base) body.base = base;
  const path = $("review-path").value.trim();
  if (path) body.path = path;
  const focus = $("review-focus").value.trim();
  if (focus) body.focus = focus;
  const button = $("review-form").querySelector("button[type=submit]");
  button.disabled = true;
  button.textContent = "Reviewing...";
  try {
    renderReview(await api("/review", { method: "POST", body }));
  } catch (e) {
    showError(error, e);
  } finally {
    button.disabled = false;
    button.textContent = "Run review";
  }
}

function renderReview(report) {
  $("review-result").hidden = false;
  const total = report.findings.length;

  // An incomplete review is not a clean one: say so before anything else, and never show
  // "no findings" as if the change had passed.
  const status = $("review-status");
  const failed = Object.entries(report.checks_failed || {});
  if (!report.complete) {
    status.textContent = "incomplete";
    status.className = "state state-failed";
  } else {
    status.textContent = total ? `${total} finding${total === 1 ? "" : "s"}` : "no findings";
    status.className = `state ${total ? "state-paused" : "state-finished"}`;
  }
  const incomplete = $("review-incomplete");
  incomplete.hidden = report.complete && !report.truncated;
  incomplete.replaceChildren(
    el("strong", {}, report.complete ? "Diff truncated. " : "This review is incomplete. "),
    report.complete
      ? "Only part of the change was reviewed."
      : "Missing findings do not mean the change is clean.",
    failed.length ? el("ul", {}, ...failed.map(([check, why]) => el("li", {}, `${check}: ${why}`))) : null,
  );

  $("review-counts").replaceChildren(
    ...SEVERITIES.filter((s) => report.counts[s]).map((s) =>
      el("span", { class: `chip sev sev-${s}` }, `${report.counts[s]} ${s}`),
    ),
  );
  const summary = $("review-summary");
  summary.hidden = !report.summary;
  summary.textContent = report.summary || "";
  const files = report.files_reviewed.length;
  $("review-meta").textContent =
    `${files} file${files === 1 ? "" : "s"} reviewed - checks: ${report.checks_run.join(", ") || "none"}` +
    ` - model: ${report.model || "none"}` +
    (report.model_selection ? ` (${report.model_selection})` : "");

  const container = $("review-findings");
  container.replaceChildren(
    ...Object.entries(report.by_file).map(([file, findings]) =>
      el(
        "div",
        { class: "file review-file" },
        el("div", { class: "file-head" }, el("strong", {}, file),
          el("span", { class: "muted small-text" }, `${findings.length} finding${findings.length === 1 ? "" : "s"}`)),
        ...findings.map(renderFinding),
      ),
    ),
  );
  if (!total) {
    container.append(el("p", { class: report.complete ? "ok" : "warn" },
      report.complete ? "No findings." : "No findings were produced, but the review did not finish."));
  }

  const dropped = $("review-dropped");
  dropped.hidden = !report.dropped.length;
  dropped.textContent = report.dropped.length
    ? `${report.dropped.length} proposed finding${report.dropped.length === 1 ? " was" : "s were"} discarded ` +
      `because its location was not in the change (REV-007): ` +
      [...new Set(report.dropped.map((d) => d.reason))].join("; ")
    : "";
}

function renderFinding(f) {
  const source = f.origin + (f.model ? ` - ${f.model}` : "");
  return el(
    "div",
    { class: `finding sev-border-${f.severity}` },
    el(
      "div",
      { class: "finding-head" },
      el("span", { class: `chip sev sev-${f.severity}` }, f.severity),
      el("code", { class: "location" }, f.location),
      el("strong", {}, f.title),
    ),
    el(
      "div",
      { class: "muted small-text" },
      `${f.category} - ${f.requirement} - ${source}`,
      f.confirmed_location ? null : el("span", { class: "warn" }, " - line re-anchored"),
    ),
    f.detail ? el("p", {}, f.detail) : null,
    f.code ? el("pre", { class: "diff" }, f.code) : null,
    f.suggestion ? el("p", { class: "suggestion" }, el("strong", {}, "Suggestion: "), f.suggestion) : null,
  );
}

// ------------------------------------------------------------------ wiring
document.addEventListener("DOMContentLoaded", () => {
  $("login-form").addEventListener("submit", (event) => {
    event.preventDefault();
    signIn($("token").value.trim());
    $("token").value = "";
  });
  $("logout").addEventListener("click", () => signOut(""));
  $("new-session").addEventListener("click", () => createSession().catch(alertInline));
  $("task-form").addEventListener("submit", runTask);
  $("review-form").addEventListener("submit", runReview);
  $("btn-pause").addEventListener("click", () => control("pause"));
  $("btn-resume").addEventListener("click", () => control("resume"));
  $("btn-cancel").addEventListener("click", () => control("cancel"));
  $("approvals-badge").addEventListener("click", () => showView("approvals"));
  for (const button of document.querySelectorAll(".nav")) {
    button.addEventListener("click", () => showView(button.dataset.view));
  }
  const saved = readToken();
  if (saved) signIn(saved);
  else signOut("");
});
