import assert from "node:assert/strict";
import { test } from "node:test";

import { AicaClient, AicaError, FetchLike } from "../../src/client";

interface Seen {
  url: string;
  init: RequestInit | undefined;
}

function fake(responses: Array<[number, unknown]>): { fetch: FetchLike; seen: Seen[] } {
  const seen: Seen[] = [];
  const fetchImpl: FetchLike = async (url, init) => {
    seen.push({ url, init });
    const [status, body] = responses.shift() ?? [500, { detail: "no scripted response" }];
    return new Response(typeof body === "string" ? body : JSON.stringify(body), { status });
  };
  return { fetch: fetchImpl, seen };
}

test("every call carries the bearer token and a JSON body", async () => {
  const { fetch, seen } = fake([[200, { session_id: "s1", answer: "a", model: "m", sources: [], model_selection: "" }]]);
  const client = new AicaClient("http://127.0.0.1:8000/", "tok", fetch);
  const result = await client.chat("why?", { context: "sel", sessionId: "s0" });
  assert.equal(result.session_id, "s1");
  assert.equal(seen[0].url, "http://127.0.0.1:8000/chat"); // trailing slash handled
  const headers = seen[0].init?.headers as Record<string, string>;
  assert.equal(headers["Authorization"], "Bearer tok");
  assert.deepEqual(JSON.parse(String(seen[0].init?.body)), { question: "why?", context: "sel", session_id: "s0" });
});

test("a 409 is an approval wait, with the server's detail", async () => {
  const { fetch } = fake([[409, { detail: "approval required [approval request(s) ab12 queued]" }]]);
  const err = await new AicaClient("http://x", "t", fetch).review().catch((e: unknown) => e);
  assert.ok(err instanceof AicaError);
  assert.equal(err.needsApproval, true);
  assert.match(err.message, /ab12 queued/);
});

test("an unreachable server says how to fix it", async () => {
  const failing: FetchLike = async () => {
    throw new TypeError("fetch failed");
  };
  const err = await new AicaClient("http://127.0.0.1:9", "t", failing).health().catch((e: unknown) => e);
  assert.ok(err instanceof AicaError);
  assert.match(err.message, /aica serve/);
});

test("starting a task creates a session first, then the task in it", async () => {
  const { fetch, seen } = fake([
    [201, { session_id: "s9" }],
    [202, { task_id: "t1", session_id: "s9", task: "fix", state: "running", outcome: null, succeeded: null }],
  ]);
  const summary = await new AicaClient("http://x", "t", fetch).startTask("fix it", "groq-qwen3.8-27b");
  assert.equal(summary.task_id, "t1");
  assert.equal(seen[1].url, "http://x/sessions/s9/tasks");
  assert.deepEqual(JSON.parse(String(seen[1].init?.body)), { task: "fix it", model: "groq-qwen3.8-27b" });
});

test("hunk-level decisions are sent as the index list the API expects", async () => {
  const { fetch, seen } = fake([[200, { decision: "partial" }]]);
  await new AicaClient("http://x", "t", fetch).decide("t1", "src/a.py", [0, 2], "n");
  assert.deepEqual(JSON.parse(String(seen[0].init?.body)), { path: "src/a.py", accept: [0, 2], note: "n" });
});

test("the event stream yields agent events and resolves with the final state", async () => {
  const wire =
    'event: step_started\ndata: {"type":"step_started","message":"read","step_number":1,"total_steps":2,"tool":"fs.read","status":"running","data":{}}\n\n' +
    'event: state\ndata: {"task_id":"t1","state":"succeeded","outcome":"SUCCESS"}\n\n';
  const fetchImpl: FetchLike = async () => new Response(wire, { status: 200 });
  const events: string[] = [];
  const final = await new AicaClient("http://x", "t", fetchImpl).streamEvents("t1", (e) => events.push(e.message));
  assert.deepEqual(events, ["read"]);
  assert.equal(final?.outcome, "SUCCESS");
});
