import assert from "node:assert/strict";
import { test } from "node:test";

import { SseParser } from "../../src/sse";

test("events split across arbitrary chunks are reassembled", () => {
  const parser = new SseParser();
  const wire = 'event: step_started\ndata: {"a":1}\n\nevent: state\ndata: {"b":2}\n\n';
  const events = [];
  for (const ch of wire) {
    events.push(...parser.push(ch)); // one character at a time: the worst case
  }
  assert.deepEqual(events, [
    { event: "step_started", data: '{"a":1}' },
    { event: "state", data: '{"b":2}' },
  ]);
});

test("CRLF line endings, comments and multi-line data are handled", () => {
  const parser = new SseParser();
  const events = parser.push(": keep-alive\r\n\r\nevent: x\r\ndata: line1\r\ndata: line2\r\n\r\n");
  assert.deepEqual(events, [{ event: "x", data: "line1\nline2" }]);
});

test("an incomplete event is held until its terminating blank line", () => {
  const parser = new SseParser();
  assert.deepEqual(parser.push("event: x\ndata: 1\n"), []);
  assert.deepEqual(parser.push("\n"), [{ event: "x", data: "1" }]);
});

test("an event without a name is a message", () => {
  assert.deepEqual(new SseParser().push("data: hi\n\n"), [{ event: "message", data: "hi" }]);
});
