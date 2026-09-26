import assert from "node:assert/strict";
import { test } from "node:test";

import type { Finding, ReviewReport } from "../../src/client";
import { describeReview, toDiagnostics } from "../../src/findings";

function finding(overrides: Partial<Finding>): Finding {
  return {
    file: "src/db.py",
    line: 12,
    end_line: 13,
    severity: "high",
    category: "security",
    title: "SQL injection",
    detail: "query built with f-string",
    suggestion: "use parameters",
    origin: "static",
    ...overrides,
  };
}

function report(findings: Finding[], overrides: Partial<ReviewReport> = {}): ReviewReport {
  return { complete: true, truncated: false, model: "m", summary: "", checks_failed: {}, findings, ...overrides };
}

test("findings become zero-based diagnostics with severity mapped to editor levels", () => {
  const specs = toDiagnostics(
    report([finding({}), finding({ severity: "medium", line: 1, end_line: null }), finding({ severity: "info" })]),
  );
  assert.deepEqual(
    specs.map((s) => [s.line, s.endLine, s.level]),
    [
      [11, 12, "error"],
      [0, 0, "warning"],
      [11, 12, "hint"],
    ],
  );
  assert.match(specs[0].message, /Suggestion: use parameters/);
  assert.equal(specs[0].code, "high/security");
});

test("a finding without a line has no place in the editor and is skipped", () => {
  assert.equal(toDiagnostics(report([finding({ line: null })])).length, 0);
});

test("an incomplete review never reads as clean (TEST-009)", () => {
  const text = describeReview(report([], { complete: false, model: null, checks_failed: { correctness: "no model" } }));
  assert.match(text, /^INCOMPLETE review/);
  assert.match(text, /correctness did not run/);
  assert.match(text, /does not mean the change is clean/);
  assert.match(describeReview(report([], { truncated: true })), /truncated/);
});
