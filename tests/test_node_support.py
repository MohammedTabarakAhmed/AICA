"""node:test output parsing and JS/TS import resolution (LANG-003, TEST-005, RAG-005)."""

from __future__ import annotations

from aica.rag.index import _resolve_import
from aica.testing.results import parse_output

SPEC = """\u2139 tests 3
\u2139 suites 0
\u2139 pass 2
\u2139 fail 1
\u2139 cancelled 0
\u2139 skipped 0
\u2139 todo 0

\u2716 failing tests:

test at test\\cart.test.ts:5:1
\u2716 subtotal multiplies price by quantity (1.7142ms)
  AssertionError [ERR_ASSERTION]: Expected values to be strictly equal:
"""

TAP = r"""TAP version 13
# Subtest: subtotal multiplies price by quantity
not ok 1 - subtotal multiplies price by quantity
  ---
  duration_ms: 1.2
  type: 'test'
  location: 'C:\\repo\\test\\cart.test.ts:5:1'
  failureType: 'testCodeFailure'
  ...
ok 2 - discount rounds to cents
# tests 2
# pass 1
# fail 1
# skipped 1
"""


def test_spec_reporter_counts_and_failure_location() -> None:
    outcome = parse_output("unit", "npm test", SPEC, "", 1)
    assert (outcome.passed, outcome.failed, outcome.skipped) == (2, 1, 0)
    (failure,) = outcome.failures
    assert (failure.file, failure.line) == ("test/cart.test.ts", 5)
    assert failure.message.startswith("AssertionError")


def test_tap_reporter_counts_and_failure_location() -> None:
    outcome = parse_output("unit", "npm test", TAP, "", 1)
    assert (outcome.passed, outcome.failed, outcome.skipped) == (1, 1, 1)
    (failure,) = outcome.failures
    assert failure.file == "C:/repo/test/cart.test.ts" and failure.line == 5


def test_a_zero_exit_with_node_failures_is_still_failed() -> None:
    assert not parse_output("unit", "npm test", SPEC, "", 0).ok


def test_relative_imports_resolve_against_the_importer() -> None:
    assert _resolve_import("test/cart.test.ts", "../src/cart.ts") == "src/cart.ts"
    assert _resolve_import("src/a/b.ts", "./c") == "src/a/c"
    assert _resolve_import("src/x.ts", "node:test") == "node:test"
    assert _resolve_import("src/x.ts", "react") == "react"
    # Pointing outside the repository is kept as written, never turned into a path.
    assert _resolve_import("a.ts", "../../outside") == "../../outside"
