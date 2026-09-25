"""Surefire, `go test -v` and cargo output parsing, from real captured output (LANG-002/4/5)."""

from __future__ import annotations

from aica.testing.results import parse_output

SUREFIRE = r"""[INFO] Running com.example.cart.CartTest
[ERROR] Tests run: 2, Failures: 1, Errors: 0, Skipped: 0, Time elapsed: 0.095 s <<< FAILURE! -- in com.example.cart.CartTest
[INFO] Running com.example.cart.LineItemTest
[INFO] Tests run: 3, Failures: 0, Errors: 0, Skipped: 0, Time elapsed: 0.004 s -- in com.example.cart.LineItemTest
[INFO] Results:
[ERROR] Failures:
[ERROR]   CartTest.subtotalMultipliesPriceByQuantity:12 expected: <10.0> but was: <2.5>
[ERROR] Tests run: 5, Failures: 1, Errors: 0, Skipped: 0
"""

GO_VERBOSE = """=== RUN   TestSubtotalMultipliesPriceByQuantity
    cart_test.go:9: Subtotal() = 2.5, want 10
--- FAIL: TestSubtotalMultipliesPriceByQuantity (0.00s)
=== RUN   TestEmptyCartIsZero
--- PASS: TestEmptyCartIsZero (0.00s)
FAIL
FAIL\texample.com/shop/cart\t0.742s
=== RUN   TestRound
--- PASS: TestRound (0.00s)
=== RUN   TestSkipped
--- SKIP: TestSkipped (0.00s)
PASS
ok  \texample.com/shop/money\t0.730s
FAIL
"""

CARGO = r"""     Running unittests src\lib.rs (target\debug\deps\cart-792d1eebface3d93.exe)
running 3 tests
test tests::empty_cart_is_zero ... ok
test tests::subtotal_multiplies_price_by_quantity ... FAILED

failures:

---- tests::subtotal_multiplies_price_by_quantity stdout ----

thread 'tests::subtotal_multiplies_price_by_quantity' (12020) panicked at src\lib.rs:36:9:
assertion `left == right` failed
  left: 2.5
 right: 10.0

test result: FAILED. 2 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests\public_api.rs (target\debug\deps\public_api-1.exe)
test result: ok. 2 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s
"""


def test_surefire_uses_the_summary_not_the_first_class() -> None:
    outcome = parse_output("unit", "mvn -B test", SUREFIRE, "", 1)
    assert (outcome.passed, outcome.failed, outcome.skipped) == (4, 1, 0)
    (failure,) = outcome.failures
    assert failure.test == "CartTest.subtotalMultipliesPriceByQuantity"
    assert (failure.file, failure.line) == ("CartTest.java", 12)
    assert failure.message == "expected: <10.0> but was: <2.5>"


def test_go_counts_tests_and_locates_the_failure() -> None:
    outcome = parse_output("unit", "go test -v ./...", GO_VERBOSE, "", 1)
    assert (outcome.passed, outcome.failed, outcome.skipped) == (2, 1, 1)
    (failure,) = outcome.failures
    assert (failure.test, failure.file, failure.line) == (
        "TestSubtotalMultipliesPriceByQuantity",
        "cart_test.go",
        9,
    )


def test_go_without_verbose_output_still_reports_the_failure() -> None:
    plain = "--- FAIL: TestX (0.00s)\nFAIL\nFAIL\texample.com/x\t0.1s\n"
    outcome = parse_output("unit", "go test ./...", plain, "", 1)
    assert outcome.failed == 1 and not outcome.ok


def test_cargo_sums_every_test_binary_and_locates_the_panic() -> None:
    outcome = parse_output("unit", "cargo test --no-fail-fast", CARGO, "", 101)
    assert (outcome.passed, outcome.failed, outcome.skipped) == (4, 1, 1)
    (failure,) = outcome.failures
    assert failure.test == "tests::subtotal_multiplies_price_by_quantity"
    assert (failure.file, failure.line) == ("src/lib.rs", 36)
    assert failure.message == "assertion `left == right` failed"
