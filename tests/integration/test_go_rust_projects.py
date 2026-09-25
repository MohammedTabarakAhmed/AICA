"""LANG-004 Go and LANG-005 Rust over real projects, with the real toolchains.

Each project has one real bug in one package/module and a second, passing one, so the
counts must add up across packages (Go) and test binaries (Rust). Indexing, discovery,
output parsing and the agent loop run for real; only the model is scripted. Neither
project has dependencies, so nothing is downloaded.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from aica.agent.loop import AgentLoop
from aica.approvals import AllowAllApprover
from aica.audit import AuditLog, InMemoryAuditSink
from aica.models.fake import ScriptedAdapter
from aica.policy import Policy
from aica.rag.index import RepositoryIndex
from aica.testing.discovery import discover
from aica.testing.results import parse_output
from aica.tools import ToolContext, default_registry
from aica.workspace import GitGuard, WorkspaceGuard

pytestmark = pytest.mark.integration

GO = shutil.which("go")
CARGO = shutil.which("cargo")
requires_go = pytest.mark.skipif(GO is None, reason="needs the Go toolchain on PATH")
requires_cargo = pytest.mark.skipif(CARGO is None, reason="needs the Rust toolchain on PATH")

GO_FILES = {
    "go.mod": "module example.com/shop\n\ngo 1.22\n",
    "cart/cart.go": """package cart

// LineItem is one product in a cart.
type LineItem struct {
\tSKU       string
\tUnitPrice float64
\tQuantity  int
}

// Cart holds line items.
type Cart struct {
\titems []LineItem
}

// Add puts an item in the cart.
func (c *Cart) Add(item LineItem) {
\tc.items = append(c.items, item)
}

// Subtotal is the sum of every line.
func (c *Cart) Subtotal() float64 {
\ttotal := 0.0
\tfor _, item := range c.items {
\t\ttotal += item.UnitPrice
\t}
\treturn total
}
""",
    "cart/cart_test.go": """package cart

import "testing"

func TestSubtotalMultipliesPriceByQuantity(t *testing.T) {
\tc := &Cart{}
\tc.Add(LineItem{SKU: "A", UnitPrice: 2.5, Quantity: 4})
\tif got := c.Subtotal(); got != 10 {
\t\tt.Errorf("Subtotal() = %v, want 10", got)
\t}
}

func TestEmptyCartIsZero(t *testing.T) {
\tif got := (&Cart{}).Subtotal(); got != 0 {
\t\tt.Errorf("Subtotal() = %v, want 0", got)
\t}
}
""",
    "money/money.go": """package money

import "math"

// Round rounds to cents.
func Round(v float64) float64 { return math.Round(v*100) / 100 }
""",
    "money/money_test.go": """package money

import "testing"

func TestRound(t *testing.T) {
\tif Round(1.234) != 1.23 {
\t\tt.Fatal("bad rounding")
\t}
}
""",
}

RUST_FILES = {
    "Cargo.toml": '[package]\nname = "cart"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\n',
    "src/lib.rs": """//! A shopping cart.

pub mod money;

/// One product in a cart.
pub struct LineItem {
    pub sku: String,
    pub unit_price: f64,
    pub quantity: u32,
}

/// Holds line items.
#[derive(Default)]
pub struct Cart {
    items: Vec<LineItem>,
}

impl Cart {
    pub fn add(&mut self, item: LineItem) {
        self.items.push(item);
    }

    pub fn subtotal(&self) -> f64 {
        self.items.iter().map(|i| i.unit_price).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subtotal_multiplies_price_by_quantity() {
        let mut cart = Cart::default();
        cart.add(LineItem { sku: "A".into(), unit_price: 2.5, quantity: 4 });
        assert_eq!(cart.subtotal(), 10.0);
    }

    #[test]
    fn empty_cart_is_zero() {
        assert_eq!(Cart::default().subtotal(), 0.0);
    }
}
""",
    "src/money.rs": """/// Rounds to cents.
pub fn round(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

#[cfg(test)]
mod tests {
    #[test]
    fn rounds() {
        assert_eq!(super::round(1.234), 1.23);
    }
}
""",
    # A second test binary: its counts must be added to the library's.
    "tests/public_api.rs": """use cart::money::round;

#[test]
fn rounds_through_the_public_api() {
    assert_eq!(round(2.005), 2.01);
}

#[test]
fn rounds_down() {
    assert_eq!(round(2.004), 2.0);
}
""",
}


def _project(root: Path, files: dict[str, str], ignore: str) -> Path:
    for rel, content in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8", newline="\n")
    (root / ".gitignore").write_text(ignore, encoding="utf-8")
    for args in (
        ["git", "init", "-q", "-b", "work"],
        ["git", "config", "user.email", "agent@example.com"],
        ["git", "config", "user.name", "Agent"],
        ["git", "config", "core.autocrlf", "false"],
        ["git", "add", "-A"],
        ["git", "commit", "-qm", "initial"],
    ):
        subprocess.run(args, cwd=root, check=True)
    return root


@pytest.fixture
def go_project(tmp_path: Path) -> Path:
    return _project(tmp_path, GO_FILES, "")


@pytest.fixture
def rust_project(tmp_path: Path) -> Path:
    return _project(tmp_path, RUST_FILES, "target/\n")


def _context(root: Path) -> ToolContext:
    policy = Policy()
    ws = WorkspaceGuard(root, policy.autonomy.allowed_directories)
    git = GitGuard(ws.root, policy.git)
    return ToolContext(
        workspace=ws,
        policy=policy,
        audit=AuditLog(InMemoryAuditSink(), actor="lang-integration"),
        git=git if git.is_repository() else None,
        approver=AllowAllApprover(),
    )


def _fix_plan(path: str, old: str, new: str) -> ScriptedAdapter:
    return ScriptedAdapter(
        [
            json.dumps(
                {
                    "summary": "see the failure",
                    "steps": [
                        {
                            "intent": "run the suite",
                            "tool": "test.run",
                            "arguments": {"kind": "unit"},
                        }
                    ],
                    "verification": ["unit", "build"],
                }
            ),
            json.dumps(
                {
                    "action": "replace",
                    "reason": "subtotal ignores quantity",
                    "steps": [
                        {
                            "intent": "multiply by quantity",
                            "tool": "fs.edit",
                            "arguments": {"path": path, "old_text": old, "new_text": new},
                        },
                        {"intent": "rerun", "tool": "test.run", "arguments": {"kind": "unit"}},
                        {"intent": "build", "tool": "test.run", "arguments": {"kind": "build"}},
                    ],
                }
            ),
        ]
    )


# ------------------------------------------------------------------ Go (LANG-004)
def test_go_symbols_are_indexed(go_project: Path) -> None:
    index = RepositoryIndex(WorkspaceGuard(go_project))
    try:
        index.index_repository()
        assert index.search_symbol("Subtotal")[0].path == "cart/cart.go"
        assert index.search_symbol("Round")[0].path == "money/money.go"
    finally:
        index.close()


@requires_go
def test_real_go_output_counts_tests_not_packages(go_project: Path) -> None:
    found = {c.kind: c.command for c in discover(go_project)}
    assert found["unit"] == "go test -v ./..." and found["build"] == "go build ./..."
    assert GO is not None
    run = subprocess.run(
        [GO, "test", "-v", "./..."], cwd=go_project, capture_output=True, text=True, check=False
    )
    outcome = parse_output("unit", "go test -v ./...", run.stdout, run.stderr, run.returncode)
    assert (outcome.passed, outcome.failed) == (2, 1), run.stdout
    (failure,) = outcome.failures
    assert failure.test == "TestSubtotalMultipliesPriceByQuantity"
    assert (failure.file, failure.line) == ("cart_test.go", 9)


@requires_go
def test_agent_fixes_go_and_proves_it(go_project: Path) -> None:
    adapter = _fix_plan(
        "cart/cart.go",
        "total += item.UnitPrice",
        "total += item.UnitPrice * float64(item.Quantity)",
    )
    report = AgentLoop(adapter, default_registry()).run(
        "make the go tests pass", _context(go_project)
    )
    assert GO is not None
    independent = subprocess.run(
        [GO, "test", "./..."], cwd=go_project, capture_output=True, text=True, check=False
    )
    assert independent.returncode == 0, independent.stdout
    assert report.outcome() == "SUCCESS", report.render()


# ------------------------------------------------------------------ Rust (LANG-005)
def test_rust_symbols_are_indexed(rust_project: Path) -> None:
    index = RepositoryIndex(WorkspaceGuard(rust_project))
    try:
        index.index_repository()
        assert index.search_symbol("Cart")[0].path == "src/lib.rs"
        assert index.search_symbol("round")[0].path == "src/money.rs"
    finally:
        index.close()


@requires_cargo
def test_real_cargo_output_sums_every_test_binary(rust_project: Path) -> None:
    found = {c.kind: c.command for c in discover(rust_project)}
    assert found["unit"] == "cargo test --no-fail-fast" and found["build"] == "cargo build"
    assert CARGO is not None
    run = subprocess.run(
        [CARGO, "test", "--no-fail-fast"],
        cwd=rust_project,
        capture_output=True,
        text=True,
        check=False,
        timeout=600,
    )
    outcome = parse_output(
        "unit", "cargo test --no-fail-fast", run.stdout, run.stderr, run.returncode
    )
    # lib: 2 passed 1 failed; tests/public_api.rs: 2 passed; doc-tests: 0.
    assert (outcome.passed, outcome.failed) == (4, 1), run.stdout + run.stderr
    (failure,) = outcome.failures
    assert failure.test == "tests::subtotal_multiplies_price_by_quantity"
    assert failure.file == "src/lib.rs" and failure.line == 36


@requires_cargo
def test_agent_fixes_rust_and_proves_it(rust_project: Path) -> None:
    adapter = _fix_plan(
        "src/lib.rs",
        ".map(|i| i.unit_price).sum()",
        ".map(|i| i.unit_price * f64::from(i.quantity)).sum()",
    )
    report = AgentLoop(adapter, default_registry()).run(
        "make the rust tests pass", _context(rust_project)
    )
    assert CARGO is not None
    independent = subprocess.run(
        [CARGO, "test"], cwd=rust_project, capture_output=True, text=True, check=False, timeout=600
    )
    assert independent.returncode == 0, independent.stdout + independent.stderr
    assert report.outcome() == "SUCCESS", report.render()
