"""LANG-003: TypeScript over a real project, with a real Node toolchain.

A small TypeScript package - an interface, a class, a function, a node:test suite and a build
script - with one real bug. Indexing, retrieval, test discovery, test-output parsing and the
agent loop are all exercised against it; only the model is scripted. Node >= 23 runs
TypeScript directly (type stripping), so nothing is installed from a registry.
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


def _node_major() -> int:
    node = shutil.which("node")
    if node is None:
        return 0
    out = subprocess.run([node, "--version"], capture_output=True, text=True, check=False)
    try:
        return int(out.stdout.strip().lstrip("v").split(".")[0])
    except ValueError:
        return 0


requires_node = pytest.mark.skipif(
    _node_major() < 23 or shutil.which("npm") is None,
    reason="needs Node >= 23 (runs TypeScript without a compiler) and npm on PATH",
)

PACKAGE = {
    "name": "cart",
    "version": "1.0.0",
    "type": "module",
    "scripts": {"test": "node --test test/*.test.ts", "build": "node scripts/build.mjs"},
}

BUILD = """// Loads every module so a syntax or import error fails the build.
import { readdirSync } from "node:fs";
for (const f of readdirSync(new URL("../src/", import.meta.url))) {
  await import(new URL(`../src/${f}`, import.meta.url));
}
console.log("build ok");
"""

CART = """export interface LineItem {
  sku: string;
  unitPrice: number;
  quantity: number;
}

export class Cart {
  private items: LineItem[] = [];

  add(item: LineItem): void {
    this.items.push(item);
  }

  subtotal(): number {
    return this.items.reduce((sum, i) => sum + i.unitPrice, 0);
  }
}

export function applyDiscount(amount: number, percent: number): number {
  return Math.round(amount * (1 - percent / 100) * 100) / 100;
}
"""

TESTS = """import { test } from "node:test";
import assert from "node:assert/strict";
import { Cart, applyDiscount } from "../src/cart.ts";

test("subtotal multiplies price by quantity", () => {
  const cart = new Cart();
  cart.add({ sku: "A", unitPrice: 2.5, quantity: 4 });
  assert.equal(cart.subtotal(), 10);
});

test("discount rounds to cents", () => {
  assert.equal(applyDiscount(10, 15), 8.5);
});

test("empty cart is zero", () => {
  assert.equal(new Cart().subtotal(), 0);
});
"""


@pytest.fixture
def project(tmp_path: Path) -> Path:
    (tmp_path / "src").mkdir()
    (tmp_path / "test").mkdir()
    (tmp_path / "scripts").mkdir()
    (tmp_path / "package.json").write_text(json.dumps(PACKAGE, indent=2), encoding="utf-8")
    (tmp_path / "scripts" / "build.mjs").write_text(BUILD, encoding="utf-8")
    (tmp_path / "src" / "cart.ts").write_text(CART, encoding="utf-8")
    (tmp_path / "test" / "cart.test.ts").write_text(TESTS, encoding="utf-8")
    for args in (
        ["git", "init", "-q", "-b", "work"],
        ["git", "config", "user.email", "agent@example.com"],
        ["git", "config", "user.name", "Agent"],
        ["git", "config", "core.autocrlf", "false"],
        ["git", "add", "-A"],
        ["git", "commit", "-qm", "initial"],
    ):
        subprocess.run(args, cwd=tmp_path, check=True)
    return tmp_path


def _context(root: Path) -> ToolContext:
    policy = Policy()
    ws = WorkspaceGuard(root, policy.autonomy.allowed_directories)
    git = GitGuard(ws.root, policy.git)
    return ToolContext(
        workspace=ws,
        policy=policy,
        audit=AuditLog(InMemoryAuditSink(), actor="ts-integration"),
        git=git if git.is_repository() else None,
        approver=AllowAllApprover(),
    )


def test_typescript_symbols_are_indexed_and_retrieved(project: Path) -> None:
    index = RepositoryIndex(WorkspaceGuard(project))
    try:
        index.index_repository()
        hits = index.search("cart subtotal of line items", 5)
        assert hits and hits[0].path == "src/cart.ts"
        # Symbol retrieval: the class and the interface are chunks of their own.
        assert index.search_symbol("Cart")[0].kind == "class"
        assert index.search_symbol("LineItem")[0].path == "src/cart.ts"
        # Dependency-aware: the test imports the module it tests.
        assert "src/cart.ts" in index.dependencies_of("test/cart.test.ts")
    finally:
        index.close()


@requires_node
def test_npm_scripts_are_discovered_as_unit_and_build(project: Path) -> None:
    found = {c.kind: c.command for c in discover(project)}
    assert found["unit"] == "npm run test"
    assert found["build"] == "npm run build"


@requires_node
def test_a_real_node_test_failure_is_parsed_to_its_location(project: Path) -> None:
    npm = shutil.which("npm")
    assert npm is not None
    run = subprocess.run(
        [npm, "run", "test"],
        cwd=project,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
        shell=False,
    )
    outcome = parse_output("unit", "npm run test", run.stdout, run.stderr, run.returncode)
    assert (outcome.passed, outcome.failed) == (2, 1)
    (failure,) = outcome.failures
    assert failure.test == "subtotal multiplies price by quantity"
    assert failure.file is not None and failure.file.endswith("test/cart.test.ts")
    assert failure.line == 5


@requires_node
def test_agent_fixes_typescript_and_proves_it_with_real_tests_and_build(project: Path) -> None:
    ctx = _context(project)
    adapter = ScriptedAdapter(
        [
            json.dumps(
                {
                    "summary": "see the failure",
                    "steps": [
                        {
                            "intent": "run the suite",
                            "tool": "test.run",
                            "arguments": {"command": "npm run test", "kind": "unit"},
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
                            "arguments": {
                                "path": "src/cart.ts",
                                "old_text": "sum + i.unitPrice,",
                                "new_text": "sum + i.unitPrice * i.quantity,",
                            },
                        },
                        {
                            "intent": "rerun the suite",
                            "tool": "test.run",
                            "arguments": {"command": "npm run test", "kind": "unit"},
                        },
                        {
                            "intent": "build",
                            "tool": "test.run",
                            "arguments": {"command": "npm run build", "kind": "build"},
                        },
                    ],
                }
            ),
        ]
    )
    report = AgentLoop(adapter, default_registry()).run("make the cart tests pass", ctx)

    assert "i.unitPrice * i.quantity" in (project / "src" / "cart.ts").read_text("utf-8")
    npm = shutil.which("npm")
    assert npm is not None
    independent = subprocess.run(
        [npm, "run", "test"], cwd=project, capture_output=True, text=True, check=False
    )
    assert independent.returncode == 0, independent.stdout
    assert report.outcome() == "SUCCESS", report.render()
    assert "unit" in report.ledger.disclosure() and "build" in report.ledger.disclosure()
    assert [c.path for c in report.changes] == ["src/cart.ts"]


def test_relative_imports_resolve_so_dependents_are_found(project: Path) -> None:
    """RAG-005 on TypeScript: raw '../src/cart.ts' used to match nothing."""
    index = RepositoryIndex(WorkspaceGuard(project))
    try:
        index.index_repository()
        assert "node:test" in index.dependencies_of("test/cart.test.ts")
        assert index.dependents_of("src/cart.ts") == ["test/cart.test.ts"]
    finally:
        index.close()
