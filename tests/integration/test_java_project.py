"""LANG-002: Java over a real Maven project, with a real JDK and Maven.

A small package - a class, a record, two JUnit 5 test classes - with one real bug. Indexing,
retrieval, test discovery, Surefire output parsing and the agent loop are exercised against
it; only the model is scripted. The first run downloads JUnit into the local Maven
repository, so it needs Maven Central the first time.
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

MVN = shutil.which("mvn")
requires_maven = pytest.mark.skipif(
    MVN is None or shutil.which("java") is None, reason="needs a JDK and Maven on PATH"
)

POM = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>cart</artifactId>
  <version>1.0.0</version>
  <properties>
    <maven.compiler.release>21</maven.compiler.release>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.junit.jupiter</groupId>
      <artifactId>junit-jupiter</artifactId>
      <version>5.11.4</version>
      <scope>test</scope>
    </dependency>
  </dependencies>
  <build>
    <plugins>
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-surefire-plugin</artifactId>
        <version>3.5.2</version>
      </plugin>
    </plugins>
  </build>
</project>
"""

CART = """package com.example.cart;

import java.util.ArrayList;
import java.util.List;

public class Cart {
    private final List<LineItem> items = new ArrayList<>();

    public void add(LineItem item) {
        items.add(item);
    }

    public double subtotal() {
        double total = 0;
        for (LineItem item : items) {
            total += item.unitPrice();
        }
        return total;
    }
}
"""

LINE_ITEM = """package com.example.cart;

public record LineItem(String sku, double unitPrice, int quantity) {
}
"""

CART_TEST = """package com.example.cart;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class CartTest {
    @Test
    void subtotalMultipliesPriceByQuantity() {
        Cart cart = new Cart();
        cart.add(new LineItem("A", 2.5, 4));
        assertEquals(10.0, cart.subtotal(), 1e-9);
    }

    @Test
    void emptyCartIsZero() {
        assertEquals(0.0, new Cart().subtotal(), 1e-9);
    }
}
"""

LINE_ITEM_TEST = """package com.example.cart;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class LineItemTest {
    @Test
    void keepsItsSku() {
        assertEquals("A", new LineItem("A", 1.0, 1).sku());
    }

    @Test
    void keepsItsQuantity() {
        assertEquals(3, new LineItem("A", 1.0, 3).quantity());
    }

    @Test
    void keepsItsPrice() {
        assertEquals(1.0, new LineItem("A", 1.0, 3).unitPrice(), 1e-9);
    }
}
"""

MAIN = Path("src/main/java/com/example/cart")
TEST = Path("src/test/java/com/example/cart")


@pytest.fixture
def project(tmp_path: Path) -> Path:
    (tmp_path / MAIN).mkdir(parents=True)
    (tmp_path / TEST).mkdir(parents=True)
    (tmp_path / "pom.xml").write_text(POM, encoding="utf-8")
    (tmp_path / MAIN / "Cart.java").write_text(CART, encoding="utf-8")
    (tmp_path / MAIN / "LineItem.java").write_text(LINE_ITEM, encoding="utf-8")
    (tmp_path / TEST / "CartTest.java").write_text(CART_TEST, encoding="utf-8")
    (tmp_path / TEST / "LineItemTest.java").write_text(LINE_ITEM_TEST, encoding="utf-8")
    (tmp_path / ".gitignore").write_text("target/\n", encoding="utf-8")
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


def test_java_types_are_indexed_and_retrieved(project: Path) -> None:
    index = RepositoryIndex(WorkspaceGuard(project))
    try:
        index.index_repository()
        cart = index.search_symbol("Cart")
        assert cart and cart[0].path == (MAIN / "Cart.java").as_posix()
        assert index.search_symbol("LineItem")[0].path == (MAIN / "LineItem.java").as_posix()
        hits = index.search("subtotal of the cart's line items", 5)
        assert hits and hits[0].path.endswith("Cart.java")
    finally:
        index.close()


def test_maven_is_discovered_for_tests_and_build(project: Path) -> None:
    found = {c.kind: c.command for c in discover(project)}
    assert found["unit"] == "mvn -B test"
    assert found["build"] == "mvn -B package -DskipTests"


@requires_maven
def test_a_real_surefire_failure_is_counted_and_located(project: Path) -> None:
    assert MVN is not None
    run = subprocess.run(
        [MVN, "-B", "test"], cwd=project, capture_output=True, text=True, check=False, timeout=600
    )
    outcome = parse_output("unit", "mvn -B test", run.stdout, run.stderr, run.returncode)
    # Two test classes: the per-class line says 2, the summary says 5. The summary counts.
    assert (outcome.passed, outcome.failed) == (4, 1), run.stdout[-2000:]
    (failure,) = outcome.failures
    assert failure.test == "CartTest.subtotalMultipliesPriceByQuantity"
    assert failure.file is not None and failure.file.endswith("CartTest.java")
    assert failure.line == 12


@requires_maven
def test_agent_fixes_java_and_proves_it_with_real_tests_and_build(project: Path) -> None:
    policy = Policy()
    ws = WorkspaceGuard(project, policy.autonomy.allowed_directories)
    git = GitGuard(ws.root, policy.git)
    ctx = ToolContext(
        workspace=ws,
        policy=policy,
        audit=AuditLog(InMemoryAuditSink(), actor="java-integration"),
        git=git if git.is_repository() else None,
        approver=AllowAllApprover(),
    )
    cart = (MAIN / "Cart.java").as_posix()
    adapter = ScriptedAdapter(
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
                            "arguments": {
                                "path": cart,
                                "old_text": "total += item.unitPrice();",
                                "new_text": "total += item.unitPrice() * item.quantity();",
                            },
                        },
                        {
                            "intent": "rerun the suite",
                            "tool": "test.run",
                            "arguments": {"kind": "unit"},
                        },
                        {"intent": "build", "tool": "test.run", "arguments": {"kind": "build"}},
                    ],
                }
            ),
        ]
    )
    report = AgentLoop(adapter, default_registry()).run("make the cart tests pass", ctx)

    assert "unitPrice() * item.quantity()" in (project / cart).read_text("utf-8")
    assert MVN is not None
    independent = subprocess.run(
        [MVN, "-B", "-q", "test"], cwd=project, capture_output=True, text=True, check=False
    )
    assert independent.returncode == 0, independent.stdout[-2000:]
    assert report.outcome() == "SUCCESS", report.render()
    assert (project / "target" / "cart-1.0.0.jar").is_file()  # the build really packaged it
    assert [c.path for c in report.changes] == [cart]
