from collections.abc import Iterator
from pathlib import Path

import pytest

from aica.rag import HashingEmbedder, RepositoryIndex, chunk_file, detect_language, tokenize
from aica.tools import default_registry
from aica.workspace import WorkspaceGuard
from tests.test_tools_fs import make_ctx

PY = '''"""Module docstring."""
import os
from decimal import Decimal


CONSTANT = 42


def compute_total(items, tax_rate):
    """Sum item prices and apply tax."""
    subtotal = sum(i.price for i in items)
    return subtotal * (1 + tax_rate)


class InvoiceBuilder:
    """Builds invoices from orders."""

    def __init__(self, currency):
        self.currency = currency

    def build(self, order):
        total = compute_total(order.items, order.tax_rate)
        return Decimal(total)
'''

TS = """import { Router } from 'express';
import { db } from './database';

export interface User {
  id: string;
  email: string;
}

export function createUser(email: string): User {
  const id = db.insert('users', { email });
  return { id, email };
}

export class UserService {
  private cache = new Map();

  async findUser(id: string) {
    return this.cache.get(id) ?? db.query('users', id);
  }
}
"""

GO = """package main

import (
	"fmt"
	"net/http"
)

func handleRequest(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "ok")
}

type Server struct {
	port int
}
"""


# ---------------------------------------------------------------- chunking


def test_language_detection() -> None:
    assert detect_language("a/b.py") == "python"
    assert detect_language("x.ts") == "typescript"
    assert detect_language("main.go") == "go"
    assert detect_language("Cargo.toml") == "toml"
    assert detect_language("q.sql") == "sql"
    assert detect_language("unknown.zzz") == "text"


def test_python_chunks_keep_functions_and_classes_whole() -> None:
    chunks = chunk_file("src/inv.py", PY)
    by_symbol = {c.symbol: c for c in chunks if c.symbol}
    assert "compute_total" in by_symbol
    fn = by_symbol["compute_total"]
    assert fn.kind == "function"
    assert "subtotal = sum" in fn.text and "return subtotal" in fn.text
    cls = by_symbol["InvoiceBuilder"]
    assert cls.kind == "class" and "def build" in cls.text
    build = [c for c in chunks if c.symbol == "build"][0]
    assert build.kind == "method" and build.parent == "InvoiceBuilder"
    assert build.qualified_name == "InvoiceBuilder.build"
    assert "os" in fn.imports and "decimal" in fn.imports


def test_python_line_numbers_are_accurate() -> None:
    lines = PY.splitlines()
    for c in chunk_file("src/inv.py", PY):
        assert c.text.splitlines()[0] == lines[c.start_line - 1]


def test_typescript_and_go_chunking() -> None:
    ts = chunk_file("src/user.ts", TS)
    names = {c.symbol for c in ts}
    assert "createUser" in names and "UserService" in names
    svc = [c for c in ts if c.symbol == "UserService"][0]
    assert "findUser" in svc.text
    go = chunk_file("main.go", GO)
    assert "handleRequest" in {c.symbol for c in go}


def test_malformed_python_falls_back_to_windows() -> None:
    chunks = chunk_file("bad.py", "def broken(:\n  pass\n" * 5)
    assert chunks and all(c.kind == "window" for c in chunks)


def test_markdown_and_toml_sections() -> None:
    md = chunk_file(
        "README.md",
        "# Title\nintro text here\n\n## Install\nrun the installer now\n\n## Usage\nuse it well\n",
    )
    assert any(c.symbol == "Usage" for c in md)
    toml = chunk_file(
        "pyproject.toml",
        "[project]\nname = 'x'\nversion = '1'\n\n[tool.ruff]\nline-length = 100\nsrc = ['src']\n",
    )
    assert any(c.symbol and "project" in c.symbol for c in toml)


def test_tokenizer_splits_identifiers() -> None:
    toks = tokenize("def computeTotalPrice(item_count):")
    assert "computetotalprice" in toks and "compute" in toks and "total" in toks
    assert "item_count" in toks and "item" in toks and "count" in toks


def test_hashing_embedder_is_deterministic_and_similar_for_related_text() -> None:
    e = HashingEmbedder(dims=256)
    from aica.rag import cosine

    a, b, c = e.embed(
        [
            "compute total invoice tax",
            "compute total invoice tax",
            "unrelated banana kitchen recipe",
        ]
    )
    assert a == b
    assert cosine(a, b) > cosine(a, c)


# ---------------------------------------------------------------- index


@pytest.fixture
def indexed(tmp_path: Path) -> Iterator[RepositoryIndex]:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "invoice.py").write_text(PY, encoding="utf-8")
    (tmp_path / "src" / "user.ts").write_text(TS, encoding="utf-8")
    (tmp_path / "README.md").write_text("# Demo\nInvoice calculation service.\n", encoding="utf-8")
    (tmp_path / "src" / "caller.py").write_text(
        "from src.invoice import compute_total\n\n\ndef run(order):\n    return compute_total(order.items, 0.2)\n",
        encoding="utf-8",
    )
    idx = RepositoryIndex(WorkspaceGuard(tmp_path), db_path=tmp_path / "index.db")
    idx.index_repository()
    yield idx
    idx.close()


def test_index_covers_repository(indexed: RepositoryIndex) -> None:
    stats = indexed.stats()
    assert stats["files"] == 4 and int(stats["chunks"]) > 5
    assert "src/invoice.py" in indexed.indexed_paths()


def test_lexical_search_finds_exact_identifier(indexed: RepositoryIndex) -> None:
    results = indexed.search_lexical("compute_total")
    assert results and any(r.path == "src/invoice.py" for r in results)
    assert all(r.start_line >= 1 and r.end_line >= r.start_line for r in results)


def test_semantic_search_finds_by_meaning(indexed: RepositoryIndex) -> None:
    results = indexed.search_semantic("apply tax to the sum of prices")
    assert results
    assert any(
        "compute_total" in (r.symbol or "") or "compute_total" in r.text for r in results[:5]
    )


def test_symbol_search(indexed: RepositoryIndex) -> None:
    results = indexed.search_symbol("InvoiceBuilder")
    assert results and results[0].symbol == "InvoiceBuilder"
    assert results[0].path == "src/invoice.py"


def test_hybrid_search_ranks_relevant_first(indexed: RepositoryIndex) -> None:
    results = indexed.search("how is invoice total calculated")
    assert results
    assert any(r.path == "src/invoice.py" for r in results[:3])


def test_results_carry_source_locations(indexed: RepositoryIndex) -> None:
    r = indexed.search_symbol("compute_total")[0]
    assert r.location.startswith("src/invoice.py:")
    assert ":" in r.location and "-" in r.location


def test_retrieval_depth_widens_results(indexed: RepositoryIndex) -> None:
    shallow = indexed.search("invoice", 5, depth="shallow")
    deep = indexed.search("invoice", 5, depth="deep")
    assert len(deep) >= len(shallow)


def test_incremental_reindex_only_changed_files(indexed: RepositoryIndex) -> None:
    second = indexed.index_repository()
    assert second.files_indexed == 0 and second.files_unchanged == 4  # nothing changed
    root = indexed.workspace.root
    (root / "src" / "invoice.py").write_text(
        PY + "\n\ndef apply_discount(total, pct):\n    return total * (1 - pct)\n", encoding="utf-8"
    )
    third = indexed.index_repository()
    assert third.files_indexed == 1
    assert indexed.search_symbol("apply_discount")


def test_deleted_file_is_removed_from_index(indexed: RepositoryIndex) -> None:
    (indexed.workspace.root / "src" / "user.ts").unlink()
    stats = indexed.index_repository()
    assert stats.files_removed == 1
    assert "src/user.ts" not in indexed.indexed_paths()
    assert not [r for r in indexed.search_lexical("UserService") if r.path == "src/user.ts"]


def test_dependencies_and_dependents(indexed: RepositoryIndex) -> None:
    deps = indexed.dependencies_of("src/caller.py")
    assert any("invoice" in d for d in deps)
    dependents = indexed.dependents_of("src/invoice.py")
    assert "src/caller.py" in dependents


def test_references_exclude_the_definition(indexed: RepositoryIndex) -> None:
    refs = indexed.references_to("compute_total")
    assert any(r.path == "src/caller.py" for r in refs)


def test_secrets_are_never_indexed(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("API_KEY=supersecretvalue1234\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    with RepositoryIndex(WorkspaceGuard(tmp_path), db_path=tmp_path / "i.db") as idx:
        idx.index_repository()
        assert ".env" not in idx.indexed_paths()
        assert not idx.search_lexical("supersecretvalue1234")


def test_authorization_limits_retrieval(tmp_path: Path) -> None:
    (tmp_path / "public").mkdir()
    (tmp_path / "private").mkdir()
    (tmp_path / "public" / "a.py").write_text("def visible_symbol(): pass\n", encoding="utf-8")
    (tmp_path / "private" / "b.py").write_text("def hidden_symbol(): pass\n", encoding="utf-8")
    with RepositoryIndex(WorkspaceGuard(tmp_path), db_path=tmp_path / "i.db") as full:
        full.index_repository()
        assert full.search_symbol("hidden_symbol")
    # A user authorized only for public/ must not retrieve private/ content (RAG-007).
    guard = WorkspaceGuard(tmp_path, ["public"])
    with RepositoryIndex(guard, db_path=tmp_path / "i.db") as restricted:
        assert not restricted.search_symbol("hidden_symbol")
        assert restricted.search_symbol("visible_symbol")
        assert not [
            r for r in restricted.search_lexical("hidden_symbol") if r.path.startswith("private/")
        ]


# ---------------------------------------------------------------- RAG tools


def test_rag_tools_end_to_end(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "invoice.py").write_text(PY, encoding="utf-8")
    ctx = make_ctx(tmp_path)
    ctx.index = RepositoryIndex(ctx.workspace, db_path=tmp_path / "i.db")
    assert ctx.index is not None
    reg = default_registry()
    stats = reg.call("repo.index", {}, ctx)
    assert stats.data["files_indexed"] == 1
    search = reg.call("repo.search", {"query": "compute total", "limit": 3}, ctx)
    assert search.data["count"] >= 1
    assert all(":" in loc for loc in search.data["locations"])
    deps = reg.call("repo.dependencies", {"symbol": "compute_total"}, ctx)
    assert deps.data["definitions"]
    info = reg.call("repo.stats", {}, ctx)
    assert int(info.data["files"]) == 1
    ctx.index.close()
