"""Repository index (RAG-001..RAG-010).

A single SQLite database holds chunks, an FTS-like inverted index for lexical/symbol
search (RAG-004), dense vectors for semantic search (RAG-003), a symbol table and an
import/dependency edge table (RAG-005). Indexing is incremental by content hash
(RAG-006). Every retrieval result carries repository-relative path and line span
(RAG-008); paths are filtered through the caller's ``WorkspaceGuard`` so a user can never
retrieve content outside their authorized workspace (RAG-007).

SQLite is chosen for the MVP because it needs no service, supports incremental updates
and keeps the whole index reproducible as one file. Swapping the vector store later only
touches ``_search_semantic``.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import posixpath
import sqlite3
import time
from collections import defaultdict
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

from aica.rag.chunking import CODE_LANGUAGES, Chunk, chunk_file, detect_language
from aica.rag.embeddings import Embedder, HashingEmbedder, cosine, tokenize
from aica.workspace.paths import WorkspaceGuard

DEFAULT_INDEX_PATH = Path(".aica/index/repo.db")
SKIP_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".aica",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    "dist",
    "build",
    "target",
    ".idea",
    ".tox",
    "coverage",
    "htmlcov",
}
SKIP_SUFFIXES = {
    ".pyc",
    ".pyo",
    ".so",
    ".dll",
    ".dylib",
    ".exe",
    ".bin",
    ".zip",
    ".tar",
    ".gz",
    ".jar",
    ".war",
    ".class",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".svg",
    ".pdf",
    ".docx",
    ".xlsx",
    ".pptx",
    ".woff",
    ".woff2",
    ".ttf",
    ".mp4",
    ".mp3",
    ".db",
    ".sqlite",
    ".lock",
}
MAX_FILE_BYTES = 1_000_000

_SCHEMA = """
CREATE TABLE IF NOT EXISTS files (
  path TEXT PRIMARY KEY, sha TEXT NOT NULL, language TEXT NOT NULL,
  size INTEGER NOT NULL, indexed_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS chunks (
  id INTEGER PRIMARY KEY, path TEXT NOT NULL, language TEXT NOT NULL, kind TEXT NOT NULL,
  symbol TEXT, parent TEXT, signature TEXT, start_line INTEGER NOT NULL,
  end_line INTEGER NOT NULL, text TEXT NOT NULL, vector TEXT
);
CREATE INDEX IF NOT EXISTS chunks_path ON chunks(path);
CREATE INDEX IF NOT EXISTS chunks_symbol ON chunks(symbol);
CREATE TABLE IF NOT EXISTS postings (term TEXT NOT NULL, chunk_id INTEGER NOT NULL, tf INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS postings_term ON postings(term);
CREATE INDEX IF NOT EXISTS postings_chunk ON postings(chunk_id);
CREATE TABLE IF NOT EXISTS symbols (
  name TEXT NOT NULL, path TEXT NOT NULL, kind TEXT NOT NULL, parent TEXT,
  start_line INTEGER NOT NULL, end_line INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS symbols_name ON symbols(name);
CREATE TABLE IF NOT EXISTS deps (src_path TEXT NOT NULL, target TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS deps_src ON deps(src_path);
CREATE INDEX IF NOT EXISTS deps_target ON deps(target);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


@dataclass(frozen=True)
class SearchResult:
    path: str
    start_line: int
    end_line: int
    language: str
    kind: str
    symbol: str | None
    score: float
    text: str
    source: str  # lexical | semantic | symbol | dependency

    @property
    def location(self) -> str:
        """RAG-008: citable source location."""
        base = f"{self.path}:{self.start_line}-{self.end_line}"
        return f"{base} ({self.symbol})" if self.symbol else base


@dataclass(frozen=True)
class IndexStats:
    files_indexed: int
    files_unchanged: int  # already current (incremental no-op)
    files_skipped: int  # unreadable/binary
    files_removed: int
    chunks: int
    duration_ms: int


def _resolve_import(importer: str, target: str) -> str:
    """RAG-005: store a relative import (``./x``, ``../src/x.ts``) as a repository path.

    Kept raw, ``../src/cart.ts`` matches nothing, so the files importing a module could
    never be found. Package imports (``react``, ``node:test``) are left as written.
    """
    if not target.startswith(("./", "../")):
        return target
    joined = posixpath.normpath(posixpath.join(posixpath.dirname(importer), target))
    return target if joined.startswith("..") else joined


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


class RepositoryIndex:
    def __init__(
        self,
        workspace: WorkspaceGuard,
        db_path: str | os.PathLike[str] | None = None,
        embedder: Embedder | None = None,
        *,
        allow_thread_handoff: bool = False,
    ) -> None:
        """``allow_thread_handoff`` permits the index to be used from a thread other than
        the one that opened it.

        SQLite binds a connection to its creating thread by default. A server that prepares
        retrieval on a request thread and then hands the index to a task worker needs to opt
        out of that check. It is only safe because ownership passes from one thread to the
        next - the two never use the connection at the same time - so callers that would
        share it concurrently must open their own index instead.
        """
        self.workspace = workspace
        self.embedder = embedder or HashingEmbedder()
        path = Path(db_path) if db_path else workspace.root / DEFAULT_INDEX_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db_path = path
        self.conn = sqlite3.connect(str(path), check_same_thread=not allow_thread_handoff)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA)
        self._set_meta("embedder", self.embedder.name)
        self._set_meta("dims", str(self.embedder.dims))

    # ------------------------------------------------------------------ meta
    def _set_meta(self, key: str, value: str) -> None:
        self.conn.execute(
            "INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )
        self.conn.commit()

    def get_meta(self, key: str) -> str | None:
        row = self.conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else None

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> RepositoryIndex:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------ RAG-001/006
    def iter_source_files(self, subdir: str | None = None) -> Iterator[Path]:
        base = self.workspace.resolve(subdir).absolute if subdir else self.workspace.root
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = sorted(
                d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".git")
            )
            for fn in sorted(filenames):
                p = Path(dirpath) / fn
                if p.suffix.lower() in SKIP_SUFFIXES:
                    continue
                try:
                    if p.stat().st_size > MAX_FILE_BYTES:
                        continue
                except OSError:
                    continue
                if not self.workspace.is_authorized(p):
                    continue
                rel = p.relative_to(self.workspace.root)
                if WorkspaceGuard.is_sensitive(rel):
                    continue  # never index credentials (SAFE-006)
                yield p

    def index_repository(self, subdir: str | None = None, *, force: bool = False) -> IndexStats:
        started = time.monotonic()
        seen: set[str] = set()
        indexed = unchanged = skipped = 0
        for path in self.iter_source_files(subdir):
            rel = path.relative_to(self.workspace.root).as_posix()
            seen.add(rel)
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                skipped += 1
                continue
            if self.index_file(rel, text, force=force):
                indexed += 1
            else:
                unchanged += 1
        removed = 0
        if subdir is None:
            known = {r["path"] for r in self.conn.execute("SELECT path FROM files")}
            for gone in known - seen:
                self.remove_file(gone)
                removed += 1
        self.conn.commit()
        total = self.conn.execute("SELECT COUNT(*) AS c FROM chunks").fetchone()["c"]
        return IndexStats(
            indexed, unchanged, skipped, removed, total, int((time.monotonic() - started) * 1000)
        )

    def index_file(self, rel_path: str, text: str, *, force: bool = False) -> bool:
        """Index one file. Returns False when unchanged (RAG-006 incremental)."""
        sha = sha256(text)
        row = self.conn.execute("SELECT sha FROM files WHERE path=?", (rel_path,)).fetchone()
        if row and row["sha"] == sha and not force:
            return False
        self.remove_file(rel_path, commit=False)
        language = detect_language(rel_path)
        chunks = chunk_file(rel_path, text)
        if not chunks:
            self.conn.execute(
                "INSERT INTO files(path,sha,language,size,indexed_at) VALUES(?,?,?,?,?)",
                (rel_path, sha, language, len(text), time.time()),
            )
            return True
        vectors = self.embedder.embed([self._embed_text(c) for c in chunks])
        for chunk, vector in zip(chunks, vectors, strict=True):
            cur = self.conn.execute(
                "INSERT INTO chunks(path,language,kind,symbol,parent,signature,start_line,end_line,text,vector) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    chunk.path,
                    chunk.language,
                    chunk.kind,
                    chunk.symbol,
                    chunk.parent,
                    chunk.signature,
                    chunk.start_line,
                    chunk.end_line,
                    chunk.text,
                    json.dumps([round(v, 5) for v in vector]),
                ),
            )
            chunk_id = int(cur.lastrowid or 0)
            counts: dict[str, int] = defaultdict(int)
            for tok in tokenize(chunk.text):
                counts[tok] += 1
            if chunk.symbol:
                for tok in tokenize(chunk.symbol):
                    counts[tok] += 5  # symbol names weigh more
            self.conn.executemany(
                "INSERT INTO postings(term,chunk_id,tf) VALUES(?,?,?)",
                [(t, chunk_id, c) for t, c in counts.items()],
            )
            if chunk.symbol and chunk.kind in {"class", "function", "method", "statement"}:
                self.conn.execute(
                    "INSERT INTO symbols(name,path,kind,parent,start_line,end_line) VALUES(?,?,?,?,?,?)",
                    (
                        chunk.symbol,
                        chunk.path,
                        chunk.kind,
                        chunk.parent,
                        chunk.start_line,
                        chunk.end_line,
                    ),
                )
        for target in dict.fromkeys(
            _resolve_import(rel_path, t) for c in chunks for t in c.imports
        ):
            self.conn.execute("INSERT INTO deps(src_path,target) VALUES(?,?)", (rel_path, target))
        self.conn.execute(
            "INSERT INTO files(path,sha,language,size,indexed_at) VALUES(?,?,?,?,?)",
            (rel_path, sha, language, len(text), time.time()),
        )
        return True

    @staticmethod
    def _embed_text(chunk: Chunk) -> str:
        head = " ".join(
            filter(
                None, [chunk.path.replace("/", " "), chunk.parent, chunk.symbol, chunk.signature]
            )
        )
        return f"{head}\n{chunk.text}"

    def remove_file(self, rel_path: str, *, commit: bool = True) -> None:
        ids = [
            r["id"] for r in self.conn.execute("SELECT id FROM chunks WHERE path=?", (rel_path,))
        ]
        if ids:
            self.conn.executemany("DELETE FROM postings WHERE chunk_id=?", [(i,) for i in ids])
        self.conn.execute("DELETE FROM chunks WHERE path=?", (rel_path,))
        self.conn.execute("DELETE FROM symbols WHERE path=?", (rel_path,))
        self.conn.execute("DELETE FROM deps WHERE src_path=?", (rel_path,))
        self.conn.execute("DELETE FROM files WHERE path=?", (rel_path,))
        if commit:
            self.conn.commit()

    # ------------------------------------------------------------------ retrieval
    def _authorized(self, path: str) -> bool:
        """RAG-007: never return content outside the caller's authorized workspace."""
        return self.workspace.is_authorized(path)

    def _row_to_result(
        self, row: sqlite3.Row, score: float, source: str, *, snippet: bool = True
    ) -> SearchResult:
        text = row["text"]
        if snippet and len(text) > 4000:
            text = text[:4000] + "\n... [truncated]"
        return SearchResult(
            row["path"],
            row["start_line"],
            row["end_line"],
            row["language"],
            row["kind"],
            row["symbol"],
            score,
            text,
            source,
        )

    def search_lexical(
        self, query: str, limit: int = 10, *, path_prefix: str | None = None
    ) -> list[SearchResult]:
        """RAG-004: BM25-ish scoring over the inverted index."""
        terms = list(dict.fromkeys(tokenize(query)))
        if not terms:
            return []
        total_docs = self.conn.execute("SELECT COUNT(*) AS c FROM chunks").fetchone()["c"] or 1
        scores: dict[int, float] = defaultdict(float)
        for term in terms:
            rows = self.conn.execute(
                "SELECT chunk_id, tf FROM postings WHERE term=?", (term,)
            ).fetchall()
            if not rows:
                continue
            idf = math.log(1 + (total_docs - len(rows) + 0.5) / (len(rows) + 0.5))
            for r in rows:
                tf = r["tf"]
                scores[r["chunk_id"]] += idf * (tf * 2.2) / (tf + 1.2)
        return self._collect(scores, limit, "lexical", path_prefix)

    def search_semantic(
        self, query: str, limit: int = 10, *, path_prefix: str | None = None
    ) -> list[SearchResult]:
        """RAG-003: cosine similarity over chunk vectors."""
        qvec = self.embedder.embed([query])[0]
        scores: dict[int, float] = {}
        for row in self.conn.execute("SELECT id, vector FROM chunks WHERE vector IS NOT NULL"):
            vec = json.loads(row["vector"])
            scores[row["id"]] = cosine(qvec, vec)
        top = {k: v for k, v in scores.items() if v > 0.01}
        return self._collect(top, limit, "semantic", path_prefix)

    def search_symbol(self, name: str, limit: int = 20) -> list[SearchResult]:
        """RAG-004: exact/prefix symbol lookup."""
        rows = self.conn.execute(
            "SELECT c.* FROM symbols s JOIN chunks c ON c.path=s.path AND c.start_line=s.start_line "
            "WHERE s.name=? OR s.name LIKE ? ORDER BY (s.name=?) DESC, LENGTH(s.name) LIMIT ?",
            (name, name + "%", name, limit * 3),
        ).fetchall()
        out = [self._row_to_result(r, 1.0, "symbol") for r in rows if self._authorized(r["path"])]
        return out[:limit]

    def search(
        self, query: str, limit: int = 10, *, path_prefix: str | None = None, depth: str = "normal"
    ) -> list[SearchResult]:
        """RAG-003+004 hybrid with reciprocal-rank fusion; RAG-009 configurable depth."""
        widths = {
            "shallow": (limit, 0),
            "normal": (limit * 3, limit * 3),
            "deep": (limit * 6, limit * 6),
        }
        lex_n, sem_n = widths.get(depth, widths["normal"])
        ranked: dict[str, float] = defaultdict(float)
        seen: dict[str, SearchResult] = {}
        for rank, res in enumerate(self.search_lexical(query, lex_n, path_prefix=path_prefix)):
            ranked[res.location] += 1.0 / (60 + rank)
            seen[res.location] = res
        if sem_n:
            for rank, res in enumerate(self.search_semantic(query, sem_n, path_prefix=path_prefix)):
                ranked[res.location] += 1.0 / (60 + rank)
                seen.setdefault(res.location, res)
        for token in dict.fromkeys(tokenize(query)):
            for rank, res in enumerate(self.search_symbol(token, 3)):
                ranked[res.location] += 1.5 / (60 + rank)
                seen.setdefault(res.location, res)
        order = sorted(ranked.items(), key=lambda kv: -kv[1])[:limit]
        out: list[SearchResult] = []
        for loc, score in order:
            r = seen[loc]
            out.append(
                SearchResult(
                    r.path,
                    r.start_line,
                    r.end_line,
                    r.language,
                    r.kind,
                    r.symbol,
                    round(score, 6),
                    r.text,
                    "hybrid",
                )
            )
        return out

    def _collect(
        self, scores: dict[int, float], limit: int, source: str, path_prefix: str | None
    ) -> list[SearchResult]:
        if not scores:
            return []
        ordered = sorted(scores.items(), key=lambda kv: -kv[1])
        out: list[SearchResult] = []
        for chunk_id, score in ordered:
            row = self.conn.execute("SELECT * FROM chunks WHERE id=?", (chunk_id,)).fetchone()
            if row is None or not self._authorized(row["path"]):
                continue
            if path_prefix and not row["path"].startswith(path_prefix):
                continue
            out.append(self._row_to_result(row, round(score, 6), source))
            if len(out) >= limit:
                break
        return out

    # ------------------------------------------------------------------ RAG-005
    def dependencies_of(self, rel_path: str) -> list[str]:
        return [
            r["target"]
            for r in self.conn.execute(
                "SELECT DISTINCT target FROM deps WHERE src_path=? ORDER BY target", (rel_path,)
            )
        ]

    def dependents_of(self, rel_path: str) -> list[str]:
        """Files importing this module (matched by module-ish path stem)."""
        stem = Path(rel_path).with_suffix("").as_posix()
        # rel_path itself: a relative JS/TS import is stored resolved, extension and all.
        candidates = {rel_path, stem, stem.replace("/", "."), Path(rel_path).stem}
        if stem.startswith("src/"):
            trimmed = stem[4:]
            candidates |= {trimmed, trimmed.replace("/", ".")}
        out: set[str] = set()
        for cand in candidates:
            for r in self.conn.execute(
                "SELECT DISTINCT src_path FROM deps WHERE target=? OR target LIKE ?",
                (cand, "%" + cand.replace("/", ".")),
            ):
                if r["src_path"] != rel_path and self._authorized(r["src_path"]):
                    out.add(r["src_path"])
        return sorted(out)

    def references_to(self, symbol: str, limit: int = 20) -> list[SearchResult]:
        """Callers/usages of a symbol (RAG-005)."""
        rows = self.conn.execute(
            "SELECT c.*, p.tf FROM postings p JOIN chunks c ON c.id=p.chunk_id WHERE p.term=? ORDER BY p.tf DESC LIMIT ?",
            (symbol.lower(), limit * 3),
        ).fetchall()
        out = []
        for r in rows:
            if not self._authorized(r["path"]):
                continue
            if r["symbol"] == symbol and r["kind"] in {"class", "function", "method"}:
                continue  # skip the definition itself
            out.append(self._row_to_result(r, float(r["tf"]), "dependency"))
        return out[:limit]

    def search_file(
        self, rel_path: str, line: int | None = None, limit: int = 3
    ) -> list[SearchResult]:
        """Chunks of one file, preferring the chunk covering ``line`` (CHAT-004 log frames).

        The path is matched by suffix as well as exactly, because a log may report
        ``src/aica/x.py`` while the index stores it relative to a different root segment.
        """
        normalized = rel_path.replace("\\", "/").lstrip("./")
        rows = self.conn.execute(
            "SELECT * FROM chunks WHERE path=? OR path LIKE ? ORDER BY path, start_line",
            (normalized, "%/" + normalized),
        ).fetchall()
        results = [self._row_to_result(r, 1.0, "file") for r in rows if self._authorized(r["path"])]
        if not results:
            return []
        if line is not None:
            covering = [r for r in results if r.start_line <= line <= r.end_line]
            others = sorted(
                (r for r in results if r not in covering),
                key=lambda r: abs(r.start_line - line),
            )
            results = covering + others
        return results[:limit]

    def neighbors(self, rel_path: str) -> dict[str, list[str]]:
        return {
            "imports": self.dependencies_of(rel_path),
            "imported_by": self.dependents_of(rel_path),
        }

    # ------------------------------------------------------------------ misc
    def stats(self) -> dict[str, int | str]:
        files = self.conn.execute("SELECT COUNT(*) AS c FROM files").fetchone()["c"]
        chunks = self.conn.execute("SELECT COUNT(*) AS c FROM chunks").fetchone()["c"]
        symbols = self.conn.execute("SELECT COUNT(*) AS c FROM symbols").fetchone()["c"]
        langs = {
            r["language"]: r["c"]
            for r in self.conn.execute(
                "SELECT language, COUNT(*) AS c FROM files GROUP BY language ORDER BY c DESC"
            )
        }
        code_files = sum(c for lang, c in langs.items() if lang in CODE_LANGUAGES)
        return {
            "files": files,
            "chunks": chunks,
            "symbols": symbols,
            "code_files": code_files,
            "languages": json.dumps(langs),
            "embedder": self.embedder.name,
        }

    def indexed_paths(self) -> list[str]:
        return [r["path"] for r in self.conn.execute("SELECT path FROM files ORDER BY path")]

    def reindex_paths(self, rel_paths: Iterable[str]) -> int:
        """RAG-006: re-index specific files after the agent edits them."""
        count = 0
        for rel in rel_paths:
            absolute = self.workspace.resolve(rel).absolute
            if not absolute.exists():
                self.remove_file(rel)
                continue
            try:
                text = absolute.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            if self.index_file(absolute.relative_to(self.workspace.root).as_posix(), text):
                count += 1
        self.conn.commit()
        return count
