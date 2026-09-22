"""RAG exposed as agent tools (RAG-010, RAG-008, RAG-009)."""

from __future__ import annotations

from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field

from aica.rag.index import RepositoryIndex, SearchResult
from aica.tools.base import Tool, ToolContext, ToolError, ToolResult


class _Args(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _index(ctx: ToolContext) -> RepositoryIndex:
    if ctx.index is None:
        raise ToolError("repository index is not attached to this context")
    return ctx.index


def format_results(results: list[SearchResult], *, include_text: bool = True) -> str:
    out: list[str] = []
    for r in results:
        header = f"--- {r.location} [{r.language}/{r.kind}] score={r.score}"
        out.append(header + ("\n" + r.text if include_text else ""))
    return "\n".join(out)


class RepoSearch(Tool):
    name: ClassVar[str] = "repo.search"
    description: ClassVar[str] = (
        "Search the indexed repository. mode=hybrid (default), lexical, semantic or symbol. "
        "Results include repository path and line numbers."
    )

    class Args(_Args):
        query: str = Field(min_length=1, max_length=1000)
        mode: str = Field(default="hybrid", pattern="^(hybrid|lexical|semantic|symbol)$")
        limit: int = Field(default=8, ge=1, le=50)
        path_prefix: str | None = None
        depth: str = Field(default="normal", pattern="^(shallow|normal|deep)$")
        include_text: bool = True

    def run(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        assert isinstance(args, self.Args)
        idx = _index(ctx)
        if args.mode == "lexical":
            results = idx.search_lexical(args.query, args.limit, path_prefix=args.path_prefix)
        elif args.mode == "semantic":
            results = idx.search_semantic(args.query, args.limit, path_prefix=args.path_prefix)
        elif args.mode == "symbol":
            results = idx.search_symbol(args.query, args.limit)
        else:
            results = idx.search(
                args.query, args.limit, path_prefix=args.path_prefix, depth=args.depth
            )
        return ToolResult(
            output=format_results(results, include_text=args.include_text) or "(no matches)",
            data={
                "count": len(results),
                "locations": [r.location for r in results],
                "mode": args.mode,
            },
        )


class RepoIndexTool(Tool):
    name: ClassVar[str] = "repo.index"
    description: ClassVar[str] = "Index or incrementally re-index the repository."

    class Args(_Args):
        subdir: str | None = None
        paths: list[str] = Field(default_factory=list, description="re-index only these files")
        force: bool = False

    def run(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        assert isinstance(args, self.Args)
        idx = _index(ctx)
        if args.paths:
            n = idx.reindex_paths(args.paths)
            return ToolResult(output=f"re-indexed {n} file(s)", data={"reindexed": n})
        stats = idx.index_repository(args.subdir, force=args.force)
        return ToolResult(
            output=(
                f"indexed {stats.files_indexed} file(s), unchanged {stats.files_unchanged}, "
                f"skipped {stats.files_skipped}, removed {stats.files_removed}, "
                f"{stats.chunks} chunks in {stats.duration_ms}ms"
            ),
            data={
                "files_indexed": stats.files_indexed,
                "files_unchanged": stats.files_unchanged,
                "files_skipped": stats.files_skipped,
                "files_removed": stats.files_removed,
                "chunks": stats.chunks,
                "duration_ms": stats.duration_ms,
            },
        )


class RepoDependencies(Tool):
    name: ClassVar[str] = "repo.dependencies"
    description: ClassVar[str] = (
        "Show imports, importers and references for a file or symbol (RAG-005)."
    )

    class Args(_Args):
        path: str | None = None
        symbol: str | None = None
        limit: int = Field(default=20, ge=1, le=100)

    def run(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        assert isinstance(args, self.Args)
        if not args.path and not args.symbol:
            raise ToolError("provide path or symbol")
        idx = _index(ctx)
        data: dict[str, object] = {}
        lines: list[str] = []
        if args.path:
            rel = ctx.workspace.resolve(args.path).relative.as_posix()
            n = idx.neighbors(rel)
            data.update(n)
            lines.append(f"{rel} imports: " + (", ".join(n["imports"]) or "(none)"))
            lines.append(f"{rel} imported by: " + (", ".join(n["imported_by"]) or "(none)"))
        if args.symbol:
            defs = idx.search_symbol(args.symbol, args.limit)
            refs = idx.references_to(args.symbol, args.limit)
            data["definitions"] = [r.location for r in defs]
            data["references"] = [r.location for r in refs]
            lines.append(
                f"definitions of {args.symbol}: "
                + (", ".join(r.location for r in defs) or "(none)")
            )
            lines.append(
                f"references to {args.symbol}: " + (", ".join(r.location for r in refs) or "(none)")
            )
        return ToolResult(output="\n".join(lines), data=data)


class RepoStats(Tool):
    name: ClassVar[str] = "repo.stats"
    description: ClassVar[str] = "Index statistics: files, chunks, symbols and languages."

    class Args(_Args):
        pass

    def run(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        stats = _index(ctx).stats()
        return ToolResult(output="\n".join(f"{k}: {v}" for k, v in stats.items()), data=dict(stats))


RAG_TOOLS: list[Tool] = [RepoIndexTool(), RepoSearch(), RepoDependencies(), RepoStats()]
