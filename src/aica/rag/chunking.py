"""Syntax-aware chunking (RAG-002, BRD section 9.1 languages).

Python is chunked with the stdlib ``ast`` so functions, classes and methods stay whole.
Java / TypeScript / JavaScript / Go / Rust use declaration-boundary heuristics (brace
balanced) that keep function/class bodies coherent. Configuration files (YAML/JSON/TOML)
are chunked by top-level block. Anything else falls back to line windows. Every chunk
carries repository-relative path, line span and symbol name (RAG-008).

Upgrading the heuristic chunkers to tree-sitter grammars is a recorded Phase 2 option.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath

LANGUAGE_BY_EXT: dict[str, str] = {
    ".py": "python",
    ".pyi": "python",
    ".java": "java",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".mts": "typescript",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".go": "go",
    ".rs": "rust",
    ".sql": "sql",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
    ".toml": "toml",
    ".md": "markdown",
    ".rst": "markdown",
    ".txt": "text",
    ".sh": "shell",
    ".ps1": "powershell",
    ".cmd": "batch",
    ".bat": "batch",
    ".tf": "hcl",
    ".hcl": "hcl",
    ".xml": "xml",
    ".gradle": "groovy",
    ".kts": "kotlin",
    ".kt": "kotlin",
    ".cs": "csharp",
    ".cpp": "cpp",
    ".c": "c",
    ".h": "c",
    ".rb": "ruby",
    ".php": "php",
}
CODE_LANGUAGES = {
    "python",
    "java",
    "typescript",
    "javascript",
    "go",
    "rust",
    "sql",
    "kotlin",
    "csharp",
    "cpp",
    "c",
    "ruby",
    "php",
}
WINDOW_LINES = 60
MAX_CHUNK_LINES = 400


@dataclass(frozen=True)
class Chunk:
    path: str  # repository-relative, posix
    language: str
    kind: str  # module | class | function | method | block | window | section
    symbol: str | None
    start_line: int  # 1-based inclusive
    end_line: int  # inclusive
    text: str
    parent: str | None = None
    signature: str | None = None
    imports: tuple[str, ...] = field(default_factory=tuple)

    @property
    def id(self) -> str:
        return f"{self.path}:{self.start_line}-{self.end_line}"

    @property
    def qualified_name(self) -> str | None:
        if self.symbol is None:
            return None
        return f"{self.parent}.{self.symbol}" if self.parent else self.symbol


def detect_language(path: str) -> str:
    p = PurePosixPath(path)
    name = p.name.lower()
    if name in {"dockerfile", "makefile"}:
        return name
    if name in {"package.json", "tsconfig.json"}:
        return "json"
    return LANGUAGE_BY_EXT.get(p.suffix.lower(), "text")


def chunk_file(path: str, text: str) -> list[Chunk]:
    language = detect_language(path)
    if not text.strip():
        return []
    if language == "python":
        chunks = _chunk_python(path, text)
    elif language in {
        "java",
        "typescript",
        "javascript",
        "go",
        "rust",
        "kotlin",
        "csharp",
        "cpp",
        "c",
    }:
        chunks = _chunk_braces(path, text, language)
    elif language in {"yaml", "toml", "hcl"}:
        chunks = _chunk_indent_sections(path, text, language)
    elif language == "markdown":
        chunks = _chunk_markdown(path, text)
    elif language == "sql":
        chunks = _chunk_sql(path, text)
    else:
        chunks = []
    return chunks or _chunk_windows(path, text, language)


# ------------------------------------------------------------------ Python (ast)


def _python_imports(tree: ast.AST) -> tuple[str, ...]:
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.append(node.module)
    return tuple(dict.fromkeys(names))


def _chunk_python(path: str, text: str) -> list[Chunk]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    lines = text.splitlines()
    imports = _python_imports(tree)
    chunks: list[Chunk] = []
    covered: set[int] = set()

    def span(node: ast.AST) -> tuple[int, int]:
        start = getattr(node, "lineno", 1)
        decos = getattr(node, "decorator_list", [])
        if decos:
            start = min(start, *(d.lineno for d in decos))
        end = getattr(node, "end_lineno", start)
        return start, end

    def add(node: ast.AST, kind: str, symbol: str, parent: str | None) -> None:
        start, end = span(node)
        body = "\n".join(lines[start - 1 : end])
        sig = lines[getattr(node, "lineno", start) - 1].strip()
        chunks.append(Chunk(path, "python", kind, symbol, start, end, body, parent, sig, imports))
        covered.update(range(start, end + 1))

    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            add(node, "function", node.name, None)
        elif isinstance(node, ast.ClassDef):
            add(node, "class", node.name, None)
            for sub in node.body:
                if isinstance(sub, ast.FunctionDef | ast.AsyncFunctionDef):
                    add(sub, "method", sub.name, node.name)
    # Module-level remainder (imports, constants, top-level statements).
    rest = [i + 1 for i in range(len(lines)) if (i + 1) not in covered and lines[i].strip()]
    if rest:
        groups = _group_consecutive(rest, gap=2)
        for start, end in groups:
            body = "\n".join(lines[start - 1 : end])
            chunks.append(
                Chunk(path, "python", "module", None, start, end, body, None, None, imports)
            )
    chunks.sort(key=lambda c: (c.start_line, c.kind != "class"))
    return chunks


def _group_consecutive(numbers: list[int], gap: int = 1) -> list[tuple[int, int]]:
    groups: list[tuple[int, int]] = []
    start = prev = numbers[0]
    for n in numbers[1:]:
        if n - prev > gap:
            groups.append((start, prev))
            start = n
        prev = n
    groups.append((start, prev))
    return groups


# ------------------------------------------------------------------ brace languages

_DECL = re.compile(
    r"^\s*(?:export\s+|pub(?:\([^)]*\))?\s+|public\s+|private\s+|protected\s+|static\s+|final\s+|abstract\s+|async\s+|default\s+|unsafe\s+)*"
    r"(?:"
    r"(?P<kind>class|interface|enum|struct|trait|impl|record|object|type|fn|func|function|def|module|namespace)\s+(?P<name>[A-Za-z_][\w<>,\s]*?)\s*[({<:=]"
    r"|(?:[\w<>\[\],.?]+\s+)+(?P<jname>[A-Za-z_]\w*)\s*\([^;]*\)\s*(?:throws[^{]*)?\{"
    r"|(?:const|let|var)\s+(?P<cname>[A-Za-z_]\w*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_]\w*)\s*=>\s*\{"
    r"|func\s+\([^)]*\)\s+(?P<gname>[A-Za-z_]\w*)\s*\("
    r")"
)
_IMPORT = re.compile(
    # ":" in the module name keeps "node:test" whole instead of truncating it to "node".
    r'^\s*(?:import\s+(?:[\w.*{}\s,]+\s+from\s+)?["\']?([\w./@:-]+)|use\s+([\w:]+)|require\(["\']([\w./@:-]+))',
    re.M,
)


def _brace_imports(text: str) -> tuple[str, ...]:
    out: list[str] = []
    for m in _IMPORT.finditer(text):
        out.append(next(g for g in m.groups() if g))
    for m in re.finditer(r'^\s*import\s+(?:\(\s*([^)]*)\)|"([^"]+)")', text, re.M):  # Go
        block = m.group(1) or m.group(2) or ""
        out.extend(re.findall(r'"([^"]+)"', block) or [block])
    return tuple(dict.fromkeys(o for o in out if o))


def _chunk_braces(path: str, text: str, language: str) -> list[Chunk]:
    lines = text.splitlines()
    imports = _brace_imports(text)
    chunks: list[Chunk] = []
    i = 0
    n = len(lines)
    covered: set[int] = set()
    while i < n:
        m = _DECL.match(lines[i])
        if not m or "{" not in "".join(lines[i : i + 3]):
            i += 1
            continue
        name = (
            m.group("name") or m.group("jname") or m.group("cname") or m.group("gname") or ""
        ).strip()
        name = re.split(r"[<\s(:=]", name)[0] if name else ""
        kind_word = (m.group("kind") or "").lower()
        kind = (
            "class"
            if kind_word
            in {
                "class",
                "interface",
                "enum",
                "struct",
                "trait",
                "impl",
                "record",
                "object",
                "module",
                "namespace",
            }
            else "function"
        )
        # Walk forward balancing braces to find the end of the declaration body.
        depth = 0
        started = False
        j = i
        while j < n:
            for ch in lines[j]:
                if ch == "{":
                    depth += 1
                    started = True
                elif ch == "}":
                    depth -= 1
            if started and depth <= 0:
                break
            if j - i > MAX_CHUNK_LINES:
                break
            j += 1
        end = min(j, n - 1)
        if not started:
            i += 1
            continue
        body = "\n".join(lines[i : end + 1])
        chunks.append(
            Chunk(
                path,
                language,
                kind,
                name or None,
                i + 1,
                end + 1,
                body,
                None,
                lines[i].strip(),
                imports,
            )
        )
        covered.update(range(i + 1, end + 2))
        if kind == "class":
            # Also index methods inside the class body.
            for sub in _chunk_braces_inner(
                path, lines, i + 1, end, language, name or None, imports
            ):
                chunks.append(sub)
        i = end + 1
    rest = [k + 1 for k in range(n) if (k + 1) not in covered and lines[k].strip()]
    if rest:
        for start, end2 in _group_consecutive(rest, gap=2):
            if end2 - start + 1 > WINDOW_LINES:
                for w in _chunk_windows(
                    path, "\n".join(lines[start - 1 : end2]), language, offset=start - 1
                ):
                    chunks.append(w)
            else:
                chunks.append(
                    Chunk(
                        path,
                        language,
                        "module",
                        None,
                        start,
                        end2,
                        "\n".join(lines[start - 1 : end2]),
                        None,
                        None,
                        imports,
                    )
                )
    chunks.sort(key=lambda c: (c.start_line, c.kind != "class"))
    return chunks


def _chunk_braces_inner(
    path: str,
    lines: list[str],
    start: int,
    end: int,
    language: str,
    parent: str | None,
    imports: tuple[str, ...],
) -> list[Chunk]:
    out: list[Chunk] = []
    i = start
    while i <= end:
        m = _DECL.match(lines[i])
        if m and (
            m.group("jname")
            or m.group("gname")
            or (m.group("kind") or "") in {"fn", "func", "function", "def"}
        ):
            name = (m.group("name") or m.group("jname") or m.group("gname") or "").strip()
            name = re.split(r"[<\s(:=]", name)[0]
            depth = 0
            started = False
            j = i
            while j <= end:
                for ch in lines[j]:
                    if ch == "{":
                        depth += 1
                        started = True
                    elif ch == "}":
                        depth -= 1
                if started and depth <= 0:
                    break
                j += 1
            if started and name:
                out.append(
                    Chunk(
                        path,
                        language,
                        "method",
                        name,
                        i + 1,
                        min(j, end) + 1,
                        "\n".join(lines[i : min(j, end) + 1]),
                        parent,
                        lines[i].strip(),
                        imports,
                    )
                )
                i = j + 1
                continue
        i += 1
    return out


# ------------------------------------------------------------------ config / docs / sql


def _chunk_indent_sections(path: str, text: str, language: str) -> list[Chunk]:
    lines = text.splitlines()
    starts = [
        i
        for i, line in enumerate(lines)
        if line and not line[0].isspace() and not line.startswith("#")
    ]
    if not starts:
        return []
    chunks: list[Chunk] = []
    for idx, s in enumerate(starts):
        e = (starts[idx + 1] - 1) if idx + 1 < len(starts) else len(lines) - 1
        while e > s and not lines[e].strip():
            e -= 1
        head = lines[s].strip().strip("[]")  # TOML/HCL table headers carry their own brackets
        key = re.split(r"[:=\s]", head, maxsplit=1)[0].strip("\"'") or None
        chunks.append(
            Chunk(path, language, "section", key, s + 1, e + 1, "\n".join(lines[s : e + 1]))
        )
    return _merge_small(chunks)


def _chunk_markdown(path: str, text: str) -> list[Chunk]:
    lines = text.splitlines()
    heads = [i for i, line in enumerate(lines) if line.startswith("#")]
    if not heads:
        return []
    if heads[0] != 0:
        heads.insert(0, 0)
    chunks: list[Chunk] = []
    for idx, s in enumerate(heads):
        e = (heads[idx + 1] - 1) if idx + 1 < len(heads) else len(lines) - 1
        title = lines[s].lstrip("#").strip() or None
        chunks.append(
            Chunk(path, "markdown", "section", title, s + 1, e + 1, "\n".join(lines[s : e + 1]))
        )
    return _merge_small(chunks)


def _chunk_sql(path: str, text: str) -> list[Chunk]:
    lines = text.splitlines()
    starts = [
        i
        for i, line in enumerate(lines)
        if re.match(
            r"^\s*(create|alter|drop|insert|update|delete|select|with|begin|--\s*name:)", line, re.I
        )
    ]
    if not starts:
        return []
    chunks: list[Chunk] = []
    for idx, s in enumerate(starts):
        e = (starts[idx + 1] - 1) if idx + 1 < len(starts) else len(lines) - 1
        m = re.match(
            r"^\s*(?:create|alter|drop)\s+(?:or\s+replace\s+)?(?:table|view|index|function|procedure|type)\s+(?:if\s+(?:not\s+)?exists\s+)?([\w.\"]+)",
            lines[s],
            re.I,
        )
        chunks.append(
            Chunk(
                path,
                "sql",
                "statement",
                m.group(1).strip('"') if m else None,
                s + 1,
                e + 1,
                "\n".join(lines[s : e + 1]),
            )
        )
    return _merge_small(chunks)


def _merge_small(chunks: list[Chunk], min_lines: int = 3) -> list[Chunk]:
    """Merge tiny unnamed fragments into the preceding chunk.

    A chunk that has its own symbol (a heading, a table, a config section) stays separate
    even when short, so it remains addressable by name during retrieval.
    """
    out: list[Chunk] = []
    for c in chunks:
        if (
            out
            and c.symbol is None
            and (c.end_line - c.start_line + 1) < min_lines
            and (out[-1].end_line - out[-1].start_line + 1) < WINDOW_LINES
        ):
            prev = out.pop()
            out.append(
                Chunk(
                    prev.path,
                    prev.language,
                    prev.kind,
                    prev.symbol,
                    prev.start_line,
                    c.end_line,
                    prev.text + "\n" + c.text,
                    prev.parent,
                    prev.signature,
                    prev.imports,
                )
            )
        else:
            out.append(c)
    return out


def _chunk_windows(path: str, text: str, language: str, offset: int = 0) -> list[Chunk]:
    lines = text.splitlines()
    chunks: list[Chunk] = []
    for start in range(0, len(lines), WINDOW_LINES):
        end = min(start + WINDOW_LINES, len(lines))
        body = "\n".join(lines[start:end])
        if body.strip():
            chunks.append(
                Chunk(path, language, "window", None, offset + start + 1, offset + end, body)
            )
    return chunks
