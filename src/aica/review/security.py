"""Security-oriented review (REV-005): deterministic weakness patterns on added lines.

REV-005 is a *Should*, and the honest way to implement it is in two layers rather than
one. This module is the layer that does not need a model: a pattern set for the weakness
classes that are recognisable from a single added line - injected SQL and shell, disabled
TLS verification, weak hashes, hardcoded credentials, unsafe deserialisation, dangerous
evaluation. Each pattern carries the CWE it corresponds to, so a finding names a known
class instead of an opinion.

Two deliberate limits:

* **Only added lines are scanned.** A weakness that a change did not introduce is not
  this change's finding; reporting the whole file's history as a review of the diff
  would bury the part the author can act on. (Existing debt is a repository scan, which
  is SEC-002 territory, not REV-005.)
* **Patterns are suppressed inside tests and where the line marks itself as intentional**
  (``# nosec``, ``# noqa: S``), because a review that cannot be silenced gets ignored
  wholesale rather than per-line.

The model layer in :mod:`aica.review.reviewer` sees these findings and is asked for the
weaknesses a regex cannot see - missing authorisation, a check that runs after the
effect it guards, a value crossing a trust boundary unvalidated.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from aica.review.diff import ChangedFile, ParsedDiff
from aica.review.findings import Category, Finding, Severity

_SUPPRESSED = re.compile(r"#\s*(nosec|noqa:\s*S\d|nolint)|//\s*nosec|/\*\s*nosec")


@dataclass(frozen=True)
class Weakness:
    name: str
    cwe: str
    severity: Severity
    pattern: re.Pattern[str]
    detail: str
    suggestion: str
    languages: frozenset[str] | None = None  # None = every language


def _p(expr: str) -> re.Pattern[str]:
    return re.compile(expr)


WEAKNESSES: tuple[Weakness, ...] = (
    Weakness(
        name="SQL built by string interpolation",
        cwe="CWE-89",
        severity=Severity.CRITICAL,
        pattern=_p(
            r"(?i)(execute|executemany|query|raw|cursor\.\w+)\s*\(\s*"
            r"(f[\"']|[\"'][^\"']*[\"']\s*[%+]|[\"'][^\"']*\{)"
            r"|(select|insert|update|delete)\b[^\n]*[\"']\s*[%+]\s*\w"
        ),
        detail=(
            "The statement is assembled from a formatted string, so any value reaching it "
            "becomes SQL rather than data."
        ),
        suggestion="Pass values as bound parameters instead of formatting them into the SQL.",
    ),
    Weakness(
        name="Shell command built from a variable",
        cwe="CWE-78",
        severity=Severity.CRITICAL,
        pattern=_p(
            r"(?i)(os\.system|os\.popen|subprocess\.\w+\s*\([^)]*shell\s*=\s*True"
            r"|child_process\.exec\s*\(|Runtime\.getRuntime\(\)\.exec)"
        ),
        detail="A shell is invoked with a constructed command line, so metacharacters execute.",
        suggestion="Pass an argument list without a shell, or validate against an allowlist.",
    ),
    Weakness(
        name="Dynamic evaluation of a value",
        cwe="CWE-95",
        severity=Severity.HIGH,
        pattern=_p(r"(?<![\w.])(eval|exec)\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*[\"']"),
        detail="Evaluating a constructed string executes whatever produced it.",
        suggestion="Replace evaluation with an explicit dispatch over known cases.",
    ),
    Weakness(
        name="Unsafe deserialisation",
        cwe="CWE-502",
        severity=Severity.HIGH,
        pattern=_p(
            r"(?<![\w.])(pickle|cPickle|dill)\.loads?\s*\(|yaml\.load\s*\((?![^)]*SafeLoader)"
            r"|marshal\.loads\s*\(|ObjectInputStream\s*\("
        ),
        detail="Deserialising untrusted bytes can construct arbitrary objects and run code.",
        suggestion="Use a data-only format, or yaml.safe_load / an allowlisted decoder.",
    ),
    Weakness(
        name="TLS certificate verification disabled",
        cwe="CWE-295",
        severity=Severity.HIGH,
        pattern=_p(
            # nosec - these are the patterns themselves, not a disabled check
            r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false"  # nosec
            r"|CERT_NONE|InsecureRequestWarning|check_hostname\s*=\s*False"  # nosec
            r"|NODE_TLS_REJECT_UNAUTHORIZED"  # nosec
        ),
        detail="Without certificate verification the connection is not authenticated.",
        suggestion="Keep verification on; pin or install the CA bundle the endpoint needs.",
    ),
    Weakness(
        name="Broken hash used for security",
        cwe="CWE-327",
        severity=Severity.MEDIUM,
        pattern=_p(r"(?i)\b(md5|sha1)\s*\(|hashlib\.(md5|sha1)\b|\"(md5|sha-?1)\""),
        detail="MD5 and SHA-1 are collision-broken and unsuitable for signatures or passwords.",
        suggestion="Use SHA-256 for integrity, or argon2/bcrypt/scrypt for passwords.",
    ),
    Weakness(
        name="Credential written into the source",
        cwe="CWE-798",
        severity=Severity.CRITICAL,
        pattern=_p(
            r"(?i)(api[_-]?key|secret|token|password|passwd|private[_-]?key|access[_-]?key)"
            r"\s*[:=]\s*[\"'][^\"'\s]{8,}[\"']"
        ),
        detail="A literal credential in source is shared with everyone who can read the repository.",
        suggestion="Read it from the environment or the approved secret store (BRD 16).",
    ),
    Weakness(
        name="Path built from an unvalidated value",
        cwe="CWE-22",
        severity=Severity.HIGH,
        pattern=_p(
            r"(open|readFile|readFileSync|sendFile|Path)\s*\([^)]*(\+|%|\bf[\"'])[^)]*"
            r"(request|req\.|params|query|argv|input)"
        ),
        detail="A caller-supplied component in a path can escape the intended directory.",
        suggestion="Resolve the path and confirm it stays inside the authorized root.",
    ),
    Weakness(
        name="HTML assembled from a value",
        cwe="CWE-79",
        severity=Severity.HIGH,
        pattern=_p(r"innerHTML\s*=|dangerouslySetInnerHTML|document\.write\s*\(|v-html\s*="),
        detail="Assigning markup from a value executes any script it carries.",
        suggestion="Set text content, or escape through the framework's own binding.",
        languages=frozenset({"js", "jsx", "ts", "tsx", "vue", "html"}),
    ),
    Weakness(
        name="Predictable randomness in a security context",
        cwe="CWE-338",
        severity=Severity.MEDIUM,
        pattern=_p(
            r"(?i)(random\.(random|randint|choice|randrange)|Math\.random)\s*\([^)]*\)"
            r"[^\n]*(token|secret|password|nonce|salt|key|session)"
            r"|(token|secret|password|nonce|salt|key)[^\n]*"
            r"(random\.(random|randint|choice|randrange)|Math\.random)\s*\("
        ),
        detail="A general-purpose PRNG is predictable and must not generate secrets.",
        suggestion="Use secrets / crypto.randomBytes / SecureRandom.",
    ),
    Weakness(
        name="Exception swallowed silently",
        cwe="CWE-390",
        severity=Severity.LOW,
        pattern=_p(r"except\s*(\w+\s*)?:\s*pass\b|catch\s*\([^)]*\)\s*\{\s*\}"),
        detail="A discarded error hides the failure it reports, including a security failure.",
        suggestion="Log the error, or narrow the handler to the case that is genuinely expected.",
    ),
)


def scan_file(changed: ChangedFile) -> list[Finding]:
    """Weakness findings for the lines ``changed`` added. Tests are skipped."""
    if changed.is_test or not changed.is_source:
        return []
    language = changed.language
    out: list[Finding] = []
    for line in changed.added_lines:
        text = line.text
        if not text.strip() or _SUPPRESSED.search(text):
            continue
        for weakness in WEAKNESSES:
            if weakness.languages is not None and language not in weakness.languages:
                continue
            if weakness.pattern.search(text):
                out.append(
                    Finding(
                        file=changed.path,
                        line=line.number,
                        severity=weakness.severity,
                        category=Category.SECURITY,
                        title=f"{weakness.name} ({weakness.cwe})",
                        detail=weakness.detail,
                        suggestion=weakness.suggestion,
                        code=text.strip(),
                        origin="security-scan",
                        model=None,
                    )
                )
                break  # one finding per line: the first match is the one to fix
    return out


def scan(parsed: ParsedDiff) -> list[Finding]:
    return [finding for changed in parsed.files for finding in scan_file(changed)]


def render(findings: list[Finding]) -> str:
    """The static findings as a prompt block, so the model adds to them rather than repeating."""
    if not findings:
        return (
            "A static weakness scan of the added lines found nothing. That covers only "
            "single-line patterns; look for weaknesses that span lines or depend on context."
        )
    lines = ["A static weakness scan already found these, so do not repeat them:"]
    lines.extend(f"- {f.location}: {f.title}" for f in findings)
    lines.append("Look for weaknesses a single-line pattern cannot see.")
    return "\n".join(lines)
