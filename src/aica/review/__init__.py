"""Code review and quality functions (BRD 11, REV-001..007).

Reviewing a diff, finding likely bugs, checking conventions and test adequacy, a
security pass, and a summary whose every finding points at a line a reviewer can open.

The capability is read-only. It produces a :class:`~aica.review.findings.ReviewReport`;
acting on it - editing, staging, committing - stays with the tools that have the guards
and the approval gates for it.
"""

from aica.review.adequacy import FileAdequacy
from aica.review.diff import ChangedFile, ParsedDiff, parse_diff
from aica.review.findings import (
    Category,
    DroppedFinding,
    Finding,
    ReviewReport,
    Severity,
)
from aica.review.reviewer import (
    DEFAULT_CHECKS,
    CodeReviewer,
    ReviewCheck,
    ReviewRequest,
)

__all__ = [
    "DEFAULT_CHECKS",
    "Category",
    "ChangedFile",
    "CodeReviewer",
    "DroppedFinding",
    "FileAdequacy",
    "Finding",
    "ParsedDiff",
    "ReviewCheck",
    "ReviewReport",
    "ReviewRequest",
    "Severity",
    "parse_diff",
]
