// Review findings -> editor diagnostics (REV-007 source locations, CHAT-007 findings).
// Pure: returns plain data; extension.ts turns it into vscode.Diagnostic objects.

import type { Finding, ReviewReport } from "./client";

export type Level = "error" | "warning" | "information" | "hint";

export interface DiagnosticSpec {
  file: string;
  line: number; // zero-based, as the editor counts
  endLine: number;
  level: Level;
  message: string;
  source: string;
  code: string;
}

const LEVELS: Record<string, Level> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "information",
  info: "hint",
};

export function toDiagnostics(report: ReviewReport): DiagnosticSpec[] {
  return report.findings
    .filter((f): f is Finding & { line: number } => typeof f.line === "number" && f.line > 0)
    .map((f) => ({
      file: f.file,
      line: f.line - 1,
      endLine: Math.max((f.end_line ?? f.line) - 1, f.line - 1),
      level: LEVELS[f.severity] ?? "warning",
      message: f.suggestion ? `${f.title}: ${f.detail}\nSuggestion: ${f.suggestion}` : `${f.title}: ${f.detail}`,
      source: `aica review (${f.origin})`,
      code: `${f.severity}/${f.category}`,
    }));
}

/**
 * What the status line should say. An incomplete review must never read as a clean one
 * (TEST-009): zero findings from a review whose checks failed means nothing.
 */
export function describeReview(report: ReviewReport): string {
  const failed = Array.isArray(report.checks_failed)
    ? report.checks_failed
    : Object.keys(report.checks_failed ?? {});
  const count = report.findings.length;
  const base = `${count} finding${count === 1 ? "" : "s"}${report.model ? ` (model ${report.model})` : " (static checks only)"}`;
  if (!report.complete) {
    const why = failed.length ? `: ${failed.join(", ")} did not run` : "";
    return `INCOMPLETE review - ${base}${why}. No findings here does not mean the change is clean.`;
  }
  return report.truncated ? `${base}; the diff was truncated, so part of it was not reviewed.` : base;
}
