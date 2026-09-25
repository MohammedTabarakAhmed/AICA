// AICA in VS Code (INT-001). A thin surface over `aica serve`: the server applies policy,
// approvals, audit and model routing; the extension shows results where developers work.
//
// Every command also takes its inputs as arguments and returns its result, so the same
// command a developer runs from the palette is the one the integration test drives.

import * as path from "path";
import * as vscode from "vscode";

import { AicaClient, AicaError, ChatResult, FileChange, ReviewReport, TaskEvent, TaskSummary } from "./client";
import { DiagnosticSpec, describeReview, toDiagnostics } from "./findings";

const TOKEN_KEY = "aica.apiToken";
const CHAT_SESSION_KEY = "aica.chatSession";

let diagnostics: vscode.DiagnosticCollection;
let output: vscode.OutputChannel;
let status: vscode.StatusBarItem;
let running: { taskId: string; abort: AbortController } | undefined;
let lastTaskId: string | undefined;

function settings(): vscode.WorkspaceConfiguration {
  return vscode.workspace.getConfiguration("aica");
}

function workspaceRoot(): vscode.Uri | undefined {
  return vscode.workspace.workspaceFolders?.[0]?.uri;
}

async function client(context: vscode.ExtensionContext): Promise<AicaClient> {
  const token = (await context.secrets.get(TOKEN_KEY)) || process.env.AICA_API_TOKEN;
  if (!token) {
    throw new AicaError(0, "No AICA API token set. Run 'AICA: Set API Token' (the token `aica serve` printed).");
  }
  return new AicaClient(settings().get<string>("serverUrl", "http://127.0.0.1:8000"), token);
}

function model(): string | undefined {
  return settings().get<string>("model") || undefined;
}

async function report(err: unknown): Promise<void> {
  if (err instanceof AicaError && err.needsApproval) {
    const choice = await vscode.window.showWarningMessage(
      `Waiting for approval: ${err.detail}`,
      "Open Approvals",
    );
    if (choice) {
      await vscode.commands.executeCommand("aica.approvals");
    }
    return;
  }
  void vscode.window.showErrorMessage(err instanceof Error ? err.message : String(err));
}

/** Wrap a command so a failure is shown to the developer and also returned to a caller. */
function command<A extends unknown[], R>(fn: (...args: A) => Promise<R>): (...args: A) => Promise<R | undefined> {
  return async (...args: A) => {
    try {
      return await fn(...args);
    } catch (err) {
      await report(err);
      return undefined;
    }
  };
}

// ------------------------------------------------------------------ chat (CHAT-001..005)

async function showAnswer(result: ChatResult, question: string): Promise<void> {
  const root = workspaceRoot();
  const sources = result.sources.map((location) => {
    const match = /^(.*?):(\d+)/.exec(location);
    if (!match || !root) {
      return `- ${location}`;
    }
    const target = vscode.Uri.joinPath(root, match[1]).with({ fragment: `L${match[2]}` });
    return `- [${location}](${target.toString()})`;
  });
  const content = [
    `# ${question}`,
    "",
    result.answer,
    "",
    sources.length ? "**Sources**\n" + sources.join("\n") : "_No repository sources were cited._",
    "",
    `_Model: ${result.model} (${result.model_selection}). Session ${result.session_id}._`,
  ].join("\n");
  const doc = await vscode.workspace.openTextDocument({ language: "markdown", content });
  await vscode.window.showTextDocument(doc, { preview: true, viewColumn: vscode.ViewColumn.Beside });
}

async function ask(context: vscode.ExtensionContext, question?: string, selection?: string, newSession = false): Promise<ChatResult | undefined> {
  const q = question ?? (await vscode.window.showInputBox({ prompt: "Ask AICA about this repository" }));
  if (!q) {
    return undefined;
  }
  const api = await client(context);
  const sessionId = newSession ? undefined : context.workspaceState.get<string>(CHAT_SESSION_KEY);
  const result = await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: "AICA is answering..." },
    () => api.chat(q, { context: selection, sessionId, model: model() }),
  );
  await context.workspaceState.update(CHAT_SESSION_KEY, result.session_id);
  if (question === undefined || selection !== undefined) {
    await showAnswer(result, q);
  }
  return result;
}

// ------------------------------------------------------------------ agent tasks (AG-*, UX-*)

function describeEvent(event: TaskEvent): string {
  const step = event.step_number ? `[${event.step_number}${event.total_steps ? `/${event.total_steps}` : ""}] ` : "";
  const tool = event.tool ? ` (${event.tool})` : "";
  return `${step}${event.type}${tool}: ${event.message}`;
}

async function runTask(context: vscode.ExtensionContext, task?: string): Promise<TaskSummary | undefined> {
  if (running) {
    throw new AicaError(0, `A task is already running (${running.taskId}). Cancel it first.`);
  }
  const text = task ?? (await vscode.window.showInputBox({ prompt: "What should the agent do?" }));
  if (!text) {
    return undefined;
  }
  const api = await client(context);
  const started = await api.startTask(text, model());
  const abort = new AbortController();
  running = { taskId: started.task_id, abort };
  lastTaskId = started.task_id;
  output.show(true);
  output.appendLine(`\n=== Task ${started.task_id}: ${text}`);
  status.text = "$(sync~spin) AICA: task running";
  try {
    const final = await vscode.window.withProgress(
      { location: vscode.ProgressLocation.Notification, title: "AICA agent", cancellable: true },
      async (progress, cancel) => {
        cancel.onCancellationRequested(() => void api.cancel(started.task_id));
        return api.streamEvents(
          started.task_id,
          (event) => {
            output.appendLine(describeEvent(event));
            if (event.type === "step_started") {
              progress.report({ message: event.message });
            }
          },
          abort.signal,
        );
      },
    );
    const summary = final ?? (await api.task(started.task_id));
    output.appendLine(`=== ${summary.state}: ${summary.outcome ?? "no outcome"}`);
    const changes = await api.changes(started.task_id);
    const pending = changes.files.filter((f) => f.decision === "pending");
    if (task === undefined) {
      const message = `AICA task ${summary.outcome ?? summary.state}` + (pending.length ? ` - ${pending.length} changed file(s) to review.` : ".");
      const choice = pending.length
        ? await vscode.window.showInformationMessage(message, "Review Changes")
        : await vscode.window.showInformationMessage(message);
      if (choice) {
        await vscode.commands.executeCommand("aica.reviewChanges", started.task_id);
      }
    }
    return summary;
  } finally {
    running = undefined;
    status.text = "$(hubot) AICA";
  }
}

async function cancelTask(context: vscode.ExtensionContext): Promise<boolean> {
  if (!running) {
    void vscode.window.showInformationMessage("No AICA task is running.");
    return false;
  }
  const api = await client(context);
  const result = await api.cancel(running.taskId);
  return result.cancelled;
}

// ------------------------------------------------------------------ accept / reject (CC-005)

type Decision = "all" | "none" | number[];

async function chooseDecision(file: FileChange): Promise<Decision | undefined> {
  const doc = await vscode.workspace.openTextDocument({ language: "diff", content: file.diff });
  await vscode.window.showTextDocument(doc, { preview: true });
  const options = ["Accept all", "Reject all"];
  if (file.hunks && file.hunks.length > 1) {
    options.push("Choose hunks...");
  }
  const pick = await vscode.window.showQuickPick(options, { placeHolder: `${file.path}: ${file.action}` });
  if (pick === "Accept all") {
    return "all";
  }
  if (pick === "Reject all") {
    return "none";
  }
  if (pick === "Choose hunks..." && file.hunks) {
    const chosen = await vscode.window.showQuickPick(
      file.hunks.map((h) => ({
        label: `Hunk ${h.index + 1}`,
        description: `lines ${h.new_start}-${h.new_start + Math.max(h.new_lines - 1, 0)}`,
        index: h.index,
      })),
      { canPickMany: true, placeHolder: "Keep which hunks? The rest are reverted." },
    );
    return chosen ? chosen.map((c) => c.index) : undefined;
  }
  return undefined;
}

async function reviewChanges(
  context: vscode.ExtensionContext,
  taskId?: string,
  decisions?: Record<string, Decision>,
): Promise<Record<string, unknown>[] | undefined> {
  const id = taskId ?? lastTaskId;
  if (!id) {
    throw new AicaError(0, "No AICA task to review yet. Run 'AICA: Run Agent Task' first.");
  }
  const api = await client(context);
  const changes = await api.changes(id);
  const results: Record<string, unknown>[] = [];
  for (const file of changes.files.filter((f) => f.decision === "pending")) {
    if (!file.decidable) {
      void vscode.window.showWarningMessage(
        `${file.path} changed after the task finished; it can no longer be decided here (it will not be overwritten).`,
      );
      continue;
    }
    const decision = decisions ? decisions[file.path] : await chooseDecision(file);
    if (decision === undefined) {
      continue;
    }
    results.push(await api.decide(id, file.path, decision, "decided in VS Code"));
  }
  return results;
}

// ------------------------------------------------------------------ code review (REV-*)

function applyDiagnostics(specs: DiagnosticSpec[]): number {
  diagnostics.clear();
  const root = workspaceRoot();
  if (!root) {
    return 0;
  }
  const byFile = new Map<string, vscode.Diagnostic[]>();
  const levels = {
    error: vscode.DiagnosticSeverity.Error,
    warning: vscode.DiagnosticSeverity.Warning,
    information: vscode.DiagnosticSeverity.Information,
    hint: vscode.DiagnosticSeverity.Hint,
  };
  for (const spec of specs) {
    const range = new vscode.Range(spec.line, 0, spec.endLine, Number.MAX_SAFE_INTEGER);
    const diagnostic = new vscode.Diagnostic(range, spec.message, levels[spec.level]);
    diagnostic.source = spec.source;
    diagnostic.code = spec.code;
    const list = byFile.get(spec.file) ?? [];
    list.push(diagnostic);
    byFile.set(spec.file, list);
  }
  for (const [file, list] of byFile) {
    diagnostics.set(vscode.Uri.joinPath(root, file), list);
  }
  return specs.length;
}

async function reviewWorkingTree(
  context: vscode.ExtensionContext,
  base?: string,
): Promise<{ report: ReviewReport; diagnostics: number; summary: string } | undefined> {
  const api = await client(context);
  const result = await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: "AICA is reviewing your changes..." },
    () => api.review({ base, model: model() }),
  );
  const count = applyDiagnostics(toDiagnostics(result));
  const summary = describeReview(result);
  const show = result.complete ? vscode.window.showInformationMessage : vscode.window.showWarningMessage;
  void show(`AICA review: ${summary}`);
  if (count) {
    await vscode.commands.executeCommand("workbench.actions.view.problems");
  }
  return { report: result, diagnostics: count, summary };
}

// ------------------------------------------------------------------ approvals (API-014, UX-008)

async function approvals(context: vscode.ExtensionContext, decisions?: Record<string, boolean>): Promise<unknown[] | undefined> {
  const api = await client(context);
  const pending = await api.approvals();
  if (decisions) {
    const out: unknown[] = [];
    for (const [id, approved] of Object.entries(decisions)) {
      out.push(await api.decideApproval(id, approved, "decided in VS Code"));
    }
    return out;
  }
  if (!pending.count) {
    void vscode.window.showInformationMessage("No pending AICA approvals.");
    return [];
  }
  const pick = await vscode.window.showQuickPick(
    pending.approvals.map((a, i) => ({ label: pending.summaries[i] ?? a.action, id: a.id })),
    { placeHolder: "Pending approvals - pick one to decide" },
  );
  if (!pick) {
    return undefined;
  }
  const verdict = await vscode.window.showWarningMessage(pick.label, { modal: true }, "Approve", "Reject");
  if (!verdict) {
    return undefined;
  }
  return [await api.decideApproval(pick.id, verdict === "Approve", "decided in VS Code")];
}

// ------------------------------------------------------------------ inline completion (CC-001)

class CompletionProvider implements vscode.InlineCompletionItemProvider {
  constructor(private readonly context: vscode.ExtensionContext) {}

  async provideInlineCompletionItems(
    document: vscode.TextDocument,
    position: vscode.Position,
    _context: vscode.InlineCompletionContext,
    token: vscode.CancellationToken,
  ): Promise<vscode.InlineCompletionItem[]> {
    if (!settings().get<boolean>("inlineCompletion.enabled", false)) {
      return [];
    }
    const delay = settings().get<number>("inlineCompletion.debounceMs", 400);
    await new Promise((resolve) => setTimeout(resolve, delay));
    if (token.isCancellationRequested) {
      return []; // the developer kept typing; this request is stale
    }
    const offset = document.offsetAt(position);
    const text = document.getText();
    const root = workspaceRoot();
    const relative = root ? path.relative(root.fsPath, document.uri.fsPath).split(path.sep).join("/") : undefined;
    try {
      const api = await client(this.context);
      const result = await api.complete(
        text.slice(Math.max(0, offset - 8000), offset),
        text.slice(offset, offset + 2000),
        relative && !relative.startsWith("..") ? relative : undefined,
        model(),
      );
      if (token.isCancellationRequested || !result.completion.trim()) {
        return [];
      }
      return [new vscode.InlineCompletionItem(result.completion, new vscode.Range(position, position))];
    } catch {
      return []; // completion is best effort; errors surface through the explicit commands
    }
  }
}

// ------------------------------------------------------------------ activation

export interface AicaExtensionApi {
  /** Exposed so the integration test can drive the real provider inside VS Code. */
  completionProvider: vscode.InlineCompletionItemProvider;
}

export function activate(context: vscode.ExtensionContext): AicaExtensionApi {
  diagnostics = vscode.languages.createDiagnosticCollection("aica");
  output = vscode.window.createOutputChannel("AICA Agent");
  status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
  status.text = "$(hubot) AICA";
  status.tooltip = "AICA - check the connection to `aica serve`";
  status.command = "aica.checkConnection";
  status.show();

  const register = (name: string, fn: (...args: never[]) => Promise<unknown>) =>
    context.subscriptions.push(vscode.commands.registerCommand(name, command(fn)));

  register("aica.setToken", async (token?: string) => {
    const value = token ?? (await vscode.window.showInputBox({ prompt: "AICA API token (printed by `aica serve`)", password: true }));
    if (!value) {
      return false;
    }
    await context.secrets.store(TOKEN_KEY, value); // SecretStorage, never settings.json
    return true;
  });
  register("aica.checkConnection", async () => {
    const api = await client(context);
    await api.health();
    await api.request("GET", "/policy"); // authenticated: proves the token, not just the port
    void vscode.window.showInformationMessage("AICA server reachable and the token is accepted.");
    return true;
  });
  register("aica.ask", (question?: string, newSession?: boolean) => ask(context, question, undefined, newSession));
  register("aica.explainSelection", async (question?: string) => {
    const editor = vscode.window.activeTextEditor;
    if (!editor || editor.selection.isEmpty) {
      throw new AicaError(0, "Select some code to explain first.");
    }
    const selection = editor.document.getText(editor.selection);
    const where = `${vscode.workspace.asRelativePath(editor.document.uri)}:${editor.selection.start.line + 1}-${editor.selection.end.line + 1}`;
    return ask(context, question ?? `Explain this code (${where})`, selection);
  });
  register("aica.runTask", (task?: string) => runTask(context, task));
  register("aica.cancelTask", () => cancelTask(context));
  register("aica.reviewChanges", (taskId?: string, decisions?: Record<string, Decision>) => reviewChanges(context, taskId, decisions));
  register("aica.reviewWorkingTree", (base?: string) => reviewWorkingTree(context, base));
  register("aica.approvals", (decisions?: Record<string, boolean>) => approvals(context, decisions));

  const completionProvider = new CompletionProvider(context);
  context.subscriptions.push(
    vscode.languages.registerInlineCompletionItemProvider({ pattern: "**" }, completionProvider),
    diagnostics,
    output,
    status,
  );
  return { completionProvider };
}

export function deactivate(): void {
  running?.abort.abort();
}
