// Runs inside the VS Code extension host. No test framework dependency: each check is an
// async function, run in order (they share one server and one workspace), and the first
// failure fails the run with its message.

import assert from "node:assert/strict";
import * as fs from "fs";
import * as path from "path";
import * as vscode from "vscode";

import type { AicaExtensionApi } from "../../../src/extension";

const EXTENSION_ID = "aica-local.aica-vscode";
const workspace = process.env.AICA_TEST_WORKSPACE ?? "";

type Check = [string, () => Promise<void>];

let chatSession = "";
let taskId = "";

const checks: Check[] = [
  ["the extension activates and registers its commands", async () => {
    const ext = vscode.extensions.getExtension<AicaExtensionApi>(EXTENSION_ID);
    assert.ok(ext, "extension not found");
    await ext.activate();
    const commands = await vscode.commands.getCommands(true);
    for (const name of ["aica.ask", "aica.runTask", "aica.reviewChanges", "aica.reviewWorkingTree", "aica.approvals"]) {
      assert.ok(commands.includes(name), `${name} not registered`);
    }
  }],

  ["a missing token is refused with guidance, not a crash", async () => {
    const result = await vscode.commands.executeCommand("aica.checkConnection");
    assert.equal(result, undefined); // reported to the user, returned as no result
  }],

  ["the token goes to SecretStorage and the connection is authenticated", async () => {
    assert.equal(await vscode.commands.executeCommand("aica.setToken", process.env.AICA_TEST_TOKEN), true);
    assert.equal(await vscode.commands.executeCommand("aica.checkConnection"), true);
    const settings = fs.readFileSync(path.join(workspace, ".vscode", "settings.json"), "utf8");
    assert.ok(!settings.includes(process.env.AICA_TEST_TOKEN ?? "~"), "token must never land in settings.json");
  }],

  ["ask answers from the repository and keeps the conversation (CHAT-001..005)", async () => {
    const first = await vscode.commands.executeCommand<{ answer: string; session_id: string }>(
      "aica.ask", "What does apply_discount do?", true,
    );
    assert.ok(first, "no answer");
    assert.match(first.answer, /percentage of the price/);
    const second = await vscode.commands.executeCommand<{ session_id: string }>("aica.ask", "And for 100%?");
    assert.equal(second?.session_id, first.session_id, "follow-up should continue the session");
    chatSession = first.session_id;
  }],

  ["explain selection sends the selected code", async () => {
    const doc = await vscode.workspace.openTextDocument(path.join(workspace, "src", "pricing.py"));
    const editor = await vscode.window.showTextDocument(doc);
    editor.selection = new vscode.Selection(0, 0, 2, 40);
    const result = await vscode.commands.executeCommand<{ session_id: string }>("aica.explainSelection");
    assert.ok(result?.session_id, "no answer for the selection");
    assert.equal(result.session_id, chatSession);
  }],

  ["the working-tree review lands in the Problems panel (REV-*, CHAT-007)", async () => {
    const result = await vscode.commands.executeCommand<{ diagnostics: number; summary: string }>("aica.reviewWorkingTree");
    assert.ok(result && result.diagnostics > 0, `expected findings, got ${JSON.stringify(result)}`);
    const uri = vscode.Uri.file(path.join(workspace, "src", "users.py"));
    const found = vscode.languages.getDiagnostics(uri);
    const sql = found.find((d) => /SQL/i.test(d.message));
    assert.ok(sql, `no SQL finding on users.py: ${found.map((d) => d.message).join(" | ")}`);
    assert.equal(sql.severity, vscode.DiagnosticSeverity.Error);
    assert.equal(sql.range.start.line, 1, "the finding should point at line 2 (zero-based 1)");
  }],

  ["an agent task runs to the end with its events streamed (AG-*, UX-001..003)", async () => {
    const summary = await vscode.commands.executeCommand<{ task_id: string; state: string }>(
      "aica.runTask", "Fix the percentage arithmetic in src/pricing.py",
    );
    assert.ok(summary, "no task summary");
    assert.notEqual(summary.state, "running");
    taskId = summary.task_id;
    const edited = fs.readFileSync(path.join(workspace, "src", "pricing.py"), "utf8");
    assert.match(edited, /percent \/ 100/, "the agent's edit should be on disk before review");
  }],

  ["rejecting the task's change reverts the file (CC-005)", async () => {
    const results = await vscode.commands.executeCommand<Record<string, unknown>[]>(
      "aica.reviewChanges", taskId, { "src/pricing.py": "none" },
    );
    assert.equal(results?.length, 1, `expected one decision, got ${JSON.stringify(results)}`);
    const reverted = fs.readFileSync(path.join(workspace, "src", "pricing.py"), "utf8");
    assert.match(reverted, /price - price \* percent\n/, "rejected change must be reverted");
    const again = await vscode.commands.executeCommand<Record<string, unknown>[]>(
      "aica.reviewChanges", taskId, { "src/pricing.py": "all" },
    );
    assert.equal(again?.length, 0, "a decision is final; nothing should remain to decide");
  }],

  ["a pending approval can be decided from the IDE (API-014, UX-008)", async () => {
    const id = process.env.AICA_TEST_APPROVAL_ID ?? "";
    const results = await vscode.commands.executeCommand<Array<{ state?: string }>>("aica.approvals", { [id]: false });
    assert.equal(results?.length, 1);
    assert.equal(results?.[0]?.state, "rejected");
  }],

  ["inline completion is off by default and answers when enabled (CC-001)", async () => {
    const ext = vscode.extensions.getExtension<AicaExtensionApi>(EXTENSION_ID);
    const provider = ext?.exports.completionProvider;
    assert.ok(provider, "provider not exported");
    const doc = await vscode.workspace.openTextDocument(path.join(workspace, "src", "pricing.py"));
    const position = new vscode.Position(2, 11);
    const trigger = { triggerKind: vscode.InlineCompletionTriggerKind.Invoke, selectedCompletionInfo: undefined };
    const token = new vscode.CancellationTokenSource().token;
    const off = await provider.provideInlineCompletionItems(doc, position, trigger, token);
    assert.deepEqual(off, [], "disabled by default");
    await vscode.workspace.getConfiguration("aica").update("inlineCompletion.debounceMs", 100, vscode.ConfigurationTarget.Workspace);
    await vscode.workspace.getConfiguration("aica").update("inlineCompletion.enabled", true, vscode.ConfigurationTarget.Workspace);
    const on = (await provider.provideInlineCompletionItems(doc, position, trigger, token)) as vscode.InlineCompletionItem[];
    assert.equal(on.length, 1, "expected one completion when enabled");
    assert.ok(String(on[0].insertText).length > 0);
  }],
];

export async function run(): Promise<void> {
  const failures: string[] = [];
  for (const [name, check] of checks) {
    try {
      await check();
      console.log(`  ok   ${name}`);
    } catch (err) {
      console.log(`  FAIL ${name}\n       ${err instanceof Error ? err.message : String(err)}`);
      failures.push(name);
      break; // later checks depend on earlier ones; stop at the first failure
    }
  }
  if (failures.length) {
    throw new Error(`${failures.length} integration check(s) failed: ${failures.join("; ")}`);
  }
  console.log(`  all ${checks.length} integration checks passed`);
}
