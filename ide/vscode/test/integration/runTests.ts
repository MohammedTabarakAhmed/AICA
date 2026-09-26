// Launches the real VS Code with this extension against a real `aica serve` (INT-001).
//
// - The workspace is a throwaway git repository with a planted bug and a planted SQL
//   injection, so the agent, the review and the diagnostics have real work.
// - VS Code runs with its own user-data and extensions directories, so the developer's
//   profile, settings and extensions are never touched.
// - VS Code: AICA_VSCODE_EXECUTABLE, else the local install; set AICA_VSCODE_DOWNLOAD=1 to
//   let @vscode/test-electron download a test copy instead.

import { ChildProcess, execFileSync, spawn } from "child_process";
import * as crypto from "crypto";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { runTests } from "@vscode/test-electron";

const EXTENSION_ROOT = path.resolve(__dirname, "../../..");
const REPO_ROOT = path.resolve(EXTENSION_ROOT, "../..");

function python(): string {
  if (process.env.AICA_PYTHON) {
    return process.env.AICA_PYTHON;
  }
  const win = path.join(REPO_ROOT, ".venv", "Scripts", "python.exe");
  return fs.existsSync(win) ? win : path.join(REPO_ROOT, ".venv", "bin", "python");
}

function vscodeExecutable(): string | undefined {
  if (process.env.AICA_VSCODE_DOWNLOAD === "1") {
    return undefined;
  }
  if (process.env.AICA_VSCODE_EXECUTABLE) {
    return process.env.AICA_VSCODE_EXECUTABLE;
  }
  const local = path.join(os.homedir(), "AppData", "Local", "Programs", "Microsoft VS Code", "Code.exe");
  return fs.existsSync(local) ? local : undefined;
}

function git(cwd: string, ...args: string[]): void {
  execFileSync("git", args, { cwd, stdio: "ignore" });
}

function makeWorkspace(root: string, serverUrl: string): void {
  fs.mkdirSync(path.join(root, "src"), { recursive: true });
  fs.mkdirSync(path.join(root, ".vscode"), { recursive: true });
  fs.writeFileSync(
    path.join(root, "src", "pricing.py"),
    'def apply_discount(price, percent):\n    """Return price reduced by percent (0-100)."""\n    return price - price * percent\n',
  );
  fs.writeFileSync(
    path.join(root, "policy.toml"),
    'version = 1\n[autonomy]\nallowed_tools = ["filesystem", "git", "tests", "rag"]\n[network]\nmode = "deny"\n[git]\nprotected_branches = []\n',
  );
  fs.writeFileSync(path.join(root, ".vscode", "settings.json"), JSON.stringify({ "aica.serverUrl": serverUrl }, null, 2));
  fs.writeFileSync(path.join(root, ".gitignore"), ".aica/\n.vscode/\n");
  git(root, "init", "-q", "-b", "work");
  git(root, "config", "user.email", "t@example.com");
  git(root, "config", "user.name", "t");
  git(root, "add", ".");
  git(root, "commit", "-q", "-m", "init");
  // Uncommitted, so the working-tree review sees it: a real CWE-89 for the static check.
  fs.writeFileSync(
    path.join(root, "src", "users.py"),
    'def find(cursor, user_id):\n    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n    return cursor.fetchone()\n',
  );
}

function startServer(workspace: string, port: number, token: string): Promise<{ proc: ChildProcess; approvalId: string }> {
  const script = path.join(EXTENSION_ROOT, "test", "fixture_server.py");
  const proc = spawn(python(), [script, "--workspace", workspace, "--port", String(port), "--token", token], {
    cwd: REPO_ROOT,
    stdio: ["ignore", "pipe", "pipe"],
  });
  return new Promise((resolve, reject) => {
    let out = "";
    const timer = setTimeout(() => reject(new Error(`server did not start:\n${out}`)), 60_000);
    const onData = (chunk: Buffer) => {
      out += chunk.toString();
      const match = /READY (\w+)/.exec(out);
      if (match) {
        clearTimeout(timer);
        resolve({ proc, approvalId: match[1] });
      }
    };
    proc.stdout?.on("data", onData);
    proc.stderr?.on("data", (chunk: Buffer) => (out += chunk.toString()));
    proc.on("exit", (code) => reject(new Error(`server exited (${code}):\n${out}`)));
  });
}

async function waitForHealth(url: string): Promise<void> {
  for (let i = 0; i < 100; i++) {
    try {
      if ((await fetch(`${url}/health`)).ok) {
        return;
      }
    } catch {
      // not listening yet
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error("server never became healthy");
}

async function main(): Promise<void> {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "aica-vscode-it-"));
  const workspace = path.join(scratch, "workspace");
  const port = 18000 + Math.floor(Math.random() * 2000);
  const url = `http://127.0.0.1:${port}`;
  const token = crypto.randomBytes(24).toString("hex");
  makeWorkspace(workspace, url);
  const { proc, approvalId } = await startServer(workspace, port, token);
  let code = 1;
  try {
    await waitForHealth(url);
    await runTests({
      vscodeExecutablePath: vscodeExecutable(),
      extensionDevelopmentPath: EXTENSION_ROOT,
      extensionTestsPath: path.join(__dirname, "suite", "index.js"),
      launchArgs: [
        workspace,
        "--user-data-dir", path.join(scratch, "user-data"),
        "--extensions-dir", path.join(scratch, "extensions"),
        "--disable-workspace-trust",
        "--disable-extensions",
        "--skip-welcome",
        "--skip-release-notes",
      ],
      extensionTestsEnv: {
        AICA_TEST_TOKEN: token,
        AICA_TEST_APPROVAL_ID: approvalId,
        AICA_TEST_WORKSPACE: workspace,
      },
    });
    code = 0;
  } catch (err) {
    console.error("integration tests failed:", err);
  } finally {
    proc.kill();
  }
  process.exit(code);
}

void main();
