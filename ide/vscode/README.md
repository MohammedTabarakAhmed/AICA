# AICA for VS Code (INT-001)

The AICA agent inside VS Code. The extension is a thin surface over a local `aica serve`:
policy, approvals, audit and model routing all stay on the server, so the IDE can never do
anything the CLI or the web app would not be allowed to.

## Setup

1. Start the server in your repository: `aica serve` (it listens on `127.0.0.1:8000` and
   prints an API token; or set `AICA_API_TOKEN` first to choose one).
2. In VS Code: **AICA: Set API Token** and paste it. It is kept in VS Code's SecretStorage,
   never in `settings.json`.
3. **AICA: Check Connection** confirms the server is reachable and the token is accepted.

## Commands

| Command | What it does | BRD |
|---|---|---|
| AICA: Ask About the Repository | Answer with clickable `file:line` sources; follow-ups continue the conversation | CHAT-001..005 |
| AICA: Explain Selection (also in the editor context menu) | Explain the selected code; the selection is sent as untrusted content | CHAT-001 |
| AICA: Run Agent Task | Plan, execute and verify, with live progress in the "AICA Agent" output; cancellable | AG-*, UX-001..003 |
| AICA: Review Task Changes | Accept all, reject all, or keep chosen hunks of each file the agent changed | CC-005 |
| AICA: Review Working Tree | Findings appear in the Problems panel at their lines; an incomplete review says so | REV-*, CHAT-007 |
| AICA: Pending Approvals | Approve or reject actions waiting for a person | API-014, UX-008 |

Inline completion (CC-001) is **off by default**, because every pause in typing is a model call.
Turn it on with `aica.inlineCompletion.enabled`.

## Settings

- `aica.serverUrl`: default `http://127.0.0.1:8000`. Keep it on loopback unless the server has TLS.
- `aica.model`: request a model by name. Empty lets the server's routing rules choose.
- `aica.inlineCompletion.enabled` / `aica.inlineCompletion.debounceMs`

## Development

```
npm install
npm run test:unit          # client, event stream and findings mapping (node:test)
npm run test:integration   # real VS Code + real `aica serve` (scripted model), isolated profile
npm run package            # builds aica-vscode-<version>.vsix
```
