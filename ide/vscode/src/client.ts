// HTTP client for `aica serve` (INT-001). No VS Code dependency, so it is unit-tested alone.
// Every call carries the bearer token; the server enforces policy, approvals and audit -
// the extension is a surface, never a second place where decisions are made.

import { SseParser } from "./sse";

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export class AicaError extends Error {
  constructor(
    readonly status: number,
    readonly detail: string,
  ) {
    super(status ? `AICA server ${status}: ${detail}` : detail);
  }

  /** 409 means "refused pending a human decision" (API-014), not a failure of the call. */
  get needsApproval(): boolean {
    return this.status === 409;
  }
}

export interface ChatResult {
  session_id: string;
  answer: string;
  model: string;
  sources: string[];
  model_selection: string;
}

export interface TaskSummary {
  task_id: string;
  session_id: string;
  task: string;
  state: string;
  outcome: string | null;
  succeeded: boolean | null;
}

export interface TaskEvent {
  type: string;
  message: string;
  step_number: number | null;
  total_steps: number | null;
  tool: string | null;
  status: string | null;
  data: Record<string, unknown>;
}

export interface Hunk {
  index: number;
  old_start: number;
  old_lines: number;
  new_start: number;
  new_lines: number;
}

export interface FileChange {
  path: string;
  action: string;
  diff: string;
  decision: string;
  decidable: boolean;
  unchanged_since_task: boolean;
  hunks: Hunk[] | null;
}

export interface Finding {
  file: string;
  line: number | null;
  end_line: number | null;
  severity: string;
  category: string;
  title: string;
  detail: string;
  suggestion: string;
  origin: string;
}

export interface ReviewReport {
  complete: boolean;
  truncated: boolean;
  model: string | null;
  summary: string;
  checks_failed: Record<string, string> | string[];
  findings: Finding[];
  model_selection?: string;
}

export interface Approval {
  id: string;
  tool: string;
  action: string;
  categories: string[];
}

export class AicaClient {
  constructor(
    private readonly baseUrl: string,
    private readonly token: string | undefined,
    private readonly fetchImpl: FetchLike = fetch,
  ) {}

  private url(path: string): string {
    return this.baseUrl.replace(/\/+$/, "") + path;
  }

  private headers(json: boolean): Record<string, string> {
    const headers: Record<string, string> = {};
    if (this.token) {
      headers["Authorization"] = `Bearer ${this.token}`;
    }
    if (json) {
      headers["Content-Type"] = "application/json";
    }
    return headers;
  }

  async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    let response: Response;
    try {
      response = await this.fetchImpl(this.url(path), {
        method,
        headers: this.headers(body !== undefined),
        body: body === undefined ? undefined : JSON.stringify(body),
      });
    } catch (err) {
      throw new AicaError(0, `cannot reach the AICA server at ${this.baseUrl} (is \`aica serve\` running?): ${String(err)}`);
    }
    const text = await response.text();
    if (!response.ok) {
      let detail = text;
      try {
        const parsed = JSON.parse(text) as { detail?: unknown };
        if (parsed.detail !== undefined) {
          detail = typeof parsed.detail === "string" ? parsed.detail : JSON.stringify(parsed.detail);
        }
      } catch {
        // not JSON; keep the raw text
      }
      throw new AicaError(response.status, detail);
    }
    return (text ? JSON.parse(text) : {}) as T;
  }

  health(): Promise<{ status: string }> {
    return this.request("GET", "/health");
  }

  chat(question: string, options: { context?: string; sessionId?: string; model?: string } = {}): Promise<ChatResult> {
    return this.request("POST", "/chat", {
      question,
      context: options.context ?? "",
      session_id: options.sessionId,
      model: options.model || undefined,
    });
  }

  complete(prefix: string, suffix: string, path?: string, model?: string): Promise<{ completion: string; model: string }> {
    return this.request("POST", "/complete", { prefix, suffix, path, model: model || undefined });
  }

  async startTask(task: string, model?: string): Promise<TaskSummary> {
    const session = await this.request<{ session_id: string }>("POST", "/sessions", { title: task.slice(0, 80) });
    return this.request("POST", `/sessions/${session.session_id}/tasks`, { task, model: model || undefined });
  }

  task(taskId: string): Promise<TaskSummary> {
    return this.request("GET", `/tasks/${taskId}`);
  }

  cancel(taskId: string): Promise<{ cancelled: boolean }> {
    return this.request("POST", `/tasks/${taskId}/cancel`);
  }

  changes(taskId: string): Promise<{ state: string; files: FileChange[] }> {
    return this.request("GET", `/tasks/${taskId}/changes`);
  }

  decide(taskId: string, path: string, accept: "all" | "none" | number[], note = ""): Promise<Record<string, unknown>> {
    return this.request("POST", `/tasks/${taskId}/changes/decide`, { path, accept, note });
  }

  review(options: { base?: string; model?: string } = {}): Promise<ReviewReport> {
    return this.request("POST", "/review", { base: options.base, model: options.model || undefined });
  }

  approvals(): Promise<{ count: number; approvals: Approval[]; summaries: string[] }> {
    return this.request("GET", "/approvals");
  }

  decideApproval(id: string, approved: boolean, note = ""): Promise<Record<string, unknown>> {
    return this.request("POST", `/approvals/${id}`, { approved, note });
  }

  /**
   * Stream a task's events until the server closes the stream. Calls ``onEvent`` for each
   * agent event and resolves with the final task summary (the server's closing "state" event).
   */
  async streamEvents(taskId: string, onEvent: (event: TaskEvent) => void, signal?: AbortSignal): Promise<TaskSummary | undefined> {
    const response = await this.fetchImpl(this.url(`/tasks/${taskId}/events`), {
      headers: this.headers(false),
      signal,
    });
    if (!response.ok || !response.body) {
      throw new AicaError(response.status, await response.text());
    }
    const parser = new SseParser();
    const decoder = new TextDecoder();
    let final: TaskSummary | undefined;
    const reader = response.body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      for (const sse of parser.push(decoder.decode(value, { stream: true }))) {
        const payload = JSON.parse(sse.data) as unknown;
        if (sse.event === "state") {
          final = payload as TaskSummary;
        } else {
          onEvent(payload as TaskEvent);
        }
      }
    }
    return final;
  }
}
