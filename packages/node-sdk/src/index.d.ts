// Type definitions for @argus/node.

export interface InitOptions {
  /** Single write-only ingest key ("ak_live_…"). Falls back to process.env.ARGUS_KEY. */
  key?: string;
  /** Legacy public API key. Falls back to process.env.ARGUS_PUBLIC_KEY. */
  publicKey?: string;
  /** Secret API key. Falls back to process.env.ARGUS_SECRET_KEY. */
  secretKey?: string;
  /** Ingestion endpoint. Falls back to process.env.ARGUS_INGEST_URL. */
  ingestUrl?: string;
  /** Environment tag applied to traces. Falls back to process.env.ARGUS_ENV or "production". */
  environment?: string;
  /** Buffer flush interval in ms (default 2000). */
  flushIntervalMs?: number;
  /** Max buffered items before an eager flush (default 100). */
  maxBatchSize?: number;
  /** Auto-patch the `openai` SDK (default true). */
  instrumentOpenAI?: boolean;
  /** Auto-patch the `@anthropic-ai/sdk` SDK (default true). */
  instrumentAnthropic?: boolean;
  /** Auto-patch global fetch (default true). */
  instrumentFetch?: boolean;
  /** Log each captured call (default false). */
  debug?: boolean;
}

export interface SpanOptions {
  /** Parent observation id, for nesting. */
  parentId?: string;
  startTime?: Date | string;
  endTime?: Date | string;
  /** String map of extra attributes. */
  attributes?: Record<string, unknown>;
}

export interface RetrievalOptions extends SpanOptions {
  /** Identifier of the source document/store (defaults to the span name). */
  source?: string;
}

export interface ToolOptions extends SpanOptions {
  input?: unknown;
  output?: unknown;
  source?: string;
}

export interface GenerationOptions extends SpanOptions {
  model?: string;
  provider?: string;
  input?: unknown;
  output?: unknown;
  inputTokens?: number;
  outputTokens?: number;
  /** If omitted, cost is auto-estimated from model + tokens. */
  costUsd?: number;
  finishReason?: string;
}

export interface TraceMeta {
  traceId?: string;
  sessionId?: string;
  userId?: string;
  environment?: string;
  release?: string;
  tags?: string[];
  metadata?: Record<string, unknown>;
}

export interface Trace {
  readonly traceId: string;
  retrieval(name: string, text: unknown, opts?: RetrievalOptions): Trace;
  generation(name: string, opts?: GenerationOptions): Trace;
  tool(name: string, opts?: ToolOptions): Trace;
  span(name: string, opts?: SpanOptions): Trace;
  finish(): void;
}

export interface MiddlewareOptions {
  name?: (req: any) => string;
  getSessionId?: (req: any) => string | undefined;
  getUserId?: (req: any) => string | undefined;
  tags?: (req: any) => string[];
}

export interface ArgusApi {
  /** init("ak_live_…") or init({ key }) or init() to read ARGUS_KEY. */
  init(keyOrOpts?: string | InitOptions): ArgusApi;
  middleware(opts?: MiddlewareOptions): (req: any, res: any, next: any) => void;
  retrieval(name: string, text: unknown, opts?: RetrievalOptions): void;
  tool(name: string, opts?: ToolOptions): void;
  generation(name: string, opts?: GenerationOptions): void;
  annotate(meta: TraceMeta): void;
  trace<T>(name: string, fn: (t: Trace) => T | Promise<T>): Promise<T>;
  trace<T>(name: string, meta: TraceMeta, fn: (t: Trace) => T | Promise<T>): Promise<T>;
  activeTrace(): Trace | null;
  flush(): Promise<void>;
  shutdown(): Promise<void>;
  version: string;
}

declare const api: ArgusApi;
export default api;

export const init: ArgusApi["init"];
export const middleware: ArgusApi["middleware"];
export const retrieval: ArgusApi["retrieval"];
export const tool: ArgusApi["tool"];
export const generation: ArgusApi["generation"];
export const annotate: ArgusApi["annotate"];
export const trace: ArgusApi["trace"];
export const activeTrace: ArgusApi["activeTrace"];
export const flush: ArgusApi["flush"];
export const shutdown: ArgusApi["shutdown"];
export const version: string;
