import { K8sStatusError } from "./gvr-client";
import type { K8sObject, Status, WatchEvent } from "./k8s-types";
import type { WatchTransport, WatchTransportRequest } from "./watch-transport";

export const WATCH_MULTIPLEXER_PATH = "/console/watch";
export const WATCH_WEBSOCKET_PROTOCOL = "apoxy.watch.v1";
export const WATCH_BEARER_PROTOCOL_PREFIX = "apoxy.authorization.bearer.";

const CONNECTING = 0;
const OPEN = 1;

interface WatchSocket {
  readonly readyState: number;
  readonly protocol: string;
  onopen: (() => void) | null;
  onmessage: ((event: { data: unknown }) => void) | null;
  onerror: (() => void) | null;
  onclose: ((event: { code?: number; reason?: string }) => void) | null;
  send(data: string): void;
  close(code?: number, reason?: string): void;
}

export type WatchSocketFactory = (
  url: string,
  protocols: string[],
) => WatchSocket;

export interface WebSocketWatchTransportOptions {
  endpointPath?: string;
  webSocketFactory?: WatchSocketFactory;
}

type ServerMessage =
  | { type: "start"; id: string; status: number }
  | { type: "data"; id: string; data: string }
  | { type: "complete"; id: string }
  | { type: "error"; id?: string; status: number; error?: Status };

class AsyncEventQueue<T> {
  private values: T[] = [];
  private waiters: Array<{
    resolve: (result: IteratorResult<T>) => void;
    reject: (error: unknown) => void;
  }> = [];
  private ended = false;
  private error: unknown;

  push(value: T): void {
    if (this.ended) return;
    const waiter = this.waiters.shift();
    if (waiter) waiter.resolve({ done: false, value });
    else this.values.push(value);
  }

  finish(): void {
    if (this.ended) return;
    this.ended = true;
    for (const waiter of this.waiters.splice(0))
      waiter.resolve({ done: true, value: undefined });
  }

  fail(error: unknown): void {
    if (this.ended) return;
    this.ended = true;
    this.error = error;
    for (const waiter of this.waiters.splice(0)) waiter.reject(error);
  }

  next(): Promise<IteratorResult<T>> {
    if (this.values.length > 0)
      return Promise.resolve({ done: false, value: this.values.shift()! });
    if (this.error !== undefined) return Promise.reject(this.error);
    if (this.ended) return Promise.resolve({ done: true, value: undefined });
    return new Promise((resolve, reject) =>
      this.waiters.push({ resolve, reject }),
    );
  }
}

class LogicalWatch<T extends K8sObject = K8sObject> {
  readonly queue = new AsyncEventQueue<WatchEvent<T>>();
  private readonly decoder = new TextDecoder();
  private text = "";
  private status = 0;

  start(status: number): void {
    this.status = status;
  }

  data(encoded: string): void {
    const bytes = decodeBase64(encoded);
    this.text += this.decoder.decode(bytes, { stream: true });
    if (this.successful) this.drainLines();
  }

  complete(): void {
    this.text += this.decoder.decode();
    if (!this.successful) {
      const status = parseStatus(this.text, this.status || 500);
      this.queue.fail(
        new K8sStatusError(status, this.status || status.code || 500),
      );
      return;
    }
    const tail = this.text.trim();
    if (tail) {
      try {
        this.queue.push(JSON.parse(tail) as WatchEvent<T>);
      } catch (error) {
        this.queue.fail(error);
        return;
      }
    }
    this.queue.finish();
  }

  fail(status: number, error?: Status): void {
    this.queue.fail(
      new K8sStatusError(
        error ?? failureStatus(status, "WebSocket watch failed"),
        status,
      ),
    );
  }

  private get successful(): boolean {
    return this.status >= 200 && this.status < 300;
  }

  private drainLines(): void {
    let newline: number;
    while ((newline = this.text.indexOf("\n")) >= 0) {
      const line = this.text.slice(0, newline).trim();
      this.text = this.text.slice(newline + 1);
      if (!line) continue;
      try {
        this.queue.push(JSON.parse(line) as WatchEvent<T>);
      } catch (error) {
        this.queue.fail(error);
        return;
      }
    }
  }
}

class MultiplexerConnection {
  readonly ready: Promise<void>;
  private readonly watches = new Map<string, LogicalWatch>();
  private resolveReady!: () => void;
  private rejectReady!: (error: unknown) => void;
  private settled = false;

  constructor(
    readonly origin: string,
    readonly authKey: string,
    private readonly socket: WatchSocket,
    private readonly onIdle: (connection: MultiplexerConnection) => void,
    private readonly onDead: (connection: MultiplexerConnection) => void,
  ) {
    this.ready = new Promise<void>((resolve, reject) => {
      this.resolveReady = resolve;
      this.rejectReady = reject;
    });
    socket.onopen = () => {
      this.settled = true;
      this.resolveReady();
    };
    socket.onmessage = (event) => this.onMessage(event.data);
    socket.onerror = () =>
      this.failAll(new Error("WebSocket watch connection failed"));
    socket.onclose = (event) => {
      const suffix = event.reason ? `: ${event.reason}` : "";
      this.failAll(new Error(`WebSocket watch connection closed${suffix}`));
    };
  }

  async subscribe(
    id: string,
    path: string,
    watch: LogicalWatch,
  ): Promise<void> {
    this.watches.set(id, watch);
    try {
      await this.ready;
      if (this.watches.get(id) !== watch) return;
      if (this.socket.readyState !== OPEN)
        throw new Error("WebSocket watch connection is not open");
      this.socket.send(JSON.stringify({ type: "subscribe", id, path }));
    } catch (error) {
      if (this.watches.get(id) === watch) {
        this.watches.delete(id);
        watch.queue.fail(error);
        if (this.watches.size === 0) this.onIdle(this);
      }
      throw error;
    }
  }

  unsubscribe(id: string): void {
    const watch = this.watches.get(id);
    if (!watch) return;
    this.watches.delete(id);
    watch.queue.finish();
    if (this.socket.readyState === OPEN)
      this.socket.send(JSON.stringify({ type: "unsubscribe", id }));
    if (this.watches.size === 0) this.onIdle(this);
  }

  close(): void {
    if (
      this.socket.readyState === CONNECTING ||
      this.socket.readyState === OPEN
    ) {
      this.socket.close(1000, "No active watches");
    }
    this.failAll(new Error("WebSocket watch connection closed"));
  }

  private onMessage(raw: unknown): void {
    if (typeof raw !== "string") {
      this.failAll(new Error("WebSocket watch message is not text"));
      return;
    }
    let msg: ServerMessage;
    try {
      msg = JSON.parse(raw) as ServerMessage;
    } catch (error) {
      this.failAll(error);
      return;
    }
    if (msg.type === "error" && !msg.id) {
      this.failAll(
        new K8sStatusError(
          msg.error ?? failureStatus(msg.status, "WebSocket watch failed"),
          msg.status,
        ),
      );
      return;
    }
    const watch = msg.id ? this.watches.get(msg.id) : undefined;
    if (!watch) return;
    switch (msg.type) {
      case "start":
        watch.start(msg.status);
        break;
      case "data":
        watch.data(msg.data);
        break;
      case "error":
        this.watches.delete(msg.id!);
        watch.fail(msg.status, msg.error);
        if (this.watches.size === 0) this.onIdle(this);
        break;
      case "complete":
        this.watches.delete(msg.id);
        watch.complete();
        if (this.watches.size === 0) this.onIdle(this);
        break;
    }
  }

  private failAll(error: unknown): void {
    if (!this.settled) {
      this.settled = true;
      this.rejectReady(error);
    }
    for (const watch of this.watches.values()) watch.queue.fail(error);
    this.watches.clear();
    this.onDead(this);
  }
}

/** One browser WebSocket that carries every active Kubernetes watch. */
export class WebSocketWatchTransport implements WatchTransport {
  private readonly endpointPath: string;
  private readonly socketFactory: WatchSocketFactory;
  private connection: MultiplexerConnection | undefined;
  private nextID = 1;

  constructor(opts: WebSocketWatchTransportOptions = {}) {
    this.endpointPath = opts.endpointPath ?? WATCH_MULTIPLEXER_PATH;
    this.socketFactory = opts.webSocketFactory ?? defaultSocketFactory;
  }

  async *watch<T extends K8sObject = K8sObject>(
    request: WatchTransportRequest,
  ): AsyncGenerator<WatchEvent<T>> {
    if (request.signal?.aborted) return;
    const target = new URL(request.url);
    const authKey = request.headers.get("Authorization") ?? "";
    const connection = this.getConnection(target.origin, authKey);
    const id = `watch-${this.nextID++}`;
    const watch = new LogicalWatch();
    const onAbort = () => connection.unsubscribe(id);
    request.signal?.addEventListener("abort", onAbort, { once: true });

    try {
      try {
        await connection.subscribe(id, target.pathname + target.search, watch);
      } catch (error) {
        if (request.signal?.aborted) return;
        throw error;
      }
      if (request.signal?.aborted) {
        connection.unsubscribe(id);
        return;
      }
      for (;;) {
        const result = await watch.queue.next();
        if (result.done) return;
        yield result.value as WatchEvent<T>;
      }
    } finally {
      request.signal?.removeEventListener("abort", onAbort);
      connection.unsubscribe(id);
    }
  }

  dispose(): void {
    this.connection?.close();
    this.connection = undefined;
  }

  private getConnection(
    origin: string,
    authKey: string,
  ): MultiplexerConnection {
    if (
      this.connection &&
      this.connection.origin === origin &&
      this.connection.authKey === authKey
    ) {
      return this.connection;
    }
    this.connection?.close();
    const endpoint = new URL(this.endpointPath, origin);
    endpoint.protocol = endpoint.protocol === "https:" ? "wss:" : "ws:";
    endpoint.searchParams.set("watch", "true");
    const protocols = [WATCH_WEBSOCKET_PROTOCOL];
    const bearer = bearerToken(authKey);
    if (bearer)
      protocols.push(WATCH_BEARER_PROTOCOL_PREFIX + encodeBase64URL(bearer));
    const socket = this.socketFactory(endpoint.toString(), protocols);
    const connection = new MultiplexerConnection(
      origin,
      authKey,
      socket,
      (idle) => {
        if (this.connection === idle) {
          this.connection = undefined;
          idle.close();
        }
      },
      (dead) => {
        if (this.connection === dead) this.connection = undefined;
      },
    );
    this.connection = connection;
    return connection;
  }
}

function defaultSocketFactory(url: string, protocols: string[]): WatchSocket {
  return new WebSocket(url, protocols) as unknown as WatchSocket;
}

function bearerToken(authorization: string): string | undefined {
  const [scheme, token, ...extra] = authorization.trim().split(/\s+/);
  return scheme?.toLowerCase() === "bearer" && token && extra.length === 0
    ? token
    : undefined;
}

function encodeBase64URL(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function decodeBase64(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function parseStatus(body: string, code: number): Status {
  try {
    return JSON.parse(body) as Status;
  } catch {
    return failureStatus(code, body.trim() || `Kubernetes API error ${code}`);
  }
}

function failureStatus(code: number, message: string): Status {
  return { metadata: {}, status: "Failure", code, message };
}

export const __testing = { encodeBase64URL };
