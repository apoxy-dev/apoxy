import { describe, expect, it, vi } from "vitest";
import { K8sStatusError } from "./gvr-client";
import type { WatchEvent } from "./k8s-types";
import {
  __testing,
  WATCH_BEARER_PROTOCOL_PREFIX,
  WATCH_MULTIPLEXER_PATH,
  WATCH_WEBSOCKET_PROTOCOL,
  WebSocketWatchTransport,
  type WatchSocketFactory,
} from "./websocket-watch-transport";

class FakeSocket {
  static readonly instances: FakeSocket[] = [];

  readyState = 0;
  protocol = "";
  onopen: (() => void) | null = null;
  onmessage: ((event: { data: unknown }) => void) | null = null;
  onerror: (() => void) | null = null;
  onclose: ((event: { code?: number; reason?: string }) => void) | null = null;
  readonly sent: Array<Record<string, unknown>> = [];

  constructor(
    readonly url: string,
    readonly protocols: string[],
    autoOpen = true,
  ) {
    FakeSocket.instances.push(this);
    if (autoOpen) queueMicrotask(() => this.open());
  }

  open(): void {
    if (this.readyState !== 0) return;
    this.readyState = 1;
    this.protocol = this.protocols[0] ?? "";
    this.onopen?.();
  }

  send(data: string): void {
    this.sent.push(JSON.parse(data) as Record<string, unknown>);
  }

  close(code = 1000, reason = ""): void {
    if (this.readyState === 3) return;
    this.readyState = 3;
    this.onclose?.({ code, reason });
  }

  emit(message: Record<string, unknown>): void {
    this.onmessage?.({ data: JSON.stringify(message) });
  }

  disconnect(reason = "test disconnect"): void {
    this.readyState = 3;
    this.onclose?.({ code: 1006, reason });
  }
}

const socketFactory: WatchSocketFactory = (url, protocols) =>
  new FakeSocket(url, protocols) as unknown as ReturnType<WatchSocketFactory>;

function request(
  path: string,
  signal?: AbortSignal,
  token = "header.payload.signature",
) {
  return {
    url: `http://api.test${path}`,
    headers: new Headers({ Authorization: `Bearer ${token}` }),
    signal,
  };
}

function encoded(value: string): string {
  return Buffer.from(value).toString("base64");
}

function event(name: string): WatchEvent {
  return {
    type: "ADDED",
    object: { apiVersion: "v1", kind: "Pod", metadata: { name } },
  };
}

describe("WebSocketWatchTransport", () => {
  it("multiplexes watches and demultiplexes event chunks by subscription ID", async () => {
    FakeSocket.instances.length = 0;
    const transport = new WebSocketWatchTransport({
      webSocketFactory: socketFactory,
    });
    const aAbort = new AbortController();
    const bAbort = new AbortController();
    const a = transport.watch(
      request("/api/v1/pods?watch=true", aAbort.signal),
    );
    const b = transport.watch(
      request("/api/v1/services?watch=true", bAbort.signal),
    );
    const aNext = a.next();
    const bNext = b.next();

    await vi.waitFor(() => expect(FakeSocket.instances).toHaveLength(1));
    const socket = FakeSocket.instances[0]!;
    await vi.waitFor(() =>
      expect(socket.sent.filter((m) => m.type === "subscribe")).toHaveLength(2),
    );
    expect(socket.url).toBe(
      `ws://api.test${WATCH_MULTIPLEXER_PATH}?watch=true`,
    );
    expect(socket.protocols).toEqual([
      WATCH_WEBSOCKET_PROTOCOL,
      WATCH_BEARER_PROTOCOL_PREFIX +
        __testing.encodeBase64URL("header.payload.signature"),
    ]);

    const subscriptions = socket.sent.filter((m) => m.type === "subscribe");
    const aID = subscriptions.find((m) => String(m.path).includes("/pods"))
      ?.id as string;
    const bID = subscriptions.find((m) => String(m.path).includes("/services"))
      ?.id as string;
    const aEvent = event("pod-one");
    const bEvent = event("service-one");
    socket.emit({ type: "start", id: aID, status: 200 });
    socket.emit({ type: "start", id: bID, status: 200 });
    socket.emit({
      type: "data",
      id: bID,
      data: encoded(`${JSON.stringify(bEvent)}\n`),
    });
    socket.emit({
      type: "data",
      id: aID,
      data: encoded(`${JSON.stringify(aEvent)}\n`),
    });

    await expect(aNext).resolves.toEqual({ done: false, value: aEvent });
    await expect(bNext).resolves.toEqual({ done: false, value: bEvent });

    aAbort.abort();
    await vi.waitFor(() =>
      expect(socket.sent).toContainEqual({ type: "unsubscribe", id: aID }),
    );
    expect(socket.readyState).toBe(1);
    bAbort.abort();
    await vi.waitFor(() =>
      expect(socket.sent).toContainEqual({ type: "unsubscribe", id: bID }),
    );
    await a.return(undefined);
    await b.return(undefined);
    expect(socket.readyState).toBe(3);
  });

  it("turns a non-success upstream response into K8sStatusError", async () => {
    FakeSocket.instances.length = 0;
    const transport = new WebSocketWatchTransport({
      webSocketFactory: socketFactory,
    });
    const stream = transport.watch(request("/api/v1/pods?watch=true"));
    const next = stream.next();
    await vi.waitFor(() =>
      expect(FakeSocket.instances[0]?.sent).toHaveLength(1),
    );
    const socket = FakeSocket.instances[0]!;
    const id = socket.sent[0]!.id as string;
    const status = {
      metadata: {},
      status: "Failure",
      code: 410,
      reason: "Gone",
      message: "too old",
    };
    socket.emit({ type: "start", id, status: 410 });
    socket.emit({ type: "data", id, data: encoded(JSON.stringify(status)) });
    socket.emit({ type: "complete", id });

    await expect(next).rejects.toMatchObject({
      code: 410,
      reason: "Gone",
    } satisfies Partial<K8sStatusError>);
  });

  it("fails every logical watch when the shared socket disconnects", async () => {
    FakeSocket.instances.length = 0;
    const transport = new WebSocketWatchTransport({
      webSocketFactory: socketFactory,
    });
    const a = transport.watch(request("/api/v1/pods?watch=true"));
    const b = transport.watch(request("/api/v1/services?watch=true"));
    const aNext = a.next();
    const bNext = b.next();
    await vi.waitFor(() =>
      expect(FakeSocket.instances[0]?.sent).toHaveLength(2),
    );
    FakeSocket.instances[0]!.disconnect();
    await expect(aNext).rejects.toThrow("test disconnect");
    await expect(bNext).rejects.toThrow("test disconnect");

    const replacement = transport.watch(
      request("/api/v1/configmaps?watch=true"),
    );
    const replacementNext = replacement.next();
    await vi.waitFor(() =>
      expect(FakeSocket.instances[1]?.sent).toHaveLength(1),
    );
    FakeSocket.instances[1]!.disconnect();
    await expect(replacementNext).rejects.toThrow("test disconnect");
  });

  it("cancels a watch that aborts while its socket is connecting", async () => {
    FakeSocket.instances.length = 0;
    const transport = new WebSocketWatchTransport({
      webSocketFactory: (url, protocols) =>
        new FakeSocket(
          url,
          protocols,
          false,
        ) as unknown as ReturnType<WatchSocketFactory>,
    });
    const abort = new AbortController();
    const stream = transport.watch(
      request("/api/v1/pods?watch=true", abort.signal),
    );
    const next = stream.next();
    await vi.waitFor(() => expect(FakeSocket.instances).toHaveLength(1));
    abort.abort();

    await expect(next).resolves.toEqual({ done: true, value: undefined });
    expect(FakeSocket.instances[0]!.sent).toEqual([]);
    expect(FakeSocket.instances[0]!.readyState).toBe(3);

    const replacement = transport.watch(request("/api/v1/services?watch=true"));
    const replacementNext = replacement.next();
    await vi.waitFor(() => expect(FakeSocket.instances).toHaveLength(2));
    FakeSocket.instances[1]!.open();
    await vi.waitFor(() =>
      expect(FakeSocket.instances[1]!.sent).toHaveLength(1),
    );
    FakeSocket.instances[1]!.disconnect();
    await expect(replacementNext).rejects.toThrow("test disconnect");
  });

  it("opens a new authenticated socket when the bearer changes", async () => {
    FakeSocket.instances.length = 0;
    const transport = new WebSocketWatchTransport({
      webSocketFactory: socketFactory,
    });
    const first = transport.watch(
      request("/api/v1/pods?watch=true", undefined, "first"),
    );
    const firstNext = first.next();
    await vi.waitFor(() =>
      expect(FakeSocket.instances[0]?.sent).toHaveLength(1),
    );

    const second = transport.watch(
      request("/api/v1/services?watch=true", undefined, "second"),
    );
    const secondNext = second.next();
    await vi.waitFor(() => expect(FakeSocket.instances).toHaveLength(2));
    expect(FakeSocket.instances[0]!.readyState).toBe(3);
    await expect(firstNext).rejects.toThrow("closed");
    expect(FakeSocket.instances[1]!.protocols[1]).toBe(
      WATCH_BEARER_PROTOCOL_PREFIX + __testing.encodeBase64URL("second"),
    );
    FakeSocket.instances[1]!.disconnect();
    await expect(secondNext).rejects.toThrow();
  });
});
