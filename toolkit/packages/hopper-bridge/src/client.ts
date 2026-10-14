import { createConnection } from "node:net";
import type { Socket } from "node:net";
import { lstatSync } from "node:fs";
import { dirname } from "node:path";
import { MAX_LINE_BYTES, PROTOCOL_VERSION, encodeLine, HopperAuthError, HopperConnectionError, HopperProtocolError, HopperRemoteError, HopperSecurityError, HopperTimeoutError } from "./protocol.ts";
import type { Response } from "./protocol.ts";

export interface ConnectOptions {
  socketPath: string;
  token: string;
  connectTimeoutMs?: number;
  /** Default per-request timeout. */
  requestTimeoutMs?: number;
}

/** Verify the socket and its directory are private to this user before any secret is sent. */
export function assertPrivateSocket(socketPath: string): void {
  const uid = process.getuid?.();
  const st = lstatSync(socketPath);
  if (!st.isSocket()) throw new HopperSecurityError(`${socketPath} is not a Unix socket`);
  if ((st.mode & 0o777) !== 0o600) throw new HopperSecurityError(`socket mode is ${(st.mode & 0o777).toString(8)}, expected 600`);
  if (uid !== undefined && st.uid !== uid) throw new HopperSecurityError(`socket owned by uid ${st.uid}, expected ${uid}`);
  const d = lstatSync(dirname(socketPath));
  if ((d.mode & 0o077) !== 0) throw new HopperSecurityError(`socket directory mode is ${(d.mode & 0o777).toString(8)}, expected 700`);
  if (uid !== undefined && d.uid !== uid) throw new HopperSecurityError(`socket directory owned by uid ${d.uid}, expected ${uid}`);
}

interface Pending { resolve: (r: Response) => void; reject: (e: Error) => void; timer: NodeJS.Timeout }

export class HopperClient {
  readonly #sock: Socket;
  readonly #pending = new Map<number, Pending>();
  readonly #requestTimeoutMs: number;
  #buf = "";
  #nextId = 1;
  #closed: Error | null = null;

  private constructor(sock: Socket, requestTimeoutMs: number) {
    this.#sock = sock;
    this.#requestTimeoutMs = requestTimeoutMs;
    sock.setEncoding("utf8");
    sock.on("data", (chunk: string) => this.#onData(chunk));
    sock.on("error", (e) => this.#fail(new HopperConnectionError(`socket error: ${e.message}`)));
    sock.on("close", () => this.#fail(new HopperConnectionError("connection closed")));
  }

  static async connect(opts: ConnectOptions): Promise<HopperClient> {
    assertPrivateSocket(opts.socketPath);
    const sock = createConnection({ path: opts.socketPath });
    await new Promise<void>((resolve, reject) => {
      const t = setTimeout(() => { sock.destroy(); reject(new HopperTimeoutError("connect timed out")); }, opts.connectTimeoutMs ?? 5000);
      sock.once("connect", () => { clearTimeout(t); resolve(); });
      sock.once("error", (e) => { clearTimeout(t); reject(new HopperConnectionError(`connect failed: ${e.message}`)); });
    });
    const c = new HopperClient(sock, opts.requestTimeoutMs ?? 30_000);
    try {
      await c.request("auth", { token: opts.token });
    } catch (e) {
      c.close();
      if (e instanceof HopperRemoteError && e.code === "auth_failed") throw new HopperAuthError("bridge rejected the session token");
      throw e;
    }
    return c;
  }

  get closed(): boolean { return this.#closed !== null; }

  /** Send one request; resolves with the result, rejects with HopperRemoteError/HopperTimeoutError/HopperConnectionError. */
  async request(method: string, params: Record<string, unknown> = {}, opts: { timeoutMs?: number } = {}): Promise<{ result: unknown; limitations: string[] }> {
    if (this.#closed) throw this.#closed;
    const id = this.#nextId++;
    const timeoutMs = opts.timeoutMs ?? this.#requestTimeoutMs;
    const resp = await new Promise<Response>((resolve, reject) => {
      const timer = setTimeout(() => { this.#pending.delete(id); reject(new HopperTimeoutError(`request "${method}" timed out after ${timeoutMs} ms`)); }, timeoutMs);
      this.#pending.set(id, { resolve, reject, timer });
      this.#sock.write(encodeLine({ v: PROTOCOL_VERSION, id, method, params }), (err) => {
        if (err) { clearTimeout(timer); this.#pending.delete(id); reject(new HopperConnectionError(`write failed: ${err.message}`)); }
      });
    });
    if (!resp.ok) throw new HopperRemoteError(resp.error.code, resp.error.message);
    return { result: resp.result, limitations: resp.limitations ?? [] };
  }

  close(): void {
    this.#fail(new HopperConnectionError("client closed"));
    this.#sock.destroy();
  }

  #fail(e: Error): void {
    if (!this.#closed) this.#closed = e;
    for (const [id, p] of this.#pending) { clearTimeout(p.timer); p.reject(this.#closed!); this.#pending.delete(id); }
  }

  #onData(chunk: string): void {
    this.#buf += chunk;
    if (this.#buf.length > MAX_LINE_BYTES && !this.#buf.includes("\n")) { this.#protocolFailure("response line exceeds maximum size"); return; }
    let nl: number;
    while ((nl = this.#buf.indexOf("\n")) >= 0) {
      const line = this.#buf.slice(0, nl);
      this.#buf = this.#buf.slice(nl + 1);
      if (line.trim() === "") continue;
      let msg: any;
      try { msg = JSON.parse(line); } catch { this.#protocolFailure("invalid JSON from bridge"); return; }
      if (!msg || msg.v !== PROTOCOL_VERSION || !Number.isInteger(msg.id) || typeof msg.ok !== "boolean") { this.#protocolFailure("malformed response envelope"); return; }
      const p = this.#pending.get(msg.id);
      if (!p) continue; // late response to a timed-out request
      clearTimeout(p.timer);
      this.#pending.delete(msg.id);
      p.resolve(msg as Response);
    }
  }

  #protocolFailure(m: string): void {
    this.#fail(new HopperProtocolError(m));
    this.#sock.destroy();
  }
}
