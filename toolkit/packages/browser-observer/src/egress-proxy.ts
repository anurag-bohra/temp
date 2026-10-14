import http from "node:http";
import net from "node:net";
import { decide, type HostRule } from "./policy.ts";

export interface EgressEntry { kind: "http" | "connect" | "upgrade"; target: string; decision: "allowed" | "blocked"; reason: string }

const HOP = new Set(["connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade"]);

/**
 * Loopback-only forward proxy that is Chromium's ONLY route to the network. It sees every request, including
 * redirect hops, WebSocket upgrades and HTTPS CONNECT tunnels, which Playwright's route() cannot police
 * (Playwright auto-continues redirect hops). Blocked requests get their socket destroyed (a network error in
 * the page) and are never forwarded.
 */
export class EgressProxy {
  readonly log: EgressEntry[] = [];
  readonly #server: http.Server;
  readonly #sockets = new Set<net.Socket>();
  #rules: HostRule[];
  port = 0;
  constructor(rules: HostRule[]) {
    this.#rules = rules;
    this.#server = http.createServer((req, res) => this.#onRequest(req, res));
    this.#server.on("connect", (req, sock, head) => this.#onConnect(req, sock as net.Socket, head));
    this.#server.on("upgrade", (req, sock, head) => this.#onUpgrade(req, sock as net.Socket, head));
    this.#server.on("connection", (s) => { this.#sockets.add(s); s.on("close", () => this.#sockets.delete(s)); });
  }
  async start(): Promise<number> {
    await new Promise<void>((r, j) => { this.#server.once("error", j); this.#server.listen(0, "127.0.0.1", () => r()); });
    this.port = (this.#server.address() as net.AddressInfo).port;
    return this.port;
  }
  async stop(): Promise<void> {
    for (const s of this.#sockets) s.destroy();
    await new Promise<void>((r) => this.#server.close(() => r()));
  }
  #check(kind: EgressEntry["kind"], url: string): boolean {
    const d = decide(url, this.#rules);
    this.log.push({ kind, target: url.length > 2000 ? url.slice(0, 2000) : url, decision: d.allowed ? "allowed" : "blocked", reason: d.reason });
    return d.allowed;
  }
  #onRequest(req: http.IncomingMessage, res: http.ServerResponse): void {
    let u: URL;
    try { u = new URL(req.url ?? ""); } catch { this.log.push({ kind: "http", target: String(req.url).slice(0, 200), decision: "blocked", reason: "non-absolute-proxy-request" }); req.socket.destroy(); return; }
    if (!this.#check("http", u.href)) { req.socket.destroy(); return; }
    const headers: http.OutgoingHttpHeaders = {};
    for (const [k, v] of Object.entries(req.headers)) if (!HOP.has(k)) headers[k] = v;
    const out = http.request({ host: u.hostname.replace(/^\[|\]$/gu, ""), port: u.port || 80, method: req.method, path: u.pathname + u.search, headers, agent: false }, (r) => {
      const h: http.OutgoingHttpHeaders = {};
      for (const [k, v] of Object.entries(r.headers)) if (!HOP.has(k)) h[k] = v;
      res.writeHead(r.statusCode ?? 502, r.statusMessage, h);
      r.pipe(res);
    });
    out.on("error", () => req.socket.destroy());
    req.pipe(out);
  }
  #onConnect(req: http.IncomingMessage, sock: net.Socket, head: Buffer): void {
    const target = req.url ?? "";
    const i = target.lastIndexOf(":");
    const host = target.slice(0, i), port = target.slice(i + 1);
    if (!this.#check("connect", `https://${host.includes(":") && !host.startsWith("[") ? `[${host}]` : host}:${port}/`)) { sock.destroy(); return; }
    const up = net.connect(Number(port), host.replace(/^\[|\]$/gu, ""), () => {
      sock.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head.length) up.write(head);
      up.pipe(sock); sock.pipe(up);
    });
    up.on("error", () => sock.destroy()); sock.on("error", () => up.destroy()); sock.on("close", () => up.destroy()); up.on("close", () => sock.destroy());
  }
  #onUpgrade(req: http.IncomingMessage, sock: net.Socket, head: Buffer): void {
    let u: URL;
    try { u = new URL(req.url ?? ""); } catch { sock.destroy(); return; }
    const wsUrl = u.href.replace(/^http/u, "ws");
    if (!this.#check("upgrade", wsUrl)) { sock.destroy(); return; }
    const up = net.connect(Number(u.port || 80), u.hostname.replace(/^\[|\]$/gu, ""), () => {
      let raw = `${req.method} ${u.pathname}${u.search} HTTP/1.1\r\n`;
      for (let k = 0; k < req.rawHeaders.length; k += 2) if (!/^proxy-/iu.test(req.rawHeaders[k])) raw += `${req.rawHeaders[k]}: ${req.rawHeaders[k + 1]}\r\n`;
      up.write(raw + "\r\n"); if (head.length) up.write(head);
      up.pipe(sock); sock.pipe(up);
    });
    up.on("error", () => sock.destroy()); sock.on("error", () => up.destroy()); sock.on("close", () => up.destroy()); up.on("close", () => sock.destroy());
  }
}
