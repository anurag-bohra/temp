import { createServer } from "node:net";
import type { Server, Socket } from "node:net";
import { chmodSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export interface FakeOptions {
  token: string;
  sha256?: string;
  /** methods that never get a response */
  silent?: string[];
  /** per-method delay in ms */
  delay?: Record<string, number>;
  socketMode?: number;
  dirMode?: number;
  /** send garbage instead of a response for this method */
  garbage?: string;
}

export interface FakeHandle { dir: string; socketPath: string; token: string; requests: any[]; connections: number; close(): Promise<void> }

export async function startFake(o: FakeOptions): Promise<FakeHandle> {
  const dir = mkdtempSync(join(tmpdir(), "rtk-fakehopper-"));
  chmodSync(dir, o.dirMode ?? 0o700);
  const socketPath = join(dir, "s.sock");
  const requests: any[] = [];
  const socks = new Set<Socket>();
  const h: FakeHandle = { dir, socketPath, token: o.token, requests, connections: 0, close: async () => {} };
  const server: Server = createServer((sock) => {
    h.connections++;
    socks.add(sock);
    sock.on("close", () => socks.delete(sock));
    sock.on("error", () => {});
    let authed = false, buf = "";
    sock.setEncoding("utf8");
    sock.on("data", (d: string) => {
      buf += d;
      let i: number;
      while ((i = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, i); buf = buf.slice(i + 1);
        const req = JSON.parse(line);
        requests.push({ ...req, authed });
        const send = (m: unknown) => sock.write(JSON.stringify(m) + "\n");
        const reply = () => {
          if (!authed) {
            if (req.method === "auth" && req.params.token === o.token) { authed = true; return send({ v: 1, id: req.id, ok: true, result: { authenticated: true } }); }
            send({ v: 1, id: req.id, ok: false, error: { code: "auth_failed", message: "bad token" } });
            return sock.end();
          }
          if (o.garbage === req.method) return sock.write("this is not json\n");
          switch (req.method) {
            case "hello": return send({ v: 1, id: req.id, ok: true, result: { protocol: 1, hopper_version: "fake-0" } });
            case "open_document": return send({ v: 1, id: req.id, ok: true, result: { sha256: o.sha256 ?? req.params.sha256 } });
            case "shutdown": send({ v: 1, id: req.id, ok: true, result: { bye: true } }); return sock.end();
            case "ping": return send({ v: 1, id: req.id, ok: true, result: { pong: true } });
            case "list_procedures": return send({ v: 1, id: req.id, ok: true, result: { procedures: [{ entry: "0x1000", name: "main" }] }, limitations: ["fake"] });
            case "procedure_pseudo_code": return send({ v: 1, id: req.id, ok: true, result: { pseudo_code: "int main(){return 0;}" } });
            case "xrefs": return send({ v: 1, id: req.id, ok: false, error: { code: "not_implemented", message: "nope" } });
            default: return send({ v: 1, id: req.id, ok: false, error: { code: "unknown_method", message: req.method } });
          }
        };
        if (o.silent?.includes(req.method)) continue;
        const d = o.delay?.[req.method];
        if (d) setTimeout(reply, d); else reply();
      }
    });
  });
  await new Promise<void>((r) => server.listen(socketPath, r));
  chmodSync(socketPath, o.socketMode ?? 0o600);
  h.close = async () => { for (const s of socks) s.destroy(); await new Promise<void>((r) => server.close(() => r())); rmSync(dir, { recursive: true, force: true }); };
  return h;
}
