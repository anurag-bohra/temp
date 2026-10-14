import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { arch, platform, tmpdir } from "node:os";
import { join } from "node:path";
import { chromium, type BrowserContext, type Page, type Request, type Response } from "playwright-core";
import { createEvidence, type Evidence } from "@rtk/evidence";
import { EgressProxy } from "./egress-proxy.ts";
import { ENV_EXECUTABLE, findChromium, killProfileProcesses, pidsUsingProfile } from "./chromium.ts";
import { DEFAULT_ALLOW_HOSTS, DEFAULT_REDACT_HEADERS, REDACTED, decide, parseHostRule, redactHeaders, sha256 } from "./policy.ts";

export { findChromium, ENV_EXECUTABLE } from "./chromium.ts";
export { decide, parseHostRule, DEFAULT_ALLOW_HOSTS, DEFAULT_REDACT_HEADERS } from "./policy.ts";

export const PROVIDER = { id: "rtk-browser-observer", name: "RTK passive browser observer", version: "0.1.0" } as const;

export interface ObserveOptions {
  /** Hosts ("host" or "host:port") the page may contact. Default: loopback only (any port). Everything else is aborted. */
  allowHosts?: string[];
  /** Hard wall-clock limit for the whole observation (navigation + settle + collection). Default 15000. */
  timeoutMs?: number;
  /** Extra time to let the page run after the load event. Default 750. */
  settleMs?: number;
  /** Requests beyond this count are aborted (reason max-requests). Default 200. */
  maxRequests?: number;
  /** Cumulative response bytes beyond this abort further requests (reason max-bytes). Default 10 MiB. */
  maxBytes?: number;
  /** Header names (case-insensitive) whose values are replaced by [REDACTED]. Default authorization, cookie, set-cookie, ... */
  redactHeaders?: string[];
  /** Record cookie values instead of only their length+sha256 prefix. Default false. */
  includeCookieValues?: boolean;
  /** Chromium executable; else $RTK_CHROMIUM_PATH, else search /opt/pw-browsers. */
  executablePath?: string;
  /** Max inline/external script body bytes hashed per script. Default 2 MiB. */
  maxScriptBytes?: number;
}

export class PolicyError extends Error {}
export class ChromiumNotFoundError extends Error {}

const SECURITY_HEADERS = ["content-security-policy", "strict-transport-security", "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy", "cross-origin-opener-policy", "cross-origin-embedder-policy", "cross-origin-resource-policy"] as const;
const INDICATORS: [string, RegExp][] = [["eval", /\beval\s*\(/u], ["function-constructor", /\bnew\s+Function\s*\(|\bFunction\s*\(/u], ["atob", /\batob\s*\(/u], ["document.write", /document\.write(?:ln)?\s*\(/u], ["string-timer", /set(?:Timeout|Interval)\s*\(\s*['"`]/u], ["fromCharCode", /String\.fromCharCode/u]];

interface ReqRec {
  id: number; url: string; method: string; resource_type: string; is_navigation: boolean; decision: "allowed" | "blocked"; reason: string;
  redirected_from: string | null; status: number | null; request_headers: Record<string, string>; response_headers: Record<string, string> | null; response_bytes: number | null; failure: string | null;
}

export function isRoot(): boolean { return typeof process.getuid === "function" && process.getuid() === 0; }

export async function observePage(url: string, opts: ObserveOptions = {}): Promise<Evidence> {
  const o = { timeoutMs: 15000, settleMs: 750, maxRequests: 200, maxBytes: 10 * 1024 * 1024, maxScriptBytes: 2 * 1024 * 1024, ...opts };
  const rules = (opts.allowHosts ?? [...DEFAULT_ALLOW_HOSTS]).map(parseHostRule);
  const redactSet = new Set((opts.redactHeaders ?? [...DEFAULT_REDACT_HEADERS]).map((h) => h.toLowerCase()));

  let target: URL;
  try { target = new URL(url); } catch { throw new PolicyError(`invalid URL ${JSON.stringify(url)}`); }
  if (target.protocol !== "http:" && target.protocol !== "https:") throw new PolicyError(`only http(s) targets are observable (got ${target.protocol})`);
  const d0 = decide(url, rules);
  if (!d0.allowed) throw new PolicyError(`target ${target.host} is not in the egress allowlist; pass allowHosts: ["${target.host}"] to observe it deliberately`);
  const exe = findChromium(opts.executablePath);
  if (!exe) throw new ChromiumNotFoundError(`no Chromium found (set ${ENV_EXECUTABLE}, pass executablePath, or install under /opt/pw-browsers)`);

  const profileDir = mkdtempSync(join(tmpdir(), "rtk-browser-profile-"));
  const sandboxed = !isRoot();
  // Network-layer enforcement that also covers redirect hops (Playwright's route() does NOT see them):
  // Chromium's only path out is a loopback egress proxy that applies the allowlist to every request.
  const proxy = new EgressProxy(rules);
  const proxyPort = await proxy.start();
  const resolverRules = "MAP * ~NOTFOUND, EXCLUDE 127.0.0.1"; // defence in depth: no local DNS resolution of anything else

  const started = Date.now();
  const deadline = started + o.timeoutMs;
  let timedOut = false;
  let context: BrowserContext | null = null;
  const reqs: ReqRec[] = [];
  const byReq = new Map<Request, ReqRec>();
  const consoleMsgs: unknown[] = [];
  const dialogs: unknown[] = [];
  const popups: unknown[] = [];
  const downloads: unknown[] = [];
  const websockets: unknown[] = [];
  const scripts: Record<string, unknown>[] = [];
  const pending: Promise<unknown>[] = [];
  let totalBytes = 0, requestCount = 0, requestsOver = false, bytesOver = false;
  let mainBody: Buffer | null = null;
  let mainResponse: Response | null = null;
  let navError: string | null = null;
  let navStatus: number | null = null;
  let finalUrl: string | null = null;
  let title: string | null = null;
  let browserVersion: string | null = null;
  const redirectChain: { url: string; status: number | null; location: string | null }[] = [];
  let cookies: unknown[] = [], localKeys: string[] | null = null, sessionKeys: string[] | null = null;
  let killTimer: NodeJS.Timeout | undefined;

  const shortUrl = (u: string) => (u.length > 2000 ? u.slice(0, 2000) + "...[truncated]" : u);

  try {
    context = await chromium.launchPersistentContext(profileDir, {
      executablePath: exe.path,
      headless: true,
      chromiumSandbox: sandboxed,
      acceptDownloads: false,
      serviceWorkers: "block",
      permissions: [],
      ignoreHTTPSErrors: false,
      locale: "en-US", timezoneId: "UTC",
      viewport: { width: 1280, height: 800 },
      args: [`--proxy-server=http://127.0.0.1:${proxyPort}`, "--proxy-bypass-list=<-loopback>", `--host-resolver-rules=${resolverRules}`, "--disable-background-networking", "--disable-component-update", "--disable-sync", "--no-first-run", "--no-default-browser-check", "--disable-default-apps", "--disable-features=Translate,OptimizationHints,MediaRouter", "--metrics-recording-only", "--mute-audio"],
    });
    const ctx = context;
    browserVersion = ctx.browser()?.version() ?? null;
    // hard timeout: close the context; if the renderer is wedged, SIGKILL everything using this profile
    const hardStop = setTimeout(() => {
      timedOut = true;
      void ctx.close().catch(() => {});
      killTimer = setTimeout(() => { killProfileProcesses(profileDir); }, 2000);
    }, o.timeoutMs);

    // every request (including redirect hops, which Playwright never routes) is recorded here with the policy decision
    ctx.on("request", (r) => {
      const dec = decide(r.url(), rules);
      requestCount++;
      const rec: ReqRec = {
        id: requestCount, url: shortUrl(r.url()), method: r.method(), resource_type: r.resourceType(), is_navigation: r.isNavigationRequest(),
        decision: dec.allowed ? "allowed" : "blocked", reason: dec.reason, redirected_from: r.redirectedFrom()?.url() ?? null, status: null,
        request_headers: redactHeaders(r.headers(), redactSet), response_headers: null, response_bytes: null, failure: null,
      };
      reqs.push(rec); byReq.set(r, rec);
    });
    await ctx.route("**/*", async (route) => {
      const request = route.request();
      const rec = byReq.get(request);
      let dec = decide(request.url(), rules);
      if (dec.allowed && rec && rec.id > o.maxRequests) { dec = { allowed: false, reason: "max-requests" }; requestsOver = true; }
      if (dec.allowed && totalBytes > o.maxBytes) { dec = { allowed: false, reason: "max-bytes" }; bytesOver = true; }
      if (rec) { rec.decision = dec.allowed ? "allowed" : "blocked"; rec.reason = dec.reason; rec.request_headers = redactHeaders(request.headers(), redactSet); }
      if (!dec.allowed) { await route.abort("blockedbyclient").catch(() => {}); return; }
      await route.continue().catch(() => {});
    });
    await ctx.routeWebSocket(/.*/u, (ws) => {
      const dec = decide(ws.url(), rules);
      websockets.push({ url: shortUrl(ws.url()), decision: dec.allowed ? "allowed" : "blocked", reason: dec.reason });
      if (!dec.allowed) { void ws.close({ code: 1008, reason: "blocked by observer policy" }); return; }
      ws.connectToServer();
    });

    const attachPage = (p: Page, isMain: boolean) => {
      p.on("console", (m) => { if (isMain) consoleMsgs.push({ type: m.type(), text: m.text().slice(0, 2000), location: m.location().url ? { url: shortUrl(m.location().url), line: m.location().lineNumber, column: m.location().columnNumber } : null }); });
      p.on("pageerror", (e) => { if (isMain) consoleMsgs.push({ type: "pageerror", text: String(e.message ?? e).slice(0, 2000), location: null }); });
      p.on("dialog", (dlg) => { dialogs.push({ type: dlg.type(), message: dlg.message().slice(0, 1000), default_value: dlg.defaultValue() || null, action: "dismissed", page: isMain ? "main" : "popup" }); void dlg.dismiss().catch(() => {}); });
      p.on("download", (dl) => { downloads.push({ url: shortUrl(dl.url()), suggested_filename: dl.suggestedFilename(), action: "denied" }); void dl.cancel().catch(() => {}); });
    };
    ctx.on("page", (p) => {
      if (p === mainPage) return;
      const idx = popups.push({ url: shortUrl(p.url()), action: "closed" }) - 1;
      attachPage(p, false);
      pending.push((async () => {
        await p.waitForLoadState("domcontentloaded", { timeout: 1500 }).catch(() => {});
        popups[idx] = { url: shortUrl(p.url()), action: "closed" };
        await p.close().catch(() => {});
      })());
    });
    const mainPage: Page = ctx.pages()[0] ?? (await ctx.newPage());
    attachPage(mainPage, true);

    ctx.on("response", (resp) => {
      const rec = byReq.get(resp.request());
      if (!rec) return;
      rec.status = resp.status();
      pending.push((async () => {
        try {
          rec.response_headers = redactHeaders(await resp.allHeaders(), redactSet);
          const cd = rec.response_headers["content-disposition"];
          if (cd && /attachment/iu.test(cd)) downloads.push({ url: rec.url, suggested_filename: /filename="?([^";]+)/iu.exec(cd)?.[1] ?? null, action: "denied", via: "content-disposition" });
        } catch { /* response gone */ }
        const isScript = rec.resource_type === "script";
        if (resp.status() >= 300 && resp.status() < 400) return;
        try {
          const body = await resp.body();
          rec.response_bytes = body.length; totalBytes += body.length;
          if (totalBytes > o.maxBytes) bytesOver = true;
          if (isScript) scripts.push(scriptRecord(rec.url, body, false, o.maxScriptBytes));
          if (rec.is_navigation && rec.resource_type === "document" && resp.request().frame() === mainPage.mainFrame()) mainBody = body;
        } catch { /* body unavailable (aborted, redirected) */ }
      })());
    });
    ctx.on("requestfailed", (r) => { const rec = byReq.get(r); if (rec && !rec.failure) rec.failure = r.failure()?.errorText ?? "failed"; });

    try {
      mainResponse = await mainPage.goto(url, { waitUntil: "load", timeout: Math.max(1, deadline - Date.now()) });
    } catch (e) { navError = String((e as Error).message ?? e).split("\n")[0].slice(0, 300); }
    if (!timedOut && !navError) await mainPage.waitForTimeout(Math.max(0, Math.min(o.settleMs, deadline - Date.now() - 500))).catch(() => {});

    if (!timedOut) {
      try {
        await Promise.allSettled(pending);
        finalUrl = mainPage.url();
        title = await mainPage.title().catch(() => null);
        if (mainResponse) {
          navStatus = mainResponse.status();
          const chain: Request[] = []; for (let r: Request | null = mainResponse.request(); r; r = r.redirectedFrom()) chain.unshift(r);
          for (const r of chain) { const resp = await r.response().catch(() => null); const h = resp ? await resp.allHeaders().catch(() => ({} as Record<string, string>)) : {}; redirectChain.push({ url: shortUrl(r.url()), status: resp?.status() ?? null, location: h["location"] ?? null }); }
        }
        // inline scripts + storage, evaluated passively in the page (read-only)
        const inline: string[] = await mainPage.evaluate(() => Array.from(document.scripts).filter((s) => !s.src).map((s) => s.textContent ?? "")).catch(() => []);
        for (const code of inline) scripts.push(scriptRecord(null, Buffer.from(code, "utf8"), true, o.maxScriptBytes));
        localKeys = await mainPage.evaluate(() => { try { return Object.keys(localStorage); } catch { return null; } }).catch(() => null);
        sessionKeys = await mainPage.evaluate(() => { try { return Object.keys(sessionStorage); } catch { return null; } }).catch(() => null);
        cookies = (await ctx.cookies().catch(() => [])).map((c) => ({
          name: c.name, domain: c.domain, path: c.path, httpOnly: c.httpOnly, secure: c.secure, sameSite: c.sameSite, expires: c.expires,
          value: opts.includeCookieValues ? c.value : REDACTED, value_length: c.value.length,
        }));
      } catch { /* page closed under us */ }
    }
    clearTimeout(hardStop);
    await ctx.close().catch(() => {});
  } catch (e) {
    if (!timedOut) { await context?.close().catch(() => {}); killProfileProcesses(profileDir); await proxy.stop().catch(() => {}); rmSync(profileDir, { recursive: true, force: true }); throw e; }
  } finally {
    clearTimeout(killTimer);
  }
  // ---- verify cleanup
  await proxy.stop().catch(() => {});
  await new Promise((r) => setTimeout(r, 50));
  let leftover = pidsUsingProfile(profileDir);
  if (leftover.length) { killProfileProcesses(profileDir); await new Promise((r) => setTimeout(r, 200)); leftover = pidsUsingProfile(profileDir); }
  let removed = false;
  for (let i = 0; i < 5 && !removed; i++) { rmSync(profileDir, { recursive: true, force: true }); removed = !existsSync(profileDir); if (!removed) await new Promise((r) => setTimeout(r, 100)); }

  const mainRec = mainResponse ? byReq.get((mainResponse as Response).request()) : undefined;
  const mainHeaders = mainRec?.response_headers ?? null;
  const present: Record<string, string> = {}; const missing: string[] = [];
  for (const h of SECURITY_HEADERS) { if (mainHeaders?.[h] !== undefined) present[h] = mainHeaders[h]; else missing.push(h); }
  const blocked = reqs.filter((r) => r.decision === "blocked");
  scripts.sort((a, b) => String(a.url ?? "").localeCompare(String(b.url ?? "")) || String(a.sha256).localeCompare(String(b.sha256)));

  const limitations: string[] = [
    sandboxed
      ? "Chromium ran with its OS sandbox enabled, but environment.isolation is 'process' only: a hostile page that exploits the browser is not contained by this package. Prefer running the observer inside the @rtk/sandbox runner or a VM."
      : "PROMINENT: running as root forces Chromium --no-sandbox, so the browser's renderer sandbox is OFF. A hostile page can attack the browser process and the host; environment.isolation is honestly 'process' (a disposable profile directory plus request-interception policy, not a security boundary). Run inside the @rtk/sandbox runner or a VM.",
    "egress control is enforced by request interception (route.abort) AND, because Playwright does not route redirect hops, by Chromium --host-resolver-rules (every host:port not allowlisted fails name resolution, IP literals included) and --no-proxy-server; redirect hops are therefore recorded from request events and blocked at the resolver, not by route.abort; it covers HTTP(S) and WebSocket from pages and workers visible to Playwright; other protocols (WebRTC, QUIC to literal IPs, etc.) are not individually verified to be blocked",
    "allowlisted origins ARE contacted: observing a page that talks to an allowlisted host sends that host real requests",
    "passive only: no clicks, form input or navigation beyond the load event + settle window; behaviour gated on user interaction, timing beyond settleMs, or a real (non-headless) fingerprint is not observed",
    "script indicators (eval, Function constructor, atob, ...) are textual matches on script source, not proof of execution; inline scripts are read from the DOM after load",
    "cookie values are redacted unless includeCookieValues is set; localStorage/sessionStorage values are never recorded, only keys; URL query strings are recorded as-is",
    "popups are recorded and closed after their first navigation request was issued (allowlist still applies to that request)",
  ];
  if (timedOut) limitations.push(`hard timeout ${o.timeoutMs}ms reached: observation is partial (page state, cookies, storage and inline scripts were not collected)`);
  if (requestsOver) limitations.push(`max-requests budget (${o.maxRequests}) exceeded: further requests were aborted and recorded as blocked (reason max-requests)`);
  if (bytesOver) limitations.push(`max-bytes budget (${o.maxBytes}) exceeded: further requests were aborted and recorded as blocked (reason max-bytes)`);
  if (!removed) limitations.push("temporary profile directory could NOT be removed; remove it manually: " + profileDir);
  if (leftover.length) limitations.push(`${leftover.length} browser process(es) still referenced the profile after shutdown`);
  if (navError) limitations.push(`navigation error: ${navError}`);
  if (platform() !== "linux") limitations.push("profile process verification (/proc scan) is Linux-only and was skipped");

  const subjectBytes = mainBody ? (mainBody as Buffer) : null;
  return createEvidence({
    subject: { name: target.href, digest: { sha256: subjectBytes ? sha256(subjectBytes) : sha256(target.href) }, local_path: null, format: "web-page", architecture: null },
    provider: { ...PROVIDER },
    predicate_type: "rtk.web-page-observation",
    operation: "observe_web_page",
    parameters: { url: target.href, allow_hosts: rules.map((r) => (r.port ? `${r.host}:${r.port}` : r.host)), timeout_ms: o.timeoutMs, settle_ms: o.settleMs, max_requests: o.maxRequests, max_bytes: o.maxBytes, redact_headers: [...redactSet].sort(), include_cookie_values: !!opts.includeCookieValues },
    normalized_result: {
      target: target.href, final_url: finalUrl, title,
      navigation: { status: navStatus, error: navError, timed_out: timedOut, subject_is_main_document_body: !!mainBody },
      redirect_chain: redirectChain,
      requests: reqs, blocked_requests: blocked.map((r) => ({ id: r.id, url: r.url, reason: r.reason, resource_type: r.resource_type })),
      egress: { proxy: "loopback forward proxy (sole network path of the browser)", log: proxy.log, blocked: proxy.log.filter((x) => x.decision === "blocked").length },
      websockets, scripts, console: consoleMsgs, dialogs, popups, downloads, cookies,
      storage: { local_storage_keys: localKeys, session_storage_keys: sessionKeys },
      security_headers: { main_document: { present, missing } },
      budgets: { max_requests: o.maxRequests, max_bytes: o.maxBytes, requests_seen: requestCount, response_bytes: totalBytes, requests_exceeded: requestsOver, bytes_exceeded: bytesOver },
      profile: { removed, leftover_processes: leftover.length },
      browser: { executable_source: exe.source, version: browserVersion, os_sandbox: sandboxed, headless: true },
      summary: { requests: reqs.length, allowed: reqs.length - blocked.length, blocked: blocked.length, scripts: scripts.length, inline_scripts: scripts.filter((s) => s.inline).length, console_messages: consoleMsgs.length, console_errors: consoleMsgs.filter((m) => ["error", "pageerror"].includes((m as { type: string }).type)).length, dialogs: dialogs.length, popups: popups.length, downloads: downloads.length, cookies: cookies.length, redirects: Math.max(0, redirectChain.length - 1), elapsed_ms: Date.now() - started },
    },
    confidence: "observed",
    authority: "controlled-replay",
    environment: { id: "rtk-browser-observer/chromium-headless", platform: platform(), architecture: arch(), isolation: "process" },
    limitations,
    locations: scripts.filter((s) => s.url).map((s) => ({ kind: "script", url: s.url, sha256: s.sha256 })),
  });
}

function scriptRecord(url: string | null, body: Buffer, inline: boolean, max: number): Record<string, unknown> {
  const text = body.subarray(0, max).toString("utf8");
  return { url, inline, bytes: body.length, sha256: sha256(body), indicators: INDICATORS.filter(([, re]) => re.test(text)).map(([n]) => n), truncated_scan: body.length > max };
}
