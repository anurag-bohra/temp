# @rtk/browser-observer

Passive, policy-enforcing observation of one web page in a disposable headless Chromium (`playwright-core` 1.56, pinned to
match the Chromium 1194 build under `/opt/pw-browsers`). Output is an `@rtk/evidence` record.

```ts
import { observePage } from "@rtk/browser-observer";
const ev = await observePage("http://127.0.0.1:8080/", { allowHosts: ["127.0.0.1:8080"], timeoutMs: 15000, maxRequests: 200, maxBytes: 10 << 20 });
```
Provider `rtk-browser-observer`, operation `observe_web_page`, predicate `rtk.web-page-observation`, confidence `observed`,
authority `controlled-replay`, subject sha256 = main-document response body (falls back to sha256 of the URL).

## WARNING: isolation
`environment.isolation` is recorded honestly as **`process`**. When running as root (as in this lab) Chromium is forced to
`--no-sandbox`, so the renderer sandbox is OFF and a hostile page can attack the browser and the host. The disposable profile
and the egress policy are not a security boundary. Run the observer inside the `@rtk/sandbox` runner or a VM. The first entry of
`Evidence.limitations` states this (differently when the OS sandbox is on).

## Finding Chromium
`executablePath` option, else env **`RTK_CHROMIUM_PATH`** (or `PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH`), else search
`$PLAYWRIGHT_BROWSERS_PATH`, `/opt/pw-browsers`, `~/.cache/ms-playwright` (prefers `chromium_headless_shell-*`). None found:
`observePage` throws `ChromiumNotFoundError`; the tests skip with a reason.

## What it enforces
- **Egress allowlist** (`allowHosts`: `host` or `host:port`; default loopback `localhost`, `127.0.0.1`, `[::1]`, any port). Chromium is launched with `--proxy-server` pointing at a loopback forward proxy (`src/egress-proxy.ts`) with `<-loopback>` so even localhost goes through it; the proxy applies the allowlist to every HTTP request, redirect hop, WebSocket upgrade and HTTPS CONNECT, never forwards a blocked one (socket destroyed => network error in the page) and logs it (`normalized_result.egress`). Playwright `route()` additionally aborts blocked requests and applies the budgets, and `--host-resolver-rules` removes local DNS. A non-allowlisted target URL, a non-http(s) target, or `file:` is refused with `PolicyError` before any browser starts.
- Fresh `mkdtemp` profile (`rtk-browser-profile-*`) removed on exit; the code scans `/proc` for browser processes still using it, SIGKILLs leftovers and records `profile.removed` / `leftover_processes`.
- Downloads denied (`acceptDownloads:false`, recorded), dialogs dismissed (recorded), popups closed (recorded), service workers blocked, no permissions granted.
- Hard timeout (`timeoutMs`): closes the context and SIGKILLs stragglers; partial evidence with `navigation.timed_out`. Budgets `maxRequests` (extra requests aborted, reason `max-requests`) and `maxBytes` (reason `max-bytes`).
- Recorded: redirect chain (url, status, Location), all requests (decision, reason, redirect source, status, redacted headers, bytes), scripts (url, sha256, bytes, inline flag, textual indicators such as `eval`/`atob`), console + uncaught errors, cookies (value redacted unless `includeCookieValues`, length kept), localStorage/sessionStorage **keys**, main-document security headers (present / missing), websockets.
- Redaction: `authorization`, `proxy-authorization`, `cookie`, `set-cookie`, `x-api-key`, `x-auth-token` header values become `[REDACTED]` (configurable via `redactHeaders`). Test asserts the secret strings appear nowhere in the serialized Evidence.

## Verification (`test/observer.test.ts`, 19 tests; 2 run without Chromium, the rest skip cleanly when none is found)
Local `node:http` servers. Egress: fetch/Image/WebSocket/`localhost` alias to a non-allowlisted loopback port on another server are blocked and logged and that server records zero requests/upgrades; a 302 to a non-allowlisted origin is not followed (proven by the proxy log and zero hits). Also: inline script with `eval` (sha256/size/indicator match, eval ran), redirect chain 302->301->200, popup, download attempt, allowed localhost fetch (and the same page blocked when not allowlisted), default loopback policy, console error + pageerror, cookie set (HttpOnly, redacted) + storage keys + security headers, Authorization/Set-Cookie redaction and configurable list, hard timeout against a never-answering server and against an infinite JS loop, profile cleanup (tmp dir listing unchanged), max-requests and max-bytes budgets, Evidence envelope (isolation `process`, authenticated id).

## Not implemented / not verified
- Not run with the Chromium OS sandbox enabled (lab is root); no test of a real exploit attempt; no containment claim.
- WebRTC, QUIC/UDP and other non-proxyable protocols are not individually verified blocked. HTTPS CONNECT tunnels to allowlisted hosts are opaque to the proxy (policy is per host:port).
- Allowlisted origins are really contacted. Passive only: no clicking or form input; interaction-gated behaviour is not observed. Script indicators are regex matches, not proof of execution.
- Redirect hops are recorded from browser events (not routed); their `decision` is the policy verdict, enforcement evidence is the proxy log.
- Only a single page load; no multi-step flows, no HAR/screenshot capture.
