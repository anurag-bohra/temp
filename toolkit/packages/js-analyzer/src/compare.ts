import { createEvidence, type Evidence } from "@rtk/evidence";

/* eslint-disable @typescript-eslint/no-explicit-any */
type Any = any;
export type DeltaStatus = "improved" | "regressed" | "changed";
export interface DeltaItem { id: string; category: string; status: DeltaStatus; before: unknown; after: unknown; note: string }

const OP = "analyze_javascript_application";
const BAD_WHEN_TRUE = ["nodeIntegration", "nodeIntegrationInWorker", "nodeIntegrationInSubFrames", "enableRemoteModule", "allowRunningInsecureContent", "webviewTag", "experimentalFeatures"];
const GOOD_WHEN_TRUE = ["contextIsolation", "sandbox", "webSecurity"];
/** 0 safe, 1 default/unset, 2 dynamic/unknown, 3 unsafe */
function risk(key: string, v: unknown): number {
  if (v === "unset") return 1;
  if (v === "dynamic") return 2;
  if (BAD_WHEN_TRUE.includes(key)) return v === true ? 3 : v === false ? 0 : 2;
  if (GOOD_WHEN_TRUE.includes(key)) return v === false ? 3 : v === true ? 0 : 2;
  return 2;
}
const DANGEROUS = new Set(["child-process", "eval", "function-constructor", "vm", "dynamic-require", "native-addon"]);

function need(e: Evidence, which: string): Any {
  if (e.operation !== OP) throw new Error(`compareJavaScriptApplications: ${which} is not an ${OP} evidence record (got ${e.operation})`);
  return e.normalized_result;
}
function count<T>(xs: T[], key: (x: T) => string): Map<string, number> {
  const m = new Map<string, number>();
  for (const x of xs) m.set(key(x), (m.get(key(x)) ?? 0) + 1);
  return m;
}

/** Security delta between two analyses (A = baseline, B = candidate). Pure function of the two records. */
export function compareJavaScriptApplications(evA: Evidence, evB: Evidence): Evidence {
  const a = need(evA, "evA"), b = need(evB, "evB");
  const items: DeltaItem[] = [];
  const add = (i: DeltaItem) => items.push(i);

  // windows: matched by file + ordinal within file
  const winKey = (ws: Any[]): Map<string, Any> => { const seen = new Map<string, number>(); const m = new Map<string, Any>(); for (const w of ws) { const n = (seen.get(w.file) ?? 0) + 1; seen.set(w.file, n); m.set(`${w.file}#${n}`, w); } return m; };
  const wa = winKey(a.electron.windows), wb = winKey(b.electron.windows);
  for (const k of new Set([...wa.keys(), ...wb.keys()])) {
    const x = wa.get(k), y = wb.get(k);
    if (!x || !y) {
      add({ id: `window:${k}`, category: "browser-window", status: y ? "regressed" : "changed", before: x ? "present" : "absent", after: y ? "present" : "absent", note: y ? "new browser window (new attack surface)" : "browser window removed" });
      continue;
    }
    for (const key of [...BAD_WHEN_TRUE, ...GOOD_WHEN_TRUE]) {
      const bv = x.webPreferences[key], av = y.webPreferences[key];
      if (JSON.stringify(bv) === JSON.stringify(av)) continue;
      const rb = risk(key, bv), ra = risk(key, av);
      add({ id: `window:${k}:webPreferences.${key}`, category: "webPreferences", status: ra < rb ? "improved" : ra > rb ? "regressed" : "changed", before: bv, after: av, note: `${key}: ${JSON.stringify(bv)} -> ${JSON.stringify(av)}` });
    }
  }

  // ipc main handlers keyed by channel
  const hk = (i: Any) => `${i.channel_kind === "literal" ? i.channel : `dynamic@${i.file}:${i.loc.line}`}`;
  const ha = new Map<string, Any>(), hb = new Map<string, Any>();
  for (const i of a.electron.ipc) if (i.side === "main" && (i.kind === "handle" || i.kind === "on")) ha.set(hk(i), i);
  for (const i of b.electron.ipc) if (i.side === "main" && (i.kind === "handle" || i.kind === "on")) hb.set(hk(i), i);
  for (const k of new Set([...ha.keys(), ...hb.keys()])) {
    const x = ha.get(k), y = hb.get(k);
    if (x && y) {
      if (x.sender_validation !== y.sender_validation) add({ id: `ipc:${k}:sender_validation`, category: "ipc-sender-validation", status: y.sender_validation ? "improved" : "regressed", before: x.sender_validation, after: y.sender_validation, note: `sender validation for channel ${k}: ${x.sender_validation} -> ${y.sender_validation}` });
    } else if (y) add({ id: `ipc:${k}:added`, category: "ipc-handler", status: y.sender_validation ? "changed" : "regressed", before: null, after: { sender_validation: y.sender_validation }, note: `new IPC handler ${k}${y.sender_validation ? "" : " without sender validation"}` });
    else add({ id: `ipc:${k}:removed`, category: "ipc-handler", status: x.sender_validation ? "changed" : "improved", before: { sender_validation: x.sender_validation }, after: null, note: `IPC handler ${k} removed` });
  }

  // context bridge exposure
  const ba = new Map<string, Any>(a.electron.context_bridge.map((c: Any) => [c.api, c])), bb = new Map<string, Any>(b.electron.context_bridge.map((c: Any) => [c.api, c]));
  for (const k of new Set([...ba.keys(), ...bb.keys()])) {
    const x = ba.get(k), y = bb.get(k);
    if (!x || !y) { add({ id: `bridge:${k}`, category: "context-bridge", status: y ? "regressed" : "improved", before: x?.members ?? null, after: y?.members ?? null, note: y ? `new contextBridge API ${k}` : `contextBridge API ${k} removed` }); continue; }
    const added = y.members.filter((m: string) => !x.members.includes(m)), removed = x.members.filter((m: string) => !y.members.includes(m));
    if (added.length) add({ id: `bridge:${k}:members-added`, category: "context-bridge", status: "regressed", before: x.members, after: y.members, note: `members added: ${added.join(", ")}` });
    if (removed.length) add({ id: `bridge:${k}:members-removed`, category: "context-bridge", status: "improved", before: x.members, after: y.members, note: `members removed: ${removed.join(", ")}` });
  }

  // sinks: dangerous kinds are judged by total count per kind (swapping exec for execFileSync is not a regression);
  // per-API differences are reported as neutral 'changed'
  const sa = count<Any>(a.sinks, (s) => `${s.kind}|${s.api}`), sb = count<Any>(b.sinks, (s) => `${s.kind}|${s.api}`);
  for (const k of new Set([...sa.keys(), ...sb.keys()])) {
    const x = sa.get(k) ?? 0, y = sb.get(k) ?? 0;
    if (x !== y) add({ id: `sink:${k}`, category: "sink-count", status: "changed", before: x, after: y, note: `${k}: ${x} -> ${y}` });
  }
  const ka = count<Any>(a.sinks, (s) => s.kind), kb = count<Any>(b.sinks, (s) => s.kind);
  for (const k of new Set([...ka.keys(), ...kb.keys()])) {
    const x = ka.get(k) ?? 0, y = kb.get(k) ?? 0;
    if (x !== y && DANGEROUS.has(k)) add({ id: `sink-kind:${k}`, category: "sink-kind-count", status: y > x ? "regressed" : "improved", before: x, after: y, note: `${k} sinks: ${x} -> ${y}` });
  }

  // flows by source|sink|api (+channel)
  const fk = (f: Any) => `${f.source}->${f.sink_kind}:${f.api}${f.channel ? `@${f.channel}` : ""}`;
  const fa = new Map<string, Any[]>(), fb = new Map<string, Any[]>();
  for (const f of a.flows) fa.set(fk(f), [...(fa.get(fk(f)) ?? []), f]);
  for (const f of b.flows) fb.set(fk(f), [...(fb.get(fk(f)) ?? []), f]);
  for (const k of new Set([...fa.keys(), ...fb.keys()])) {
    const x = fa.get(k), y = fb.get(k);
    const ux = x?.some((f) => !f.guarded) ?? false, uy = y?.some((f) => !f.guarded) ?? false;
    if (x && !y) add({ id: `flow:${k}`, category: "taint-flow", status: ux ? "improved" : "changed", before: "present", after: "absent", note: `flow ${k} no longer detected` });
    else if (!x && y) add({ id: `flow:${k}`, category: "taint-flow", status: uy ? "regressed" : "changed", before: "absent", after: uy ? "present" : "present-guarded", note: `new flow ${k}${uy ? "" : " (guarded)"}` });
    else if (ux !== uy) add({ id: `flow:${k}`, category: "taint-flow", status: uy ? "regressed" : "improved", before: ux ? "unguarded" : "guarded", after: uy ? "unguarded" : "guarded", note: `flow ${k}: ${ux ? "unguarded" : "guarded"} -> ${uy ? "unguarded" : "guarded"} (guard is a heuristic: ${y?.[0]?.guard ?? x?.[0]?.guard ?? "n/a"})` });
  }

  // IOCs (neutral: reported as changed)
  const ia = new Set<string>(a.iocs.map((i: Any) => `${i.kind}:${i.value}`)), ib = new Set<string>(b.iocs.map((i: Any) => `${i.kind}:${i.value}`));
  for (const k of ib) if (!ia.has(k)) add({ id: `ioc:${k}`, category: "ioc", status: "changed", before: null, after: k, note: `IOC added: ${k}` });
  for (const k of ia) if (!ib.has(k)) add({ id: `ioc:${k}`, category: "ioc", status: "changed", before: k, after: null, note: `IOC removed: ${k}` });

  // parse health
  const pa = a.summary.parse_errors, pb = b.summary.parse_errors;
  if (pa !== pb) add({ id: "files:parse_errors", category: "coverage", status: "changed", before: pa, after: pb, note: "number of unparsable files changed; coverage differs" });

  items.sort((p, q) => (p.id < q.id ? -1 : p.id > q.id ? 1 : 0));
  const summary = { improved: items.filter((i) => i.status === "improved").length, regressed: items.filter((i) => i.status === "regressed").length, changed: items.filter((i) => i.status === "changed").length, total: items.length };
  return createEvidence({
    subject: evB.subject,
    provider: { id: "rtk-js-analyzer", name: "RTK JavaScript/Electron static analyzer", version: "0.1.0" },
    predicate_type: "rtk.javascript-application-delta",
    operation: "compare_javascript_applications",
    parameters: { before: evA.evidence_id, after: evB.evidence_id },
    normalized_result: { before: { evidence_id: evA.evidence_id, sha256: evA.subject?.digest.sha256 ?? null }, after: { evidence_id: evB.evidence_id, sha256: evB.subject?.digest.sha256 ?? null }, items, summary },
    confidence: "derived",
    authority: "shipped-artifact",
    limitations: [
      "delta is computed from two static analyses and inherits all of their limitations (heuristic taint and guard detection, 'dynamic' values are not compared)",
      "'improved'/'regressed' follows a fixed polarity table for webPreferences, sender validation, dangerous sinks and flows; IOC changes are reported as 'changed' because their meaning is analyst-dependent",
      ...new Set([...evA.limitations.slice(0, 0), ...evB.limitations.filter((l) => l.startsWith("time budget") || l.includes("exceeded"))]),
    ],
    evidence_links: [evA.evidence_id, evB.evidence_id],
  });
}
