// Facts: a normalised view of many Evidence records (REA operations and toolkit operations) used by the rule engine.
import type { Evidence } from "@rtk/evidence";
import { extractIocs, IocSet } from "./ioc.ts";

export interface Sink { kind: string; api: string; where: string | null; argument?: string | null; taint?: string | null; evidence_id: string }
export interface Flow { from: string; to: string; where: string | null; evidence_id: string }
export interface Anomaly { kind: string; detail: string; evidence_id: string }
export interface YaraHit { rule: string; tags: string[]; target: string; evidence_id: string }
export interface ElectronWindow { nodeIntegration: boolean | "dynamic" | "unset"; contextIsolation: boolean | "dynamic" | "unset"; sandbox: boolean | "dynamic" | "unset"; where: string | null; evidence_id: string }
export interface IpcFact { channel: string; senderValidation: boolean | null; where: string | null; evidence_id: string }
export interface Facts {
  apis: Map<string, Set<string>>; iocs: IocSet; permissions: Map<string, Set<string>>; sinks: Sink[]; flows: Flow[]; anomalies: Anomaly[]; yara: YaraHit[];
  electron: { windows: ElectronWindow[]; ipc: IpcFact[]; contextBridgeApis: number };
  features: { maxSectionEntropy?: number; imphash?: string; hardeningWeak?: boolean; overlayBytes?: number; stripped?: boolean };
  tags: Map<string, Set<string>>; evidenceIds: Set<string>; evidenceCount: number; allowDomains: string[];
}
export const newFacts = (allowDomains: string[] = []): Facts => ({
  apis: new Map(), iocs: new IocSet(), permissions: new Map(), sinks: [], flows: [], anomalies: [], yara: [],
  electron: { windows: [], ipc: [], contextBridgeApis: 0 }, features: {}, tags: new Map(), evidenceIds: new Set(), evidenceCount: 0, allowDomains,
});
const addTo = (m: Map<string, Set<string>>, k: string, id: string) => { if (!m.has(k)) m.set(k, new Set()); m.get(k)!.add(id); };
export const addApi = (f: Facts, name: unknown, id: string): void => {
  if (typeof name !== "string" || !name) return; const base = name.replace(/@.*$/u, "").replace(/^<EXTERNAL>::/u, "");
  for (const v of new Set([base, base.split("::").pop()!, base.split(".").pop()!])) addTo(f.apis, v, id); addTo(f.apis, base, id);
};
export const addTag = (f: Facts, tag: string, id: string): void => addTo(f.tags, tag, id);
export const addPermission = (f: Facts, p: string, id: string): void => addTo(f.permissions, p, id);
export const scan = (f: Facts, text: unknown, context: string, id: string): void => { if (typeof text === "string") extractIocs(text, f.iocs, { context, evidenceId: id, allowDomains: f.allowDomains }); };

export type FactsAdapter = { name: string; match: (e: Evidence) => boolean; apply: (e: Evidence, f: Facts) => void };
const adapters: FactsAdapter[] = [];
export const registerFactsAdapter = (a: FactsAdapter): void => { const i = adapters.findIndex((x) => x.name === a.name); if (i >= 0) adapters[i] = a; else adapters.push(a); };
export const registeredAdapters = (): string[] => adapters.map((a) => a.name);

/** Fold Evidence into Facts. Unknown operations are counted but contribute nothing (never guessed). */
export function addEvidence(f: Facts, e: Evidence): { handled: boolean } {
  f.evidenceIds.add(e.evidence_id); f.evidenceCount++; let handled = false;
  for (const a of adapters) if (a.match(e)) { a.apply(e, f); handled = true; }
  return { handled };
}
export function factsFromEvidence(evs: Evidence[], allowDomains: string[] = []): Facts { const f = newFacts(allowDomains); for (const e of evs) addEvidence(f, e); return f; }

type R = Record<string, unknown>; const asR = (x: unknown): R => (x && typeof x === "object" ? (x as R) : {}); const arr = (x: unknown): unknown[] => (Array.isArray(x) ? x : []);
const isOp = (op: string, provider?: RegExp) => (e: Evidence) => e.operation === op && (!provider || provider.test(e.provider.id));

// ---- adapters for REA v6.4.0 output (field names verified against real records) ----
registerFactsAdapter({ name: "rea:analyze_javascript_application", match: isOp("analyze_javascript_application", /^rea-/u), apply(e, f) {
  const r = asR(e.normalized_result); const id = e.evidence_id; const sg = asR(r.semantic_graph);
  for (const n of arr(sg.nodes).map(asR)) {
    const p = asR(n.properties); const mod = asR(n.identity).module_path as string | undefined;
    if (n.kind === "literal") scan(f, p.value, `js literal ${mod ?? ""}`, id);
    if (n.kind === "child-process") { f.sinks.push({ kind: "child-process", api: String(p.method ?? n.label), where: mod ?? null, argument: p.command === null ? null : String(p.command), evidence_id: id }); addApi(f, "child_process", id); addApi(f, String(p.method ?? "exec"), id); }
    if (n.kind === "request") { f.sinks.push({ kind: "network-request", api: String(p.method ?? n.label), where: mod ?? null, argument: p.endpoint === null ? null : String(p.endpoint), evidence_id: id }); }
    if (n.kind === "expression" && n.label === "eval") { f.sinks.push({ kind: "eval", api: "eval", where: mod ?? null, evidence_id: id }); addApi(f, "eval", id); }
    if (n.kind === "timer") addApi(f, "setInterval", id);
  }
  const g = asR(r.graph); const kinds = new Set(arr(g.nodes).map((n) => asR(n).kind as string));
  for (const n of arr(g.nodes).map(asR)) if (n.kind === "ipc-channel") for (const o of arr(n.observations).map(asR)) { const p = asR(o.properties); if (p.channel) f.electron.ipc.push({ channel: String(p.channel), senderValidation: null, where: null, evidence_id: id }); }
  if (kinds.has("context-bridge-api")) f.electron.contextBridgeApis += 1;
  const sum = asR(r.summary); if (typeof sum.sender_validation_observations === "number" && f.electron.ipc.length) for (const i of f.electron.ipc) if (i.evidence_id === id) i.senderValidation = sum.sender_validation_observations > 0;
  addTag(f, "javascript", id); if (kinds.has("electron-main")) addTag(f, "electron", id);
} });
registerFactsAdapter({ name: "rea:managed", match: (e) => /^rea-dotnet/u.test(e.provider.id) || e.operation === "inspect_managed_members" || e.operation === "inspect_managed_native_boundaries", apply(e, f) {
  const r = asR(e.normalized_result); const id = e.evidence_id; addTag(f, "dotnet", id);
  for (const l of arr(asR(r.user_strings).literals).map(asR)) scan(f, l.value, ".NET ldstr", id);
  for (const c of arr(r.call_edges).map(asR)) { if (c.target_name) { addApi(f, c.target_name, id); if (c.target_declaring_type) addApi(f, `${String(c.target_declaring_type)}::${String(c.target_name)}`, id); } }
  for (const p of arr(r.pinvoke_imports).map(asR)) { addApi(f, p.import_name, id); addApi(f, `${String(p.import_scope_name ?? "")}!${String(p.import_name)}`, id); addTag(f, "pinvoke", id); }
} });
registerFactsAdapter({ name: "rea:objdump", match: isOp("inspect_with_objdump"), apply(e, f) { const out = String(asR(e.normalized_result).stdout ?? ""); for (const line of out.split("\n")) { const m = /\*UND\*\s+\S+\s+(\S+)/u.exec(line); if (m) addApi(f, m[1], e.evidence_id); } } });
registerFactsAdapter({ name: "rea:native-provider", match: (e) => ["list_procedures", "list_strings", "search_strings"].includes(e.operation) && !/^rtk-/u.test(e.provider.id), apply(e, f) {
  const r = arr(e.normalized_result).map(asR);
  if (e.operation === "list_procedures") for (const p of r) { if (asR(p.procedure).external) addApi(f, String(p.value ?? "").replace("<EXTERNAL>::", ""), e.evidence_id); }
  else for (const s of r) scan(f, s.value, `native string @${String(s.address)}`, e.evidence_id);
} });
registerFactsAdapter({ name: "rea:android", match: isOp("inspect_android_package"), apply(e, f) { for (const p of arr(asR(e.normalized_result).permissions)) addPermission(f, String(p), e.evidence_id); addTag(f, "android", e.evidence_id); } });
registerFactsAdapter({ name: "rea:pe-resources", match: isOp("inspect_pe_resources"), apply(e, f) { for (const x of arr(asR(e.normalized_result).resources).map(asR)) { if (asR(x.type).id === 10) { addTag(f, "pe-rcdata-resource", e.evidence_id); f.iocs.add("embedded-resource", `RCDATA ${String(asR(x.name).name ?? asR(x.name).id)} sha256=${String(asR(x.payload).sha256)} bytes=${String(asR(asR(x.payload).location).bytes)}`, "unknown", "PE resource", e.evidence_id); } } } });
registerFactsAdapter({ name: "rea:pcap", match: isOp("inspect_pcap_capture"), apply(e, f) { const r = asR(e.normalized_result); for (const u of arr(r.http_request_uris)) scan(f, u, "pcap http", e.evidence_id); for (const d of arr(r.dns_queries)) scan(f, typeof d === "string" ? d : asR(d).name, "pcap dns", e.evidence_id); for (const s of arr(r.tls_sni_values)) scan(f, typeof s === "string" ? s : asR(s).name, "pcap sni", e.evidence_id); } });
registerFactsAdapter({ name: "rea:go", match: isOp("inspect_go_binary"), apply(e, f) { const b = asR(asR(e.normalized_result).build_info); f.iocs.add("toolchain", `go ${String(b.go_version)} module ${String(asR(b.module).path)}`, "unknown", "Go build info", e.evidence_id); addTag(f, "go", e.evidence_id); } });
registerFactsAdapter({ name: "rea:binary-layout", match: isOp("inspect_binary_layout"), apply(e, f) { const m = asR(asR(e.normalized_result).mitigations); if (m.stack_canary_indicator === false && m.executable_stack_indicator === true) { f.features.hardeningWeak = true; addTag(f, "weak-hardening", e.evidence_id); } } });
registerFactsAdapter({ name: "rea:wasm", match: isOp("inspect_wasm_artifact"), apply(e, f) { for (const x of arr(asR(asR(e.normalized_result).interface).entries).map(asR)) addApi(f, `${String(x.direction)}:${String(x.module ?? "")}.${String(x.name)}`, e.evidence_id); addTag(f, "wasm", e.evidence_id); } });
