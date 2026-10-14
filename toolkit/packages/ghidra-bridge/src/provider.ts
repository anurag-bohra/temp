import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { createEvidence } from "@rtk/evidence";
import type { Evidence } from "@rtk/evidence";
import type { AnalysisProvider, JsonObject, ProviderProfile, ProviderSupport, Target } from "@rtk/provider-router";
import { analyzeBinary, resolveInstallDir } from "./analyze.ts";
import type { AnalyzeOptions } from "./analyze.ts";
import type { GhidraFunction, GhidraSnapshot } from "./snapshot.ts";

export const GHIDRA_PROVIDER = { id: "rtk-ghidra-bridge", name: "RTK Ghidra bridge", version: "0.1.0" } as const;

export class ProcedureNotFoundError extends Error { constructor(m: string) { super(m); this.name = "ProcedureNotFoundError"; } }
export class OperationArgumentError extends Error { constructor(m: string) { super(m); this.name = "OperationArgumentError"; } }

export const GHIDRA_OPERATIONS = [
  "analyze_function", "binary_overview", "list_procedures", "list_strings", "procedure_callees", "procedure_callers",
  "procedure_info", "procedure_pseudo_code", "search_strings", "trace_call_path", "xrefs",
] as const;

export interface GhidraProviderOptions extends AnalyzeOptions {
  /** Test seam: replace the analysis step. */
  analyze?: (path: string, opts: AnalyzeOptions) => Promise<GhidraSnapshot>;
}

const cmp = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);
const num = (a: unknown, name: string, d: number, min = 0, max = 100000): number => {
  if (a === undefined) return d;
  if (typeof a !== "number" || !Number.isInteger(a) || a < min || a > max) throw new OperationArgumentError(`${name} must be an integer in [${min}, ${max}]`);
  return a;
};
const strArg = (a: unknown, name: string): string => {
  if (typeof a !== "string" || a === "") throw new OperationArgumentError(`${name} is required (non-empty string)`);
  return a;
};
const normAddr = (s: string): string | null => (/^0x[0-9a-f]+$/iu.test(s) ? "0x" + BigInt(s).toString(16) : null);

function ghidraVersion(dir: string | null): string {
  if (!dir) return "unavailable";
  try { return /application\.version=(\S+)/u.exec(readFileSync(join(dir, "Ghidra", "application.properties"), "utf8"))?.[1] ?? "unknown"; } catch { return "unknown"; }
}

export class GhidraProvider implements AnalysisProvider {
  readonly id = "ghidra";
  readonly name = "Ghidra (headless)";
  readonly kind = "deep" as const;
  readonly version: string;
  readonly #opts: GhidraProviderOptions;
  readonly #install: string | null;
  #snap: GhidraSnapshot | null = null;
  #target: Target | null = null;

  constructor(opts: GhidraProviderOptions = {}) {
    this.#opts = opts;
    this.#install = resolveInstallDir(opts.installDir);
    this.version = ghidraVersion(this.#install);
  }

  supports(target: Target): ProviderSupport {
    if (!this.#install) return { status: "unavailable", reason: "Ghidra installation not found (set GHIDRA_INSTALL_DIR)" };
    if (!existsSync(target.path)) return { status: "unsupported", reason: `target file not found: ${target.path}` };
    return { status: "supported", reason: "Ghidra can import most native executable formats; unrecognised formats are imported as raw binary only if the loader accepts them" };
  }

  profile(): ProviderProfile {
    return { settings: {
      ghidra_version: this.version, import_mode: "ephemeral-source-immutable", analysis: "ghidra default analyzers",
      decomp_timeout_sec: this.#opts.decompTimeoutSec ?? 30, decomp_budget_sec: this.#opts.decompBudgetSec ?? 600,
      max_functions: this.#opts.maxFunctions ?? 5000, max_strings: this.#opts.maxStrings ?? 50000, max_symbols: this.#opts.maxSymbols ?? 50000,
    } };
  }

  operations(): readonly string[] { return GHIDRA_OPERATIONS; }

  async open(target: Target): Promise<void> {
    if (this.#snap) throw new Error("GhidraProvider already open; close() first");
    const run = this.#opts.analyze ?? analyzeBinary;
    const snap = await run(target.path, this.#opts);
    if (snap.source.sha256 !== target.sha256) throw new Error(`Analysed file sha256 ${snap.source.sha256} does not match target ${target.sha256}`);
    this.#snap = snap;
    this.#target = target;
  }

  async close(): Promise<void> { this.#snap = null; this.#target = null; }

  /** The raw snapshot (for persistence / snapshot import by the router). */
  snapshot(): GhidraSnapshot | null { return this.#snap; }

  async call(operation: string, args: JsonObject = {}): Promise<Evidence> {
    const s = this.#snap;
    if (!s || !this.#target) throw new Error("GhidraProvider not open");
    switch (operation) {
      case "binary_overview": return this.#overview(s);
      case "list_procedures": return this.#listProcedures(s, args);
      case "procedure_info": { const f = this.#resolve(s, args.procedure); return this.#ev(s, operation, args, { procedure: this.#fnView(s, f) }, "observed", [], [loc(f)]); }
      case "list_strings": return this.#listStrings(s, args);
      case "search_strings": return this.#searchStrings(s, args);
      case "xrefs": return this.#xrefs(s, args);
      case "procedure_callers": { const f = this.#resolve(s, args.procedure); return this.#ev(s, operation, args, { procedure: ref(f), callers: f.callers }, "observed", ["Callers are call-flow references recorded by Ghidra; calls through unresolved function pointers are not included."], [loc(f)]); }
      case "procedure_callees": { const f = this.#resolve(s, args.procedure); return this.#ev(s, operation, args, { procedure: ref(f), callees: f.callees, has_unresolved_indirect_calls: f.has_unresolved_indirect_calls }, "observed", f.has_unresolved_indirect_calls ? ["This procedure contains indirect calls whose targets Ghidra did not resolve; callee list is incomplete."] : [], [loc(f)]); }
      case "procedure_pseudo_code": {
        const f = this.#resolve(s, args.procedure);
        const d = s.decompiled.find((x) => x.entry === f.entry);
        if (!d || d.code === null) throw new Error(`No pseudocode for ${f.name}: ${d?.error ?? (f.external ? "external function" : "not decompiled")}`);
        return this.#ev(s, operation, args, { procedure: ref(f), pseudo_code: d.code, truncated: d.truncated }, "derived", ["Pseudocode is decompiler output (Ghidra), a derived reconstruction, not the original source; types and names are heuristic."], [loc(f)]);
      }
      case "analyze_function": return this.#analyzeFunction(s, args);
      case "trace_call_path": return this.#trace(s, args);
      default: throw new OperationArgumentError(`Unknown operation: ${operation}`);
    }
  }

  // ---- helpers
  #ev(s: GhidraSnapshot, operation: string, parameters: JsonObject, normalized: unknown, confidence: "observed" | "derived" | "inferred", limitations: string[], locations: unknown[] = []): Evidence {
    return createEvidence({
      subject: { name: s.program.name, digest: { sha256: s.source.sha256 }, local_path: s.source.path, format: s.program.format, architecture: s.program.language_id },
      provider: GHIDRA_PROVIDER,
      analysis_profile: { provider: { id: this.id, name: "Ghidra", version: this.version }, settings: this.profile().settings },
      predicate_type: operation,
      operation,
      parameters,
      normalized_result: normalized,
      confidence,
      authority: "shipped-artifact",
      limitations: [...limitations, "Static analysis of a read-only copy; nothing was executed."],
      locations,
    });
  }

  #resolve(s: GhidraSnapshot, p: unknown): GhidraFunction {
    const q = strArg(p, "procedure");
    const addr = normAddr(q);
    if (addr) {
      const byEntry = s.functions.find((f) => f.entry === addr);
      if (byEntry) return byEntry;
      const v = BigInt(addr);
      const cont = s.functions.find((f) => f.body.some((r) => BigInt(r.start) <= v && v <= BigInt(r.end)));
      if (cont) return cont;
      throw new ProcedureNotFoundError(`Unknown procedure: no function at or containing ${q}`);
    }
    const hits = s.functions.filter((f) => f.name === q);
    if (hits.length === 1) return hits[0];
    if (hits.length > 1) throw new ProcedureNotFoundError(`Ambiguous procedure name "${q}": ${hits.map((h) => h.entry).join(", ")}; use an address`);
    throw new ProcedureNotFoundError(`Unknown procedure: "${q}"`);
  }

  #fnView(s: GhidraSnapshot, f: GhidraFunction) {
    return { entry: f.entry, name: f.name, external: f.external, thunk: f.thunk, thunk_target: f.thunk_target, signature: f.signature, calling_convention: f.calling_convention, namespace: f.namespace, body: f.body, locals: f.locals, callers: f.callers, callees: f.callees, has_unresolved_indirect_calls: f.has_unresolved_indirect_calls };
  }

  #overview(s: GhidraSnapshot): Evidence {
    return this.#ev(s, "binary_overview", {}, {
      name: s.program.name, format: s.program.format, language_id: s.program.language_id, processor: s.program.processor, endian: s.program.endian,
      pointer_size: s.program.pointer_size, image_base: s.program.image_base, sha256: s.source.sha256, entry_points: s.program.entry_points, memory_blocks: s.memory_blocks,
      counts: { functions: s.functions.filter((f) => !f.external).length, external_functions: s.functions.filter((f) => f.external).length, strings: s.strings.length, imports: s.externals.length, symbols: s.symbols.length },
      ghidra_version: s.ghidra_version,
    }, "observed", [...(s.strings_truncated ? ["String list truncated by maxStrings."] : []), ...(s.symbols_truncated ? ["Symbol list truncated by maxSymbols."] : []), ...s.warnings]);
  }

  #listProcedures(s: GhidraSnapshot, a: JsonObject): Evidence {
    const offset = num(a.offset, "offset", 0), limit = num(a.limit, "limit", 200, 1, 5000);
    const incl = a.include_external === true;
    const filter = typeof a.name_filter === "string" ? a.name_filter.toLowerCase() : null;
    const all = s.functions.filter((f) => (incl || !f.external) && (!filter || f.name.toLowerCase().includes(filter)))
      .sort((x, y) => (x.external === y.external ? cmp(x.entry.padStart(20, "0"), y.entry.padStart(20, "0")) : x.external ? 1 : -1));
    const page = all.slice(offset, offset + limit).map((f) => ({ entry: f.entry, name: f.name, external: f.external, thunk: f.thunk, signature: f.signature }));
    return this.#ev(s, "list_procedures", a, { total: all.length, offset, limit, procedures: page }, "observed", all.length > offset + limit ? ["Result page truncated; use offset/limit."] : []);
  }

  #listStrings(s: GhidraSnapshot, a: JsonObject): Evidence {
    const offset = num(a.offset, "offset", 0), limit = num(a.limit, "limit", 200, 1, 5000), minLen = num(a.min_length, "min_length", 1, 1, 100000);
    const all = s.strings.filter((x) => x.value.length >= minLen);
    const page = all.slice(offset, offset + limit).map((x) => ({ address: x.address, value: x.value, encoding: x.encoding, xref_count: x.xrefs.length }));
    return this.#ev(s, "list_strings", a, { total: all.length, offset, limit, strings: page }, "observed",
      ["Only strings Ghidra defined as string data are listed; encoded/obfuscated strings are not covered.", ...(s.strings_truncated ? ["String export truncated by maxStrings."] : [])]);
  }

  #searchStrings(s: GhidraSnapshot, a: JsonObject): Evidence {
    const pattern = strArg(a.pattern, "pattern");
    const mode = a.mode === undefined ? "literal" : a.mode;
    if (mode !== "literal" && mode !== "regex") throw new OperationArgumentError(`mode must be "literal" or "regex"`);
    const cs = a.case_sensitive === true;
    const limit = num(a.limit, "limit", 200, 1, 5000);
    let test: (v: string) => boolean;
    if (mode === "literal") { const p = cs ? pattern : pattern.toLowerCase(); test = (v) => (cs ? v : v.toLowerCase()).includes(p); }
    else {
      if (pattern.length > 500) throw new OperationArgumentError("regex too long (max 500)");
      let re: RegExp;
      try { re = new RegExp(pattern, cs ? "u" : "iu"); } catch (e) { throw new OperationArgumentError(`invalid regex: ${(e as Error).message}`); }
      test = (v) => re.test(v.length > 10000 ? v.slice(0, 10000) : v);
    }
    const all = s.strings.filter((x) => test(x.value));
    const matches = all.slice(0, limit).map((x) => ({ address: x.address, value: x.value, encoding: x.encoding, xrefs: x.xrefs }));
    return this.#ev(s, "search_strings", a, { mode, total_matches: all.length, matches }, "observed",
      ["Searches only defined strings in the Ghidra snapshot.", ...(all.length > limit ? ["Matches truncated by limit."] : [])],
      matches.map((m) => ({ kind: "string", address: m.address })));
  }

  #xrefs(s: GhidraSnapshot, a: JsonObject): Evidence {
    const raw = strArg(a.address, "address");
    const addr = normAddr(raw);
    if (!addr) throw new OperationArgumentError("address must be hex like 0x401000");
    const refs: { from: string; type: string; function: string | null; function_entry: string | null; kind: string }[] = [];
    const str = s.strings.find((x) => x.address === addr);
    if (str) for (const x of str.xrefs) refs.push({ ...x, kind: "string-reference" });
    for (const f of s.functions) for (const cs of f.call_sites) if (cs.target === addr) refs.push({ from: cs.site, type: "CALL", function: f.name, function_entry: f.entry, kind: "call" });
    refs.sort((x, y) => cmp(x.from.padStart(20, "0"), y.from.padStart(20, "0")));
    return this.#ev(s, "xrefs", a, { address: addr, count: refs.length, references: refs }, "observed",
      ["Snapshot xrefs cover references to defined strings and direct call targets only; references to other data addresses are not exported."],
      refs.map((r) => ({ kind: "xref", address: r.from })));
  }

  #analyzeFunction(s: GhidraSnapshot, a: JsonObject): Evidence {
    const f = this.#resolve(s, a.procedure);
    const d = s.decompiled.find((x) => x.entry === f.entry);
    const inBody = (addr: string) => { const v = BigInt(addr); return f.body.some((r) => BigInt(r.start) <= v && v <= BigInt(r.end)); };
    const strings = s.strings.map((x) => ({ x, refs: x.xrefs.filter((r) => r.function_entry === f.entry || inBody(r.from)) })).filter((e) => e.refs.length)
      .map((e) => ({ address: e.x.address, value: e.x.value, encoding: e.x.encoding, referenced_from: e.refs.map((r) => r.from) }));
    const byEntry = new Map(s.functions.map((g) => [g.entry, g]));
    const importsUsed = f.callees.map((c) => byEntry.get(c.entry)).filter((g): g is GhidraFunction => !!g && (g.external || g.thunk))
      .map((g) => ({ name: g.name, entry: g.entry, via: g.external ? "external" : "thunk", ...(g.thunk_target ? { thunk_target: byEntry.get(g.thunk_target)?.name ?? g.thunk_target } : {}) }));
    return this.#ev(s, "analyze_function", a, {
      identity: { entry: f.entry, name: f.name, signature: f.signature, namespace: f.namespace, thunk: f.thunk, external: f.external },
      body: f.body, locals: f.locals, decompiler_locals: d?.high_locals ?? [], pseudo_code: d?.code ?? null, pseudo_code_error: d?.error ?? null,
      calls: f.call_sites.map((c) => ({ ...c, target_name: c.target ? byEntry.get(c.target)?.name ?? null : null })),
      callers: f.callers, referenced_strings: strings, imports_used: importsUsed,
      has_unresolved_indirect_calls: f.has_unresolved_indirect_calls,
    }, d?.code ? "derived" : "observed", [
      "Pseudocode is decompiler output (derived).",
      ...(f.has_unresolved_indirect_calls ? ["Contains indirect calls with unresolved targets; call list is incomplete."] : []),
      ...(d?.truncated ? [`Decompilation incomplete: ${d.error}`] : []),
    ], [loc(f)]);
  }

  #trace(s: GhidraSnapshot, a: JsonObject): Evidence {
    const start = this.#resolve(s, a.start), goal = this.#resolve(s, a.goal);
    const dir = a.direction === undefined ? "forward" : a.direction;
    if (dir !== "forward" && dir !== "backward") throw new OperationArgumentError(`direction must be "forward" or "backward"`);
    const maxDepth = num(a.max_depth, "max_depth", 16, 1, 1000);
    const byEntry = new Map(s.functions.map((g) => [g.entry, g]));
    const next = (f: GhidraFunction) => (dir === "forward" ? f.callees : f.callers).map((c) => c.entry).sort();
    const prev = new Map<string, string | null>([[start.entry, null]]);
    const depth = new Map<string, number>([[start.entry, 0]]);
    let frontier = [start.entry];
    let depthLimited = false;
    let reached = start.entry === goal.entry;
    while (!reached && frontier.length) {
      const nf: string[] = [];
      for (const e of frontier) {
        const d = depth.get(e)!;
        const f = byEntry.get(e);
        if (!f) continue;
        for (const n of next(f)) {
          if (prev.has(n)) continue;
          if (d + 1 > maxDepth) { depthLimited = true; continue; }
          prev.set(n, e); depth.set(n, d + 1); nf.push(n);
          if (n === goal.entry) reached = true;
        }
        if (reached) break;
      }
      frontier = nf;
    }
    let path: { entry: string; name: string }[] = [];
    if (reached) for (let c: string | null | undefined = goal.entry; c; c = prev.get(c)) path.unshift({ entry: c, name: byEntry.get(c)?.name ?? c });
    // Completeness: forward search is blind to unresolved indirect calls in visited functions; backward search is blind to
    // indirect calls anywhere in the program (an unseen caller could be reached through a function pointer).
    const blind = dir === "forward"
      ? [...prev.keys()].map((e) => byEntry.get(e)).filter((f): f is GhidraFunction => !!f && f.has_unresolved_indirect_calls)
      : s.functions.filter((f) => f.has_unresolved_indirect_calls);
    const status = reached ? "reached" : (blind.length > 0 || depthLimited) ? "unknown" : "not-reached";
    const lims = ["Call graph comes from Ghidra's resolved direct call references."];
    if (!reached && blind.length) lims.push(`Goal not found, but ${blind.length} function(s) contain unresolved indirect calls (${blind.slice(0, 5).map((f) => f.name).join(", ")}${blind.length > 5 ? ", ..." : ""}), so absence of a path is not established.`);
    if (!reached && depthLimited) lims.push(`Search truncated at max_depth=${maxDepth}.`);
    return this.#ev(s, "trace_call_path", a, {
      start: ref(start), goal: ref(goal), direction: dir, goal_status: status, path, visited: prev.size,
      unresolved_indirect_call_functions: blind.map((f) => ({ entry: f.entry, name: f.name })),
    }, "derived", lims, path.map((p) => ({ kind: "procedure", address: p.entry })));
  }
}

const ref = (f: GhidraFunction) => ({ entry: f.entry, name: f.name });
const loc = (f: GhidraFunction) => ({ kind: "procedure", address: f.entry, name: f.name });
