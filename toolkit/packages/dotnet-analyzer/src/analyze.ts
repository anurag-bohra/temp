import { readFileSync } from "node:fs";
import { basename, resolve } from "node:path";
import { createEvidence, sha256Hex } from "@rtk/evidence";
import type { Evidence } from "@rtk/evidence";
import { deriveIndicators } from "./indicators.ts";
import type { Indicator } from "./indicators.ts";
import { ensureHelperBuilt, runHelper } from "./helper.ts";

export const PROVIDER = { id: "rtk-dotnet-analyzer", name: "RTK static .NET assembly analyzer (System.Reflection.Metadata, no assembly loading)", version: "1" };

export interface InspectOptions { timeoutMs?: number; cacheDir?: string; /** throw NotManagedError instead of returning managed:false evidence */ requireManaged?: boolean }
export class NotManagedError extends Error { reason: string; constructor(reason: string) { super(`not a managed assembly: ${reason}`); this.reason = reason; } }

export interface ManagedMethod {
  full_name: string; declaring_type: string; name: string; signature: string; return_type: string | null; token: string;
  flags: number; flag_names: string; impl_flags: number; rva: number; il_length: number; il_sha256: string | null;
  body_status: string; is_pinvoke: boolean; literals: string[];
}
export interface CallEdge { caller: string; opcode: string; target: string; target_type: string | null; target_name: string | null; target_kind: string; il_offset: number }
export interface PInvoke { dll: string | null; entry_point: string; declaring_method: string; declaring_type: string; method_name: string; flags: string }
export interface ResourceInfo { name: string; location: string; size: number | null; sha256: string | null; kind: string }
export interface ManagedResult {
  managed: true;
  artifact: { byte_length: number; sha256: string };
  identity: { name: string | null; module_name: string; version: string | null; culture: string | null; mvid: string; public_key_token: string | null; metadata_version: string; is_assembly: boolean; machine: string; cor_flags: string | null };
  target_framework: string | null; custom_attributes: string[];
  assembly_references: { name: string; version: string; public_key_token: string | null; culture: string }[];
  module_references: string[];
  types: { full_name: string; flags: number; base_type: string | null; methods: string[] }[];
  methods: ManagedMethod[]; call_edges: CallEdge[];
  method_literals: { method: string; literals: string[] }[];
  user_string_literals: { token: string; value: string }[];
  pinvokes: PInvoke[]; resources: ResourceInfo[]; issues: string[];
  indicators: Indicator[];
}
export interface NotManagedResult { managed: false; reason: string; machine?: string; artifact: { byte_length: number; sha256: string } }

const LIMITATIONS = [
  "Static analysis only: the assembly was parsed byte-wise, never loaded or executed.",
  "Call edges come from call/callvirt/newobj/ldftn/ldvirtftn/jmp (and ldtoken of methods); calls through delegates, reflection, or computed targets are not resolved.",
  "ldstr literals are attributed to the method containing the ldstr instruction; strings built at run time or decrypted are not visible.",
  "Indicators are heuristic triage hints from a fixed rule table, not a maliciousness verdict.",
  "Method identity is Namespace.Type::Name(param-types); return type and generic arity are not part of the key, so overloads differing only in return type collapse.",
  "Attribute argument values other than TargetFrameworkAttribute's string are not decoded; mixed-mode/ReadyToRun native code is not analysed.",
];

export function isManaged(r: ManagedResult | NotManagedResult): r is ManagedResult { return r.managed; }

export async function inspectManagedAssembly(path: string, opts: InspectOptions = {}): Promise<Evidence> {
  const abs = resolve(path);
  const bytes = readFileSync(abs);
  const sha = sha256Hex(bytes);
  const dll = ensureHelperBuilt(opts.cacheDir);
  const raw = await runHelper(dll, abs, opts.timeoutMs ?? 60_000) as ManagedResult | NotManagedResult;
  if (!raw.managed) {
    if (opts.requireManaged) throw new NotManagedError(raw.reason);
    return createEvidence({
      subject: { name: basename(abs), digest: { sha256: sha }, local_path: abs, format: null, architecture: raw.machine ?? null },
      provider: PROVIDER, predicate_type: "rtk.dotnet", operation: "inspect_managed_assembly", parameters: {},
      normalized_result: raw, confidence: "observed", authority: "shipped-artifact",
      limitations: ["File is not a .NET assembly; no managed analysis was performed.", `Reason: ${raw.reason}`],
    });
  }
  const indicators = deriveIndicators(raw.call_edges, raw.pinvokes);
  const result: ManagedResult = { ...raw, indicators };
  const partial = result.issues.length > 0;
  return createEvidence({
    subject: { name: basename(abs), digest: { sha256: sha }, local_path: abs, format: "pe", architecture: result.identity.machine },
    provider: PROVIDER, predicate_type: "rtk.dotnet", operation: "inspect_managed_assembly", parameters: {},
    normalized_result: result,
    confidence: partial ? "derived" : "observed", authority: "shipped-artifact",
    limitations: [...LIMITATIONS, ...(partial ? [`PARTIAL: ${result.issues.length} decode issue(s) (truncated/corrupt data); see normalized_result.issues.`] : [])],
    locations: result.methods.filter((m) => m.rva !== 0).map((m) => ({ kind: "method-rva", rva: m.rva, method: m.full_name })),
  });
}

export function managedResultOf(e: Evidence): ManagedResult {
  const n = e.normalized_result as ManagedResult | NotManagedResult;
  if (!n || !n.managed) throw new NotManagedError(n ? (n as NotManagedResult).reason : "empty evidence");
  return n;
}
