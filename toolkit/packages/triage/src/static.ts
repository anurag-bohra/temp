// Built-in static features Evidence (identity, strings, ELF/PE structure) — no external engine, reads bytes only.
import { createEvidence, type Evidence } from "@rtk/evidence";
import { type Identity } from "./identify.ts";
import { extractStrings } from "./strings.ts";
import { parseElf, parsePe, type ElfFeatures, type PeFeatures } from "./features.ts";
import { type Facts, addApi, addTag, registerFactsAdapter, scan } from "./facts.ts";

export function staticFeatures(id: Identity): Evidence {
  if (!id.sha256) throw new Error("static features need a regular file");
  const limitations = ["Built-in parsers read headers/tables only; they do not unpack, emulate or execute the sample.", "String extraction is bounded (64 MiB scanned, 20,000 strings); UTF-16 scan is aligned to even offsets."];
  const st = extractStrings(id.path); let elf: ElfFeatures | null = null, pe: PeFeatures | null = null; let parseError: string | null = null;
  try { if (id.type === "elf") elf = parseElf(id.path); else if (id.type === "pe") pe = parsePe(id.path); } catch (e) { parseError = String((e as Error).message); limitations.push(`structure parse failed: ${parseError}`); }
  if (st.truncated) limitations.push("string extraction truncated");
  if (elf) limitations.push(...elf.limitations); if (pe) limitations.push(...pe.limitations);
  return createEvidence({
    subject: { name: id.path.split("/").pop()!, digest: { sha256: id.sha256 }, local_path: id.path, format: id.type, architecture: null },
    provider: { id: "rtk-triage-static", name: "rea-toolkit static feature extractor", version: "1" }, predicate_type: "rtk.static-features", operation: "extract_static_features",
    parameters: { min_string_length: 6 }, normalized_result: { identity: { type: id.type, size: id.size, md5: id.md5, sha1: id.sha1, sha256: id.sha256, entropy: id.entropy, magic: id.magic, notes: id.notes }, elf, pe, strings: { count: st.strings.length, truncated: st.truncated, scanned_bytes: st.scannedBytes, values: st.strings.map((s) => ({ v: s.value.slice(0, 300), o: s.offset, e: s.encoding })) }, parse_error: parseError },
    confidence: "observed", authority: "shipped-artifact", limitations, locations: [],
  });
}

registerFactsAdapter({ name: "rtk:static-features", match: (e) => e.operation === "extract_static_features", apply(e, f: Facts) {
  const r = e.normalized_result as { elf: ElfFeatures | null; pe: PeFeatures | null; strings: { values: { v: string; o: number }[] } }; const id = e.evidence_id;
  addTag(f, "feature-source", id);
  for (const s of r.strings.values) scan(f, s.v, `string @0x${s.o.toString(16)}`, id);
  if (r.elf) { addTag(f, "elf", id); for (const n of r.elf.undefinedSymbols) addApi(f, n, id); const me = Math.max(0, ...r.elf.sections.filter((s) => s.size > 4096).map((s) => s.entropy)); f.features.maxSectionEntropy = Math.max(f.features.maxSectionEntropy ?? 0, me); f.features.stripped = r.elf.stripped; if (r.elf.hardening.stackCanary === false && r.elf.hardening.executableStack === true) { f.features.hardeningWeak = true; addTag(f, "weak-hardening", id); } }
  if (r.pe) { addTag(f, "pe", id); if (r.pe.isDotNet) addTag(f, "dotnet", id); for (const m of r.pe.imports) for (const fn of m.functions) { addApi(f, fn, id); addApi(f, `${m.dll.toLowerCase()}!${fn}`, id); } const me = Math.max(0, ...r.pe.sections.filter((s) => s.size > 4096).map((s) => s.entropy)); f.features.maxSectionEntropy = Math.max(f.features.maxSectionEntropy ?? 0, me); f.features.overlayBytes = r.pe.overlayBytes; if (r.pe.imphash) f.features.imphash = r.pe.imphash; }
} });
registerFactsAdapter({ name: "rtk:yara", match: (e) => e.operation === "yara_scan", apply(e, f) { for (const m of ((e.normalized_result as { matches: { rule: string; target: string }[] }).matches)) f.yara.push({ rule: m.rule, tags: [], target: m.target, evidence_id: e.evidence_id }); } });
