import { createHash } from "node:crypto";
import type { Ioc } from "../ioc.ts";
import { defang } from "../ioc.ts";
import type { Finding } from "../rules.ts";

export interface ReportInput { sample: { name: string; sha256: string; sha1: string; md5: string; size: number; type: string }; iocs: Ioc[]; findings: Finding[]; score: { score: number; band: string; note: string; by_tactic: Record<string, number> }; generatedAt: string; evidenceBundleSha256?: string; limitations: string[]; unknowns?: { question: string; status: string }[] }

const uuid5 = (name: string): string => { const ns = Buffer.from("6ba7b8109dad11d180b400c04fd430c8", "hex"); const h = createHash("sha1").update(ns).update(name).digest(); h[6] = (h[6]! & 0x0f) | 0x50; h[8] = (h[8]! & 0x3f) | 0x80; const x = h.subarray(0, 16).toString("hex"); return `${x.slice(0, 8)}-${x.slice(8, 12)}-${x.slice(12, 16)}-${x.slice(16, 20)}-${x.slice(20)}`; };
const esc = (s: string) => s.replace(/\\/gu, "\\\\").replace(/'/gu, "\\'");
const ROUTABLE = new Set(["public", "unknown"]);

/** STIX 2.1 bundle: identity, file observable, indicators for routable network IOCs and file hashes, malware-analysis-free report. Non-routable/example IOCs are excluded unless includeNonRoutable. */
export function toStix(r: ReportInput, o: { includeNonRoutable?: boolean } = {}): Record<string, unknown> {
  const created = r.generatedAt; const objs: Record<string, unknown>[] = [];
  const identity = { type: "identity", spec_version: "2.1", id: `identity--${uuid5("rea-toolkit")}`, created, modified: created, name: "rea-toolkit triage", identity_class: "system" }; objs.push(identity);
  const file = { type: "file", spec_version: "2.1", id: `file--${uuid5("file:" + r.sample.sha256)}`, hashes: { "SHA-256": r.sample.sha256, "SHA-1": r.sample.sha1, "MD5": r.sample.md5 }, size: r.sample.size, name: r.sample.name }; objs.push(file);
  const refs: string[] = [file.id];
  const mk = (pattern: string, name: string, labels: string[], extra: Record<string, unknown> = {}) => { const id = `indicator--${uuid5(pattern)}`; if (!objs.some((x) => x.id === id)) { objs.push({ type: "indicator", spec_version: "2.1", id, created, modified: created, created_by_ref: identity.id, name, pattern, pattern_type: "stix", valid_from: created, indicator_types: ["malicious-activity"], labels, confidence: 30, ...extra }); refs.push(id); } };
  mk(`[file:hashes.'SHA-256' = '${r.sample.sha256}']`, `Sample ${r.sample.name}`, ["triaged-sample"], { description: `Analysed sample (triage band: ${r.score.band}). Heuristic triage, not a verdict.` });
  for (const i of r.iocs) {
    if (!o.includeNonRoutable && !ROUTABLE.has(i.classification)) continue; const lab = [`rtk-${i.classification}`];
    if (i.kind === "url") mk(`[url:value = '${esc(i.value)}']`, `URL ${defang(i.value)}`, lab, { x_rtk_evidence_ids: i.evidence_ids });
    else if (i.kind === "domain") mk(`[domain-name:value = '${esc(i.value)}']`, `Domain ${defang(i.value)}`, lab, { x_rtk_evidence_ids: i.evidence_ids });
    else if (i.kind === "ipv4") mk(`[ipv4-addr:value = '${esc(i.value)}']`, `IPv4 ${defang(i.value)}`, lab, { x_rtk_evidence_ids: i.evidence_ids });
    else if (i.kind === "sha256") mk(`[file:hashes.'SHA-256' = '${i.value}']`, `Hash ${i.value.slice(0, 12)}…`, lab, { x_rtk_evidence_ids: i.evidence_ids });
    else if (i.kind === "email") mk(`[email-addr:value = '${esc(i.value)}']`, `Email ${defang(i.value)}`, lab, { x_rtk_evidence_ids: i.evidence_ids });
  }
  objs.push({ type: "report", spec_version: "2.1", id: `report--${uuid5("report:" + r.sample.sha256 + r.generatedAt)}`, created, modified: created, created_by_ref: identity.id, name: `Triage of ${r.sample.name}`, published: created, report_types: ["threat-report"], object_refs: refs, description: `${r.findings.length} rule findings; score ${r.score.score} (${r.score.band}). ${r.score.note}` });
  return { type: "bundle", id: `bundle--${uuid5("bundle:" + r.sample.sha256 + r.generatedAt)}`, objects: objs };
}

/** MISP event JSON (importable via the MISP API/UI add-event). */
export function toMisp(r: ReportInput): Record<string, unknown> {
  const attr = (type: string, category: string, value: string, comment: string, to_ids: boolean) => ({ type, category, value, comment, to_ids, distribution: 0 });
  const A = [attr("sha256", "Payload delivery", r.sample.sha256, "sample", true), attr("sha1", "Payload delivery", r.sample.sha1, "sample", true), attr("md5", "Payload delivery", r.sample.md5, "sample", true), attr("filename", "Payload delivery", r.sample.name, "sample name", false)];
  for (const i of r.iocs) {
    const ids = ROUTABLE.has(i.classification); const c = `${i.classification}; ${i.contexts[0] ?? ""}`.slice(0, 200);
    if (i.kind === "url") A.push(attr("url", "Network activity", i.value, c, ids)); else if (i.kind === "domain") A.push(attr("domain", "Network activity", i.value, c, ids)); else if (i.kind === "ipv4") A.push(attr("ip-dst", "Network activity", i.value, c, ids));
    else if (i.kind === "email") A.push(attr("email-src", "Network activity", i.value, c, false)); else if (i.kind === "registry-key") A.push(attr("regkey", "Persistence mechanism", i.value, c, false)); else if (i.kind === "sha256") A.push(attr("sha256", "Payload delivery", i.value, `referenced: ${c}`, false));
  }
  for (const f of r.findings) A.push(attr("text", "Other", `${f.rule_id}: ${f.title}`, `severity ${f.severity}; ${f.attack.join(",")}`, false));
  return { Event: { info: `rea-toolkit triage: ${r.sample.name}`, date: r.generatedAt.slice(0, 10), threat_level_id: "4", analysis: "1", distribution: "0", Attribute: A, Tag: [{ name: "rtk:static-triage" }, ...r.findings.flatMap((f) => f.attack.map((a) => ({ name: `mitre-attack:${a}` })))].filter((t, i, a) => a.findIndex((x) => x.name === t.name) === i) } };
}

const csvCell = (s: string): string => (/[",\n\r]/u.test(s) || /^[=+\-@]/u.test(s) ? `"${(/^[=+\-@]/u.test(s) ? "'" + s : s).replace(/"/gu, '""')}"` : s);
/** CSV of IOCs; cells that could be interpreted as spreadsheet formulas are neutralised. */
export const toCsv = (iocs: Ioc[]): string => ["kind,value,defanged,classification,contexts,evidence_ids", ...iocs.map((i) => [i.kind, i.value, defang(i.value), i.classification, i.contexts.join(" | "), i.evidence_ids.join(" ")].map(csvCell).join(","))].join("\n") + "\n";

export function toMarkdown(r: ReportInput): string {
  const sev = (s: string) => ({ high: "🔴 high", medium: "🟠 medium", low: "🟡 low", info: "⚪ info" }[s] ?? s);
  let m = `# Triage report: ${r.sample.name}\n\n> Static triage. Findings are indicator matches over Evidence, **not verdicts**. ${r.score.note}\n\n| | |\n|---|---|\n| Type | ${r.sample.type} |\n| Size | ${r.sample.size} bytes |\n| SHA-256 | \`${r.sample.sha256}\` |\n| SHA-1 | \`${r.sample.sha1}\` |\n| MD5 | \`${r.sample.md5}\` |\n| Triage score | **${r.score.score}** (${r.score.band}) |\n| Generated | ${r.generatedAt} |\n${r.evidenceBundleSha256 ? `| Evidence bundle SHA-256 | \`${r.evidenceBundleSha256}\` |\n` : ""}\n`;
  m += `## Findings (${r.findings.length})\n\n`; if (!r.findings.length) m += "_No rule matched. This does not establish that the sample is benign._\n\n"; else { m += "| Rule | Severity | Tactic | ATT&CK (indicative) | Title | Detail |\n|---|---|---|---|---|---|\n"; for (const f of r.findings) m += `| ${f.rule_id} | ${sev(f.severity)} | ${f.tactic} | ${f.attack.join(", ") || "—"} | ${f.title} | ${f.detail.slice(0, 4).map((d) => defang(d).replace(/\|/gu, "\\|")).join("; ")} |\n`; m += "\n"; }
  m += `## Indicators (${r.iocs.length}; defanged)\n\n`; if (r.iocs.length) { m += "| Kind | Value | Class | Context |\n|---|---|---|---|\n"; for (const i of r.iocs.slice(0, 200)) m += `| ${i.kind} | \`${defang(i.value).replace(/\|/gu, "\\|")}\` | ${i.classification} | ${i.contexts[0] ?? ""}${i.decoded_from ? " (decoded)" : ""} |\n`; if (r.iocs.length > 200) m += `\n_${r.iocs.length - 200} more in iocs.csv_\n`; m += "\n"; } else m += "_none extracted_\n\n";
  if (r.unknowns?.length) { m += `## Open unknowns\n\n${r.unknowns.map((u) => `- [${u.status}] ${u.question}`).join("\n")}\n\n`; }
  m += `## Limitations\n\n${[...new Set(r.limitations)].slice(0, 25).map((l) => `- ${l}`).join("\n")}\n`; return m;
}
