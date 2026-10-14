#!/usr/bin/env node
// rea-triage: prototype malware-triage layer over REA Evidence JSON (the layer REA itself does not provide).
// Usage: node rea-triage.mjs <rules.json> <out-prefix> <evidence.json | mcp-transcript.json>...
// Inputs: CLI `--json` Evidence records, or MCP driver transcripts (arrays of steps with structuredContent).
// Output: <prefix>.json (findings + IOCs with Evidence-ID provenance) and <prefix>.md (report). Static only: reads files, runs nothing.
import fs from "node:fs";
const [rulesFile, outPrefix, ...inputs] = process.argv.slice(2);
const rules = JSON.parse(fs.readFileSync(rulesFile, "utf8"));
const records = []; // {evidence_id, operation, subject, result}
const add = (e) => { if (e && typeof e === "object" && e.operation && e.normalized_result !== undefined) records.push(e); };
for (const f of inputs) {
  const j = JSON.parse(fs.readFileSync(f, "utf8"));
  if (Array.isArray(j)) for (const s of j) add(s?.result?.structuredContent); else add(j);
}
const iocs = new Map(); // key kind|value -> {kind,value,evidence_ids:Set,context}
const names = new Map(); // api/symbol name -> Set(evidence ids)
const perms = new Map(); const jsKinds = new Map(); const flags = new Set();
const noteIoc = (kind, value, id, ctx) => { const k = kind + "|" + value; if (!iocs.has(k)) iocs.set(k, { kind, value, evidence_ids: new Set(), context: ctx }); iocs.get(k).evidence_ids.add(id); };
const noteName = (n, id) => { if (typeof n !== "string" || !n || n.startsWith("undefined")) return; for (const v of [n, n.replace(/@.*$/, ""), n.split("::").slice(-2).join("::"), n.split("::").pop()]) { if (!names.has(v)) names.set(v, new Set()); names.get(v).add(id); } };
const URL_RE = /\bhttps?:\/\/[^\s"'<>\\]+/g, IP_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const b64 = (s) => { if (!/^[A-Za-z0-9+/]{16,}={0,2}$/.test(s)) return null; try { const d = Buffer.from(s, "base64").toString("utf8"); return /^[\x20-\x7e]{6,}$/.test(d) ? d : null; } catch { return null; } };
const scanText = (text, id, ctx) => { if (typeof text !== "string") return;
  for (const u of text.match(URL_RE) ?? []) noteIoc("url", u, id, ctx);
  for (const ip of text.match(IP_RE) ?? []) if (!/^(127|0)\./.test(ip)) noteIoc("ipv4", ip, id, ctx);
  const d = b64(text.trim()); if (d) { noteIoc("base64-decoded", d, id, ctx + " (decoded)"); scanText(d, id, ctx + " (decoded)"); } };
for (const e of records) {
  const id = e.evidence_id, r = e.normalized_result, op = e.operation;
  if (op === "analyze_javascript_application") {
    for (const n of r.semantic_graph?.nodes ?? []) { jsKinds.set(n.kind, (jsKinds.get(n.kind) ?? new Set()).add(id)); if (n.kind === "expression" && n.label === "eval") jsKinds.set("eval-expression", new Set([id])); if (n.kind === "literal") scanText(n.properties?.value, id, "js literal " + (n.identity?.module_path ?? "")); }
    for (const n of r.graph?.nodes ?? []) jsKinds.set(n.kind, (jsKinds.get(n.kind) ?? new Set()).add(id));
  } else if (op === "inspect_managed_members") {
    for (const l of r.user_strings?.literals ?? []) scanText(l.value, id, ".NET ldstr");
    for (const c of r.call_edges ?? []) { noteName(c.target_name, id); if (c.target_type) noteName(c.target_type + "::" + c.target_name, id); noteName(JSON.stringify(c).match(/"target_(?:declaring_)?type[^"]*":"([^"]+)"/)?.[1] + "::" + c.target_name, id); }
    for (const m of r.methods ?? []) noteName(m.name, id);
  } else if (op === "inspect_managed_native_boundaries") {
    for (const m of r.module_refs ?? []) noteName(m.name, id); for (const p of r.pinvoke_imports ?? []) noteName(p.import_name ?? p.name ?? p.method, id);
  } else if (op === "inspect_with_objdump") {
    for (const line of String(r.stdout ?? "").split("\n")) { const m = line.match(/\*UND\*\s+\S+\s+(\S+)/); if (m) noteName(m[1], id); }
  } else if (op === "list_procedures") { for (const p of r) if (p.procedure?.external) noteName(String(p.value).replace("<EXTERNAL>::", ""), id); }
  else if (op === "list_strings" || op === "search_strings") { for (const s of r) scanText(s.value, id, "native string @" + s.address); }
  else if (op === "inspect_android_package") { for (const p of r.permissions ?? []) perms.set(p, (perms.get(p) ?? new Set()).add(id)); }
  else if (op === "inspect_pe_resources") { for (const x of r.resources ?? []) if (x.type?.id === 10) { flags.add("pe_rcdata"); noteIoc("embedded-resource", `RCDATA ${x.name?.name ?? x.name?.id} sha256=${x.payload?.sha256} bytes=${x.payload?.location?.bytes}`, id, "PE resource"); } }
  else if (op === "inspect_pcap_capture") { for (const u of r.http_request_uris ?? []) noteIoc("url", u, id, "pcap http"); for (const d of r.dns_queries ?? []) noteIoc("domain", d.name ?? d, id, "pcap dns"); for (const s of r.tls_sni_values ?? []) noteIoc("domain", s.name ?? s, id, "pcap sni"); }
  else if (op === "inspect_go_binary") { noteIoc("toolchain", `go ${r.build_info?.go_version} module ${r.build_info?.module?.path}`, id, "Go build info"); }
  else if (op === "inspect_binary_layout") { const m = r.mitigations; if (m && m.stack_canary_indicator === false && m.executable_stack_indicator === true) flags.add("layout_weak"); for (const s of Object.values(r.symbols ?? {})) if (s?.name) noteName(s.name, id); }
  else if (op === "inspect_wasm_artifact") { for (const x of r.interface?.entries ?? []) noteName(`${x.direction}:${x.module ?? ""}.${x.name}`, id); }
}
const findings = [];
const evOf = (set) => [...set];
for (const rule of rules) { const m = rule.match; let hit = null;
  if (m.ioc_kinds) { const h = [...iocs.values()].filter((i) => m.ioc_kinds.includes(i.kind)); if (h.length) hit = { evidence_ids: [...new Set(h.flatMap((i) => evOf(i.evidence_ids)))], detail: h.map((i) => i.value) }; }
  if (!hit && m.names_any) { const h = m.names_any.filter((n) => names.has(n)); if (h.length) hit = { evidence_ids: [...new Set(h.flatMap((n) => evOf(names.get(n))))], detail: h }; }
  if (!hit && m.names_all && m.names_all.every((n) => names.has(n))) hit = { evidence_ids: [...new Set(m.names_all.flatMap((n) => evOf(names.get(n))))], detail: m.names_all };
  if (!hit && m.or_ioc_kinds) { const h = [...iocs.values()].filter((i) => m.or_ioc_kinds.includes(i.kind)); if (h.length) hit = { evidence_ids: [...new Set(h.flatMap((i) => evOf(i.evidence_ids)))], detail: h.map((i) => i.value) }; }
  if (!hit && m.permissions_any) { const h = m.permissions_any.filter((p) => perms.has(p)); if (h.length) hit = { evidence_ids: [...new Set(h.flatMap((p) => evOf(perms.get(p))))], detail: h }; }
  if (!hit && m.js_all && m.js_all.every((k) => jsKinds.has(k))) hit = { evidence_ids: [...new Set(m.js_all.flatMap((k) => evOf(jsKinds.get(k))))], detail: m.js_all };
  if (!hit && m.pe_rcdata && flags.has("pe_rcdata")) hit = { evidence_ids: [], detail: ["RCDATA resource present"] };
  if (!hit && m.layout_weak && flags.has("layout_weak")) hit = { evidence_ids: [], detail: ["no canary + executable stack indicator"] };
  if (hit) findings.push({ rule_id: rule.id, title: rule.title, tag: rule.tag, severity: rule.severity, basis: "static-evidence-match (not a verdict)", ...hit });
}
const out = { generated_from: inputs, evidence_records: records.length, findings, iocs: [...iocs.values()].map((i) => ({ ...i, evidence_ids: [...i.evidence_ids] })) };
fs.writeFileSync(outPrefix + ".json", JSON.stringify(out, null, 1));
let md = `# rea-triage report\n\nInputs: ${inputs.length} files, ${records.length} Evidence records. Findings are rule matches over REA Evidence, **not verdicts**; each cites Evidence IDs.\n\n## Findings\n\n| Rule | Severity | Tag | Title | Detail | Evidence |\n|---|---|---|---|---|---|\n`;
for (const f of findings) md += `| ${f.rule_id} | ${f.severity} | ${f.tag} | ${f.title} | ${String(f.detail.join(", ")).replaceAll("|", "\\|").slice(0, 160)} | ${f.evidence_ids.slice(0, 2).map((x) => x.slice(0, 14) + "…").join(", ")} |\n`;
md += `\n## IOCs\n\n| Kind | Value | Context | Evidence |\n|---|---|---|---|\n`;
for (const i of out.iocs) md += `| ${i.kind} | ${i.value.replaceAll("|", "\\|")} | ${i.context} | ${i.evidence_ids.slice(0, 1).map((x) => x.slice(0, 14) + "…")} |\n`;
fs.writeFileSync(outPrefix + ".md", md);
console.log(`records=${records.length} findings=${findings.length} iocs=${out.iocs.length}`);
