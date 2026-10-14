#!/usr/bin/env node
// rtk-triage <sample> [--profile static-analysis] [--out dir] [--yara rules.yar] [--rules rules.json] [--store case.sqlite] [--approve id,id] [--allow-domain d,d] [--depth n]
import { loadRules, triageSample, writeCase, CaseStore, validateRules } from "./index.ts";
import { readFileSync } from "node:fs";
const args = process.argv.slice(2); const flag = (n: string): string | undefined => { const i = args.indexOf(`--${n}`); return i >= 0 ? args[i + 1] : undefined; };
const sample = args.find((a, i) => !a.startsWith("--") && (i === 0 || !args[i - 1]!.startsWith("--")));
if (!sample) { console.error("usage: rtk-triage <sample> [--profile locked|static-analysis|lab-vm] [--out dir] [--yara rules.yar] [--rules rules.json] [--store case.sqlite] [--approve a,b] [--allow-domain d,d] [--depth n] [--deep] [--detonate]"); process.exit(2); }
const store = flag("store") ? new CaseStore(flag("store")) : undefined;
const r = await triageSample(sample, { profile: flag("profile") ?? "static-analysis", yaraRules: flag("yara"), rules: flag("rules") ? validateRules(JSON.parse(readFileSync(flag("rules")!, "utf8"))) : loadRules(), approve: flag("approve")?.split(","), allowDomains: flag("allow-domain")?.split(","), depth: flag("depth") ? Number(flag("depth")) : undefined, store, deep: args.includes("--deep"), detonate: args.includes("--detonate") });
const out = flag("out"); const written = out ? writeCase(r, out) : null;
console.log(JSON.stringify({ sample: r.report.sample, score: r.score, findings: r.findings.map((f) => ({ id: f.rule_id, severity: f.severity, title: f.title })), iocs: r.iocs.length, analyzers_ran: r.ran, analyzers_skipped: r.skipped, case_dir: written?.dir ?? null }, null, 1));
store?.close();
