#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { parseEvidence, type Evidence } from "@rtk/evidence";
import { analyzeJavaScriptApplication, compareJavaScriptApplications, type AnalyzeOptions } from "../src/index.ts";

const USAGE = `usage:
  rtk-js analyze <dir|file.js|app.asar> [--max-file-bytes N] [--max-files N] [--time-budget-ms N] [--include-node-modules]
  rtk-js compare <A> <B>       (A, B: path to analyse, or a saved evidence .json from 'analyze')
JSON Evidence is written to stdout.`;

async function load(arg: string, o: AnalyzeOptions): Promise<Evidence> {
  if (arg.endsWith(".json")) return parseEvidence(JSON.parse(readFileSync(arg, "utf8")));
  return analyzeJavaScriptApplication(arg, o);
}
async function main(argv: string[]): Promise<number> {
  const [cmd, ...rest] = argv;
  const o: AnalyzeOptions = {}; const pos: string[] = [];
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (a === "--max-file-bytes") o.maxFileBytes = Number(rest[++i]);
    else if (a === "--max-files") o.maxFiles = Number(rest[++i]);
    else if (a === "--time-budget-ms") o.timeBudgetMs = Number(rest[++i]);
    else if (a === "--include-node-modules") o.includeNodeModules = true;
    else if (a.startsWith("--")) { process.stderr.write(`unknown option ${a}\n${USAGE}\n`); return 2; }
    else pos.push(a);
  }
  if (cmd === "analyze" && pos.length === 1) { process.stdout.write(JSON.stringify(await analyzeJavaScriptApplication(pos[0], o), null, 2) + "\n"); return 0; }
  if (cmd === "compare" && pos.length === 2) { process.stdout.write(JSON.stringify(compareJavaScriptApplications(await load(pos[0], o), await load(pos[1], o)), null, 2) + "\n"); return 0; }
  process.stderr.write(USAGE + "\n"); return 2;
}
main(process.argv.slice(2)).then((c) => { process.exitCode = c; }, (e) => { process.stderr.write(`error: ${(e as Error).message}\n`); process.exitCode = 1; });
