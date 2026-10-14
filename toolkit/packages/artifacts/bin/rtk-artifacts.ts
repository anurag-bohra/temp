#!/usr/bin/env node
import { extractArchive, inspectArchive } from "../src/index.ts";
import type { Quotas } from "../src/index.ts";

const USAGE = `usage:
  rtk-artifacts inspect <archive> [--quota key=value ...]
  rtk-artifacts extract <archive> <destDir> [--policy strict|skip-bad] [--preserve-exec] [--quota key=value ...]
quota keys: maxEntries maxTotalSize maxEntrySize maxRatio ratioMinBytes maxDepth maxNameLength maxNestedBytes
Prints the Evidence record as JSON. Exit codes: 0 ok, 1 anomalies/failed extraction, 2 usage error.`;

async function main(argv: string[]): Promise<number> {
  const pos: string[] = []; const quotas: Record<string, number> = {}; let policy: "strict" | "skip-bad" = "strict"; let preserveExec = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === "--quota") { const [k, v] = (argv[++i] ?? "").split("="); if (!k || !Number.isFinite(Number(v))) { console.error(USAGE); return 2; } quotas[k] = Number(v); }
    else if (a === "--policy") { const v = argv[++i]; if (v !== "strict" && v !== "skip-bad") { console.error(USAGE); return 2; } policy = v; }
    else if (a === "--preserve-exec") preserveExec = true;
    else if (a === "-h" || a === "--help") { console.log(USAGE); return 0; }
    else pos.push(a);
  }
  const [cmd, archive, dest] = pos;
  if (cmd === "inspect" && archive && pos.length === 2) {
    const ev = await inspectArchive(archive, quotas as Partial<Quotas>);
    console.log(JSON.stringify(ev, null, 2));
    return (ev.normalized_result as { anomalies: unknown[] }).anomalies.some((a) => (a as { severity: string }).severity === "high") ? 1 : 0;
  }
  if (cmd === "extract" && archive && dest && pos.length === 3) {
    const ev = await extractArchive(archive, dest, quotas as Partial<Quotas>, { policy, preserveExec });
    console.log(JSON.stringify(ev, null, 2));
    return (ev.normalized_result as { status: string }).status === "ok" ? 0 : 1;
  }
  console.error(USAGE); return 2;
}
main(process.argv.slice(2)).then((c) => { process.exitCode = c; }, (e) => { console.error(String(e instanceof Error ? e.message : e)); process.exitCode = 2; });
