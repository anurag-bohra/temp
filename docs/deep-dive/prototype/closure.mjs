import fs from "node:fs"; import path from "node:path";
const R = "/home/user/morluto/rea"; const SRC = path.join(R, "src");
const pkg = JSON.parse(fs.readFileSync(path.join(R, "package.json"), "utf8"));
const deps = new Set([...Object.keys(pkg.dependencies ?? {}), ...Object.keys(pkg.optionalDependencies ?? {})]);
const importRe = /(?:import|export)\s+(?:type\s+)?(?:[^'";]*?\s+from\s+)?["']([^"']+)["']|import\(\s*["']([^"']+)["']\s*\)/g;
const resolve = (from, spec) => {
  const base = path.resolve(path.dirname(from), spec.replace(/\.js$/, ""));
  for (const c of [base + ".ts", path.join(base, "index.ts"), base + ".mts"]) if (fs.existsSync(c)) return c;
  return null;
};
const BLUEPRINTS = {
  "01 ToolEffects + derived annotations": ["src/contracts/toolEffects.ts"],
  "02 Evidence record + ledger + bundle": ["src/domain/evidence.ts", "src/domain/evidenceBundle.ts", "src/application/investigation/EvidenceLedger.ts"],
  "03 Unknown registry": ["src/domain/residualUnknown.ts", "src/application/investigation/InvestigationRecords.ts"],
  "04 MCP server scaffold": ["src/server/createServer.ts"],
  "05 Provider registry + session router": ["src/application/binary/AnalysisProviderRegistry.ts", "src/application/binary/SessionProviderRouter.ts", "src/application/binary/BinarySession.ts"],
  "06 Ghidra headless bridge": ["src/ghidra/GhidraProvider.ts"],
  "07 Hopper bridge": ["src/hopper/HopperProvider.ts"],
  "08 Prompts (contracts + registration)": ["src/contracts/promptContracts.ts", "src/server/registerPrompts.ts", "src/server/promptCompletion.ts"],
  "09 JS/Electron analyzer (boundary analysis)": ["src/application/javascript/ElectronBoundaryAnalysis.ts"],
  "10 .NET static provider": ["src/dotnet/ManagedStaticProvider.ts"],
  "11 Artifact graph provider": ["src/artifacts/ArtifactProvider.ts"],
  "12 CDP browser provider": ["src/browser/CdpBrowserProvider.ts"],
  "13 Process supervision (OwnedCommand)": ["src/process/OwnedCommand.ts"],
};
const rows = [];
for (const [name, roots] of Object.entries(BLUEPRINTS)) {
  const seen = new Set(); const ext = new Set(); const stack = roots.map((r) => path.join(R, r)); const missing = [];
  for (const r of stack) if (!fs.existsSync(r)) missing.push(r);
  while (stack.length) {
    const f = stack.pop(); if (!f || seen.has(f) || !fs.existsSync(f)) continue; seen.add(f);
    const s = fs.readFileSync(f, "utf8");
    for (const m of s.matchAll(importRe)) { const spec = m[1] ?? m[2]; if (!spec) continue;
      if (spec.startsWith(".")) { const t = resolve(f, spec); if (t && !/\.(test|fixture)\.ts$/.test(t)) stack.push(t); }
      else if (!spec.startsWith("node:")) { const p = spec.startsWith("@") ? spec.split("/").slice(0, 2).join("/") : spec.split("/")[0]; ext.add(p); } }
  }
  let loc = 0; const dirs = {}; for (const f of seen) { loc += fs.readFileSync(f, "utf8").split("\n").length; const d = path.relative(SRC, f).split("/")[0]; dirs[d] = (dirs[d] ?? 0) + 1; }
  rows.push({ name, roots, missing, files: seen.size, loc, dirs, ext: [...ext].sort() });
}
fs.writeFileSync(process.argv[2], JSON.stringify(rows, null, 1));
for (const r of rows) console.log(r.name.padEnd(46), String(r.files).padStart(4), "files", String(r.loc).padStart(7), "LOC", "dirs:", Object.entries(r.dirs).sort((a,b)=>b[1]-a[1]).slice(0,5).map(([k,v])=>k+":"+v).join(","), "| ext:", r.ext.join(","), r.missing.length?"MISSING":"" );
