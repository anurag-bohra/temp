#!/usr/bin/env node
// rtk-sandbox: JSON SandboxSpec in (file argument or stdin), Evidence JSON out. `--probe` prints host isolation capabilities.
import { readFileSync } from "node:fs";
import { probeCapabilities, runSandboxed, type SandboxSpec } from "../src/index.ts";

const arg = process.argv[2];
if (arg === "--probe") {
  const c = await probeCapabilities();
  process.stdout.write(JSON.stringify({ levels: c.levels, strace: c.strace, root: c.isRoot, userns: c.userns, notes: c.notes, core_pattern: c.corePattern }, null, 2) + "\n");
} else if (arg === "--help" || arg === "-h") {
  process.stdout.write("usage: rtk-sandbox [spec.json | -]  (JSON SandboxSpec; stdin when omitted)\n       rtk-sandbox --probe\n");
} else {
  const text = arg && arg !== "-" ? readFileSync(arg, "utf8") : readFileSync(0, "utf8");
  const spec = JSON.parse(text) as SandboxSpec;
  if (typeof spec.sample !== "string") { process.stderr.write("spec.sample (path) is required\n"); process.exit(2); }
  const ev = await runSandboxed(spec);
  process.stdout.write(JSON.stringify(ev, null, 2) + "\n");
}
