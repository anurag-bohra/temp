// Regenerate data/rea-tool-effects.json from a built REA checkout:  node scripts/regenerate.mjs /path/to/rea
// (build REA, then `node scripts/generate-mcp-tool-catalog.mjs` there to produce .cache/mcp-tool-catalog.json)
import { readFileSync, writeFileSync } from "node:fs";
const rea = process.argv[2]; if (!rea) throw new Error("usage: regenerate.mjs <rea-checkout>");
const c = JSON.parse(readFileSync(`${rea}/.cache/mcp-tool-catalog.json`, "utf8")).catalog;
writeFileSync(new URL("../data/rea-tool-effects.json", import.meta.url), JSON.stringify({ generated_from: `${rea}/.cache/mcp-tool-catalog.json`, tools: Object.fromEntries(c.map((t) => [t.name, { kind: t.kind, requiresSession: t.requiresSession, effects: t.effects, annotations: t.annotations }])) }, null, 1) + "\n");
