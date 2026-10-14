#!/usr/bin/env node
import { allPrompts, installSkills, renderPrompt, skillNames } from "./index.ts";
const [cmd, ...rest] = process.argv.slice(2);
if (cmd === "list") { for (const p of allPrompts()) console.log(`${p.name}\t${p.title}`); for (const s of skillNames()) console.log(`skill\t${s}`); }
else if (cmd === "render") { const p = allPrompts().find((x) => x.name === rest[0]); if (!p) throw new Error("unknown prompt"); console.log(renderPrompt(p, JSON.parse(rest[1] ?? "{}"))); }
else if (cmd === "install") { const dry = rest.includes("--dry-run"); const dest = rest.find((a) => !a.startsWith("--")); if (!dest) throw new Error("usage: install <skills-dir> [--dry-run]"); console.log(JSON.stringify(installSkills(dest, { dryRun: dry }), null, 1)); }
else console.log("usage: rtk-skills list | render <prompt> '<json args>' | install <skills-dir> [--dry-run]");
