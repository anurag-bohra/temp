#!/usr/bin/env node
// Minimal MCP stdio driver used for the manual tests (no LLM involved).
// Usage: node drive.mjs <rea-checkout> <steps.json> <transcript-out.json>
// steps.json: [{ "tool": "name", "args": {...} } | { "prompt": "name", "args": {...} } | { "list": "tools"|"prompts" } | { "complete": {...} }]
// Run from the REA checkout (it imports @modelcontextprotocol/client from there).
import { createRequire } from "node:module";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
const [reaDir, stepsFile, outFile] = process.argv.slice(2);
const req = createRequire(join(reaDir, "package.json"));
const { Client } = await import(pathToFileURL(req.resolve("@modelcontextprotocol/client")).href);
const { StdioClientTransport } = await import(pathToFileURL(req.resolve("@modelcontextprotocol/client/stdio")).href);
const steps = JSON.parse(readFileSync(stepsFile, "utf8"));
const transport = new StdioClientTransport({ command: process.execPath, args: [join(reaDir, "scripts/rea.mjs"), "mcp"], env: { ...process.env }, stderr: "pipe" });
const client = new Client({ name: "rea-manual-test-driver", version: "1" });
const transcript = [];
let ctxSessionId = null; // "${session_id}" in later args is replaced by the last session_id seen in a tool result
let stderr = ""; transport.stderr?.on("data", (c) => { stderr = (stderr + c).slice(-20000); });
await client.connect(transport);
transcript.push({ step: "initialize", server: client.getServerVersion?.(), capabilities: client.getServerCapabilities?.(), instructions: client.getInstructions?.() });
for (const s of steps) {
  if (s.args) s.args = JSON.parse(JSON.stringify(s.args).replaceAll("${session_id}", ctxSessionId ?? ""));
  const t0 = Date.now(); let res, err;
  try {
    if (s.tool) res = await client.callTool({ name: s.tool, arguments: s.args ?? {} }, undefined, { timeout: s.timeout ?? 600000 });
    else if (s.prompt) res = await client.getPrompt({ name: s.prompt, arguments: s.args ?? {} });
    else if (s.list === "tools") res = await client.listTools();
    else if (s.list === "prompts") res = await client.listPrompts();
    else if (s.complete) res = await client.complete(s.complete);
  } catch (e) { err = String(e?.message ?? e); }
  const sid = res?.structuredContent?.result?.session_id ?? res?.structuredContent?.session_id ?? res?.structuredContent?.normalized_result?.session_id; if (sid) ctxSessionId = sid;
  if (s.sleep_ms) await new Promise((r) => setTimeout(r, s.sleep_ms));
  transcript.push({ step: s.tool ?? s.prompt ?? s.list ?? "complete", args: s.args ?? s.complete ?? null, ms: Date.now() - t0, error: err ?? null, result: res ?? null });
  console.log(`${s.tool ?? s.prompt ?? s.list ?? "complete"} ${err ? "ERROR " + err.slice(0, 120) : "ok"} (${Date.now() - t0} ms)`);
}
transcript.push({ step: "stderr-tail", stderr });
writeFileSync(outFile, JSON.stringify(transcript, null, 1));
await client.close();
