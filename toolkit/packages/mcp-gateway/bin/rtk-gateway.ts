#!/usr/bin/env node
// rtk-gateway: MCP stdio server enforcing @rtk/effects policy in front of an upstream MCP server (default: REA).
// Config: JSON file (argv[2] or RTK_GATEWAY_CONFIG) and/or env (see src/config.ts). stdout is the MCP channel: logs go to stderr.
import { loadConfig } from "../src/config.ts";
import { startStdioGateway } from "../src/server.ts";

const { gateway, upstream } = loadConfig(process.env, process.argv[2]);
if (gateway.allowedRoots.length === 0) process.stderr.write("rtk-gateway: warning: no allowed roots configured; every path argument will be refused\n");
process.stderr.write(`rtk-gateway: profile=${typeof gateway.profile === "string" ? gateway.profile : gateway.profile.name} upstream=${upstream.command} ${(upstream.args ?? []).join(" ")}\n`);
const { close } = await startStdioGateway(gateway, upstream);
for (const s of ["SIGINT", "SIGTERM"] as const) process.on(s, () => { void close().finally(() => process.exit(0)); });
process.stdin.on("end", () => { void close().finally(() => process.exit(0)); });
