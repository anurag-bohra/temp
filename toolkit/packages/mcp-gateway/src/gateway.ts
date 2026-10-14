// Gateway core: policy + argument confinement + sanitisation + audit + limits, independent of any transport or upstream,
// so every part is unit-testable with a fake upstream.
import { loadReaEffects, deriveAnnotations, effectiveEffects, type EffectsTable, type PolicyProfile } from "@rtk/effects";
import { canonicalDigest } from "@rtk/evidence";
import { AuditLog } from "./audit.ts";
import { checkArguments, decideTool, resolveProfile, type PathPolicy, type ToolVerdict } from "./policy.ts";
import { cleanMetaString, detectInjection, sanitizeText, sanitizeToolResult, sha256, type Detection } from "./sanitize.ts";

export interface UpstreamTool { name: string; description?: string; title?: string; inputSchema: unknown; outputSchema?: unknown; annotations?: unknown; [k: string]: unknown }
export interface Upstream {
  listTools(): Promise<UpstreamTool[]>;
  callTool(name: string, args: Record<string, unknown>, opts: { timeoutMs: number }): Promise<Record<string, unknown>>;
  listPrompts?(): Promise<Record<string, unknown>[]>;
  getPrompt?(name: string, args: Record<string, string> | undefined): Promise<Record<string, unknown>>;
  listResources?(): Promise<Record<string, unknown>[]>;
  listResourceTemplates?(): Promise<Record<string, unknown>[]>;
  readResource?(uri: string): Promise<Record<string, unknown>>;
}
export interface ApprovalRequest { tool: string; args: Record<string, unknown>; tier: string | null; reasons: string[] }
export interface GatewayLimits { maxCallsPerMinute: number; maxConcurrent: number; maxArgBytes: number; callTimeoutMs: number; maxBlockChars: number; maxTotalChars: number; maxStructuredBytes: number }
export interface GatewayConfig extends PathPolicy {
  profile: string | PolicyProfile;
  effects?: EffectsTable;
  approveTools?: readonly string[];
  approve?: (r: ApprovalRequest) => boolean | Promise<boolean>;
  auditLog?: string | AuditLog;
  limits?: Partial<GatewayLimits>;
  /** Clock for the rate limiter (tests). */
  now?: () => number;
}
export const DEFAULT_LIMITS: GatewayLimits = { maxCallsPerMinute: 120, maxConcurrent: 4, maxArgBytes: 256 * 1024, callTimeoutMs: 600_000, maxBlockChars: 200_000, maxTotalChars: 400_000, maxStructuredBytes: 1_000_000 };

export type Refusal = { code: "rtk_policy_denied" | "rtk_approval_required" | "rtk_argument_policy" | "rtk_rate_limited" | "rtk_limit_exceeded" | "rtk_upstream_error"; message: string; tool: string; details?: unknown };

/** Gateway-authored, trusted-format refusal (a CallToolResult with isError). */
export function refusalResult(r: Refusal): Record<string, unknown> {
  return { isError: true, content: [{ type: "text", text: `rtk-gateway refused tool call "${r.tool}" [${r.code}]: ${r.message}` }], structuredContent: { error: { source: "rtk-gateway", ...r } }, _meta: { rtk: { version: 1, refused: true, code: r.code } } };
}

export class Gateway {
  readonly config: GatewayConfig; readonly profile: PolicyProfile; readonly table: EffectsTable; readonly limits: GatewayLimits;
  readonly audit: AuditLog | null; readonly upstream: Upstream;
  private approved: Set<string>; private calls: number[] = []; private inflight = 0; private toolNames: string[] = [];
  constructor(config: GatewayConfig, upstream: Upstream) {
    this.config = config; this.upstream = upstream; this.profile = resolveProfile(config.profile); this.table = config.effects ?? loadReaEffects();
    this.limits = { ...DEFAULT_LIMITS, ...config.limits }; this.approved = new Set(config.approveTools ?? []);
    this.audit = typeof config.auditLog === "string" ? new AuditLog(config.auditLog) : (config.auditLog ?? null);
  }
  private log(method: string, tool: string | null, args: unknown, decision: string, reasons: string[], result: string | null): void {
    this.audit?.append({ method, tool, args_digest: args === undefined ? null : canonicalDigest(args), decision, reasons, result_sha256: result });
  }
  private verdictOf(name: string): ToolVerdict { return decideTool(name, this.table, this.profile); }
  private canApprove(name: string): boolean { return this.approved.has(name) || this.config.approve !== undefined; }

  /** tools/list: denied tools are not advertised; advertised annotations are DERIVED from audited effects, not taken from upstream. */
  async listTools(): Promise<Record<string, unknown>[]> {
    const up = await this.upstream.listTools(); this.toolNames = up.map((t) => t.name); const out: Record<string, unknown>[] = []; let hidden = 0;
    for (const t of up) {
      const v = this.verdictOf(t.name);
      if (v.verdict === "deny" || (v.verdict === "ask" && !this.canApprove(t.name))) { hidden++; continue; }
      const { outputSchema: _o, annotations: _a, ...rest } = t; void _o; void _a;
      const rec = this.table[t.name]!; const desc = typeof t.description === "string" ? cleanMetaString(t.description) : undefined;
      const descDet: Detection[] = desc ? detectInjection(desc, { where: `tools/list:${t.name}.description`, max: 5 }) : [];
      out.push({ ...rest, ...(desc !== undefined ? { description: (v.verdict === "ask" ? "[rtk-gateway: requires approval] " : "") + desc } : {}),
        annotations: deriveAnnotations(effectiveEffects(t.name, rec.effects)),
        _meta: { ...(typeof t._meta === "object" && t._meta ? (t._meta as object) : {}), rtk: { tier: v.tier, verdict: v.verdict, output_schema_removed: t.outputSchema !== undefined, description_detections: descDet } } });
    }
    this.log("tools/list", null, undefined, "allow", [`profile=${this.profile.name}`, `advertised=${out.length}`, `hidden=${hidden}`], null);
    return out;
  }

  async callTool(name: string, rawArgs: Record<string, unknown> | undefined): Promise<Record<string, unknown>> {
    const args = rawArgs ?? {};
    const refuse = (r: Refusal, decision = "deny", reasons: string[] = [r.message]) => { this.log("tools/call", name, args, decision, [r.code, ...reasons], null); return refusalResult(r); };
    const now = (this.config.now ?? Date.now)();
    this.calls = this.calls.filter((t) => now - t < 60_000);
    if (this.calls.length >= this.limits.maxCallsPerMinute) return refuse({ code: "rtk_rate_limited", tool: name, message: `more than ${this.limits.maxCallsPerMinute} calls per minute` });
    if (this.inflight >= this.limits.maxConcurrent) return refuse({ code: "rtk_rate_limited", tool: name, message: `more than ${this.limits.maxConcurrent} concurrent calls` });
    const argBytes = Buffer.byteLength(JSON.stringify(args));
    if (argBytes > this.limits.maxArgBytes) return refuse({ code: "rtk_limit_exceeded", tool: name, message: `arguments are ${argBytes} bytes (limit ${this.limits.maxArgBytes})` });
    this.calls.push(now);

    const v = this.verdictOf(name);
    if (v.verdict === "deny") return refuse({ code: "rtk_policy_denied", tool: name, message: `denied by profile ${this.profile.name}${v.tier ? ` (tier ${v.tier})` : ""}: ${v.reasons.join("; ")}`, details: { profile: this.profile.name, tier: v.tier, known: v.known } }, "deny", v.reasons);
    const chk = checkArguments(args, this.config);
    if (!chk.ok) return refuse({ code: "rtk_argument_policy", tool: name, message: `argument policy violation: ${chk.violations.map((x) => `${x.key}: ${x.reason}`).join("; ")}`, details: { violations: chk.violations } }, "deny", chk.violations.map((x) => `${x.key}: ${x.reason}`));
    let decision = "allow"; const reasons = [`profile=${this.profile.name}`, `tier=${v.tier}`];
    if (v.verdict === "ask") {
      const ok = this.approved.has(name) || (this.config.approve ? await this.config.approve({ tool: name, args, tier: v.tier, reasons: v.reasons }) : false);
      if (!ok) return refuse({ code: "rtk_approval_required", tool: name, message: `tier ${v.tier} tool requires approval under profile ${this.profile.name} and none was given`, details: { tier: v.tier } }, "ask-refused", v.reasons);
      decision = "ask-approved";
    }
    this.inflight++;
    let raw: Record<string, unknown>;
    try { raw = await this.upstream.callTool(name, args, { timeoutMs: this.limits.callTimeoutMs }); }
    catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      const s = sanitizeText(msg, { tool: name, where: "upstream-error", maxChars: 4000 });
      this.log("tools/call", name, args, "error", [...reasons, "upstream-error"], s.sha256);
      return { isError: true, content: [{ type: "text", text: s.text }], structuredContent: { error: { source: "rtk-gateway", code: "rtk_upstream_error", tool: name } }, _meta: { rtk: { version: 1, upstream_error: true, detections: s.detections } } };
    } finally { this.inflight--; }
    const rawDigest = canonicalDigest(raw);
    const out = sanitizeToolResult(raw, rawDigest, { tool: name, toolNames: this.toolNames, maxBlockChars: this.limits.maxBlockChars, maxTotalChars: this.limits.maxTotalChars, maxStructuredBytes: this.limits.maxStructuredBytes });
    const det = ((out._meta as { rtk: { detections: Detection[] } }).rtk.detections);
    this.log("tools/call", name, args, decision, [...reasons, ...[...new Set(det.map((d) => `injection-detected:${d.id}`))]], rawDigest);
    return out;
  }

  // ---- prompts / resources passthrough, sanitised the same way
  async listPrompts(): Promise<Record<string, unknown>[]> {
    const p = (await this.upstream.listPrompts?.()) ?? []; this.log("prompts/list", null, undefined, "allow", [`count=${p.length}`], null);
    return p.map((x) => this.cleanListing(x, "prompts/list"));
  }
  async getPrompt(name: string, args?: Record<string, string>): Promise<Record<string, unknown>> {
    if (!this.upstream.getPrompt) throw new Error("upstream has no prompts");
    const pchk = checkArguments(args ?? {}, this.config);
    if (!pchk.ok) { this.log("prompts/get", `prompt:${name}`, args ?? {}, "deny", pchk.violations.map((x) => `${x.key}: ${x.reason}`), null); throw new Error(`rtk-gateway: prompt arguments refused: ${pchk.violations.map((x) => `${x.key}: ${x.reason}`).join("; ")}`); }
    const raw = await this.upstream.getPrompt(name, args); const digest = canonicalDigest(raw);
    const msgs = Array.isArray(raw.messages) ? (raw.messages as Record<string, unknown>[]) : [];
    const detections: Detection[] = [];
    const messages = msgs.map((m, i) => {
      const c = m.content as Record<string, unknown> | undefined;
      if (c && c.type === "text" && typeof c.text === "string") { const s = sanitizeText(c.text, { tool: `prompt:${name}`, where: `messages[${i}]`, maxChars: this.limits.maxBlockChars, toolNames: this.toolNames }); detections.push(...s.detections); return { ...m, content: { ...c, text: s.text } }; }
      return m;
    });
    this.log("prompts/get", `prompt:${name}`, args ?? {}, "allow", [...new Set(detections.map((d) => `injection-detected:${d.id}`))], digest);
    const { _meta, ...rest } = raw as Record<string, unknown> & { _meta?: object };
    return { ...rest, messages, _meta: { ...(_meta ?? {}), rtk: { version: 1, untrusted: true, result_sha256: digest, detections } } };
  }
  async listResources(): Promise<Record<string, unknown>[]> { const r = (await this.upstream.listResources?.()) ?? []; this.log("resources/list", null, undefined, "allow", [`count=${r.length}`], null); return r.map((x) => this.cleanListing(x, "resources/list")); }
  async listResourceTemplates(): Promise<Record<string, unknown>[]> { const r = (await this.upstream.listResourceTemplates?.()) ?? []; return r.map((x) => this.cleanListing(x, "resources/templates/list")); }
  async readResource(uri: string): Promise<Record<string, unknown>> {
    if (!this.upstream.readResource) throw new Error("upstream has no resources");
    const chk = checkArguments({ uri }, this.config);
    if (!chk.ok) { this.log("resources/read", `resource:${uri.slice(0, 200)}`, { uri }, "deny", chk.violations.map((x) => x.reason), null); throw new Error(`rtk-gateway: resource uri refused: ${chk.violations.map((x) => x.reason).join("; ")}`); }
    const raw = await this.upstream.readResource(uri); const digest = canonicalDigest(raw);
    const detections: Detection[] = [];
    const contents = (Array.isArray(raw.contents) ? (raw.contents as Record<string, unknown>[]) : []).map((c, i) => {
      if (typeof c.text === "string") { const s = sanitizeText(c.text, { tool: `resource:${uri.slice(0, 80)}`, where: `contents[${i}]`, maxChars: this.limits.maxBlockChars, toolNames: this.toolNames }); detections.push(...s.detections); return { ...c, text: s.text }; }
      return c;
    });
    this.log("resources/read", `resource:${uri.slice(0, 200)}`, { uri }, "allow", [...new Set(detections.map((d) => `injection-detected:${d.id}`))], digest);
    const { _meta, ...rest } = raw as Record<string, unknown> & { _meta?: object };
    return { ...rest, contents, _meta: { ...(_meta ?? {}), rtk: { version: 1, untrusted: true, result_sha256: digest, detections } } };
  }
  private cleanListing(x: Record<string, unknown>, where: string): Record<string, unknown> {
    const out: Record<string, unknown> = {}; const det: Detection[] = [];
    for (const [k, v] of Object.entries(x)) {
      if (typeof v === "string" && (k === "description" || k === "title" || k === "name")) { out[k] = cleanMetaString(v); det.push(...detectInjection(out[k] as string, { where: `${where}.${k}`, max: 5 })); } else out[k] = v;
    }
    const m = (typeof x._meta === "object" && x._meta ? x._meta : {}) as object;
    return { ...out, _meta: { ...m, rtk: { detections: det, sha256: sha256(JSON.stringify(x)) } } };
  }
}
