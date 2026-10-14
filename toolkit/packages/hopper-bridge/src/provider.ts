import { existsSync } from "node:fs";
import { createEvidence } from "@rtk/evidence";
import type { Evidence } from "@rtk/evidence";
import type { AnalysisProvider, JsonObject, ProviderProfile, ProviderSupport, Target } from "@rtk/provider-router";
import { HopperClient } from "./client.ts";
import { launchBridge } from "./launcher.ts";
import type { BridgeHandle, LaunchOptions } from "./launcher.ts";
import { HopperProtocolError, HopperUnavailableError, PROTOCOL_VERSION } from "./protocol.ts";

export const HOPPER_PROVIDER = { id: "rtk-hopper-bridge", name: "RTK Hopper bridge (UNVERIFIED against real Hopper)", version: "0.1.0" } as const;
export const HOPPER_OPERATIONS = [
  "binary_overview", "list_procedures", "list_strings", "procedure_callees", "procedure_callers", "procedure_info",
  "procedure_pseudo_code", "search_strings", "xrefs",
] as const;

export interface HopperProviderOptions {
  /** Launch a bridge host process (real Hopper: UNVERIFIED command line). Mutually exclusive with `connect`. */
  launch?: LaunchOptions;
  /** Obtain an already-running bridge (socket path + token), e.g. a fake server in tests. */
  connect?: (target: Target) => Promise<{ socketPath: string; token: string; stop?: () => Promise<void> }>;
  requestTimeoutMs?: number;
}

export class HopperProvider implements AnalysisProvider {
  readonly id = "hopper";
  readonly name = "Hopper Disassembler (via rtk bridge, unverified)";
  readonly kind = "deep" as const;
  readonly version = `rtk-hopper-protocol-${PROTOCOL_VERSION}`;
  readonly #o: HopperProviderOptions;
  #client: HopperClient | null = null;
  #handle: { stop?: () => Promise<void> } | null = null;
  #target: Target | null = null;
  #hello: { hopper_version?: string } = {};

  constructor(o: HopperProviderOptions = {}) { this.#o = o; }

  supports(target: Target): ProviderSupport {
    if (!this.#o.launch && !this.#o.connect) return { status: "unavailable", reason: "Hopper bridge not configured (no launch command or connection supplied)" };
    if (this.#o.launch && !existsSyncSafe(this.#o.launch.bin)) return { status: "unavailable", reason: `Hopper executable not found: ${this.#o.launch.bin}` };
    void target;
    return { status: "supported", reason: "support for specific formats is determined by Hopper at open_document time (unverified)" };
  }

  profile(): ProviderProfile { return { settings: { protocol: PROTOCOL_VERSION, verified_against_real_hopper: false } }; }
  operations(): readonly string[] { return HOPPER_OPERATIONS; }

  async open(target: Target): Promise<void> {
    if (this.#client) throw new Error("HopperProvider already open; close() first");
    let h: (BridgeHandle & { stop: () => Promise<void> }) | { socketPath: string; token: string; stop?: () => Promise<void> };
    if (this.#o.connect) h = await this.#o.connect(target);
    else if (this.#o.launch) h = await launchBridge(this.#o.launch);
    else throw new HopperUnavailableError("Hopper bridge not configured");
    this.#handle = h;
    try {
      const c = await HopperClient.connect({ socketPath: h.socketPath, token: h.token, requestTimeoutMs: this.#o.requestTimeoutMs });
      this.#client = c;
      const hello = (await c.request("hello")).result as any;
      if (!hello || hello.protocol !== PROTOCOL_VERSION) throw new HopperProtocolError(`unsupported bridge protocol: ${JSON.stringify(hello?.protocol)}`);
      this.#hello = { hopper_version: typeof hello.hopper_version === "string" ? hello.hopper_version : undefined };
      const doc = (await c.request("open_document", { path: target.path, sha256: target.sha256 })).result as any;
      if (!doc || doc.sha256 !== target.sha256) throw new HopperProtocolError("bridge opened a document whose sha256 does not match the target");
      this.#target = target;
    } catch (e) {
      await this.close().catch(() => {});
      throw e;
    }
  }

  async close(): Promise<void> {
    const c = this.#client, h = this.#handle;
    this.#client = null; this.#handle = null; this.#target = null;
    try { if (c && !c.closed) { try { await c.request("shutdown", {}, { timeoutMs: 1000 }); } catch { /* best effort */ } } }
    finally { c?.close(); await h?.stop?.(); }
  }

  async call(operation: string, args: JsonObject = {}): Promise<Evidence> {
    const c = this.#client, t = this.#target;
    if (!c || !t) throw new Error("HopperProvider not open");
    if (!(HOPPER_OPERATIONS as readonly string[]).includes(operation)) throw new Error(`Unknown operation: ${operation}`);
    const { result, limitations } = await c.request(operation, args);
    return createEvidence({
      subject: { name: t.name ?? t.path, digest: { sha256: t.sha256 }, local_path: t.path, format: t.format ?? null, architecture: t.architecture ?? null },
      provider: HOPPER_PROVIDER,
      analysis_profile: { provider: { id: this.id, name: "Hopper", version: this.#hello.hopper_version ?? null }, settings: this.profile().settings },
      predicate_type: operation,
      operation,
      parameters: args,
      normalized_result: result,
      confidence: operation === "procedure_pseudo_code" ? "derived" : "observed",
      authority: "shipped-artifact",
      limitations: [...limitations, "UNVERIFIED: the Hopper bridge has not been run against a real Hopper installation; results come from an unverified adapter.", "Static analysis only; nothing was executed."],
    });
  }
}

function existsSyncSafe(p: string): boolean { try { return existsSync(p); } catch { return false; } }
