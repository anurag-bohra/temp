export interface Target {
  /** Local path of the target (informational; identity is the sha256). */
  path: string;
  /** Lower-case hex sha256 of the target bytes. This is the identity. */
  sha256: string;
  name?: string;
  format?: string | null;
  architecture?: string | null;
}

export type SupportStatus = "supported" | "unsupported" | "unavailable";
export interface ProviderSupport {
  status: SupportStatus;
  reason: string;
}

export type JsonObject = { [key: string]: unknown };

/** What a provider commits to when it analyses: anything that can change results belongs in `settings`. */
export interface ProviderProfile {
  settings: JsonObject;
}

export type ProviderKind = "deep" | "auxiliary";

export interface AnalysisProvider {
  readonly id: string;
  readonly name: string;
  readonly version: string;
  readonly kind: ProviderKind;
  supports(target: Target): ProviderSupport;
  profile(): ProviderProfile;
  open(target: Target): Promise<void>;
  close(): Promise<void>;
  call(operation: string, args: JsonObject): Promise<unknown>;
  operations(): readonly string[];
}

/** A provider, or a factory producing an independent instance per session (needed for concurrent sessions). */
export type ProviderEntry = AnalysisProvider | (() => AnalysisProvider);

export interface AnalysisProviderBinding {
  readonly provider_id: string;
  readonly provider_name: string;
  readonly provider_version: string;
  readonly target_sha256: string;
  readonly profile: ProviderProfile;
  readonly profile_digest: string;
  readonly selection: "auto" | "explicit";
  readonly operations: readonly string[];
  readonly auxiliary_providers: readonly { id: string; version: string; operations: readonly string[] }[];
}

export interface SnapshotIdentity {
  target_sha256: string;
  provider_id: string;
  profile_digest: string;
}
export interface AnalysisSnapshot extends SnapshotIdentity {
  data: unknown;
}

export interface CapabilityEntry {
  provider_id: string;
  name: string;
  version: string;
  kind: ProviderKind;
  support: ProviderSupport | { status: "unknown"; reason: string };
  selected: boolean;
  operations: readonly string[];
}
