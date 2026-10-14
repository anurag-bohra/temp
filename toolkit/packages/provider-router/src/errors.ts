export type SelectionFailure =
  | "unknown_provider"
  | "not_deep_provider"
  | "unsupported_target"
  | "provider_unavailable"
  | "no_supported_provider"
  | "open_failed";

export class ProviderSelectionError extends Error {
  readonly reason: SelectionFailure;
  readonly requested: string;
  constructor(reason: SelectionFailure, requested: string, message: string) {
    super(message);
    this.name = "ProviderSelectionError";
    this.reason = reason;
    this.requested = requested;
  }
}
export class RegistryConfigError extends Error {
  constructor(message: string) { super(message); this.name = "RegistryConfigError"; }
}
export class SessionStateError extends Error {
  constructor(message: string) { super(message); this.name = "SessionStateError"; }
}
export class OperationRoutingError extends Error {
  constructor(message: string) { super(message); this.name = "OperationRoutingError"; }
}
export class SnapshotIdentityError extends Error {
  readonly mismatches: string[];
  constructor(mismatches: string[]) {
    super(`Snapshot identity mismatch: ${mismatches.join("; ")}`);
    this.name = "SnapshotIdentityError";
    this.mismatches = mismatches;
  }
}
