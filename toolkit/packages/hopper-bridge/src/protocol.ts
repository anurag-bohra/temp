/**
 * rtk-hopper protocol v1 (newline-delimited JSON over a private Unix domain socket).
 *
 * Transport: the bridge (server, running inside Hopper) listens on a socket inside a private 0700 directory;
 * the socket file is 0600 and owned by the current uid. The Node client refuses to connect unless that holds.
 * Framing: one JSON object per line (UTF-8, "\n" terminated), max MAX_LINE_BYTES per line.
 * Auth: the first request on a connection MUST be method "auth" with params {token}; the token is a per-session
 *   random 256-bit hex string handed to the bridge out-of-band via a 0600 file (never on a command line).
 *   Any other first message, or a wrong token, yields error "auth_failed" and the server closes the connection.
 * Request : {"v":1,"id":<positive int>,"method":"<name>","params":{...}}
 * Response: {"v":1,"id":<same>,"ok":true,"result":<json>,"limitations":[...]?}
 *         | {"v":1,"id":<same>,"ok":false,"error":{"code":"<code>","message":"<text>"}}
 * Methods: auth, hello, open_document, close_document, shutdown, ping, plus the analysis operations
 *   binary_overview, list_procedures, procedure_info, list_strings, search_strings, xrefs,
 *   procedure_callers, procedure_callees, procedure_pseudo_code.
 * Error codes: auth_failed, bad_request, unknown_method, not_implemented, not_open, internal.
 */
export const PROTOCOL_VERSION = 1;
export const MAX_LINE_BYTES = 8 * 1024 * 1024;

export type JsonValue = null | boolean | number | string | JsonValue[] | { [k: string]: JsonValue };

export interface Request { v: 1; id: number; method: string; params: Record<string, unknown> }
export type Response =
  | { v: 1; id: number; ok: true; result: unknown; limitations?: string[] }
  | { v: 1; id: number; ok: false; error: { code: string; message: string } };

export const encodeLine = (msg: unknown): string => JSON.stringify(msg) + "\n";

export class HopperError extends Error { constructor(m: string) { super(m); this.name = new.target.name; } }
export class HopperUnavailableError extends HopperError {}
export class HopperSecurityError extends HopperError {}
export class HopperAuthError extends HopperError {}
export class HopperTimeoutError extends HopperError {}
export class HopperConnectionError extends HopperError {}
export class HopperProtocolError extends HopperError {}
export class HopperRemoteError extends HopperError { code: string; constructor(code: string, m: string) { super(`${code}: ${m}`); this.code = code; } }
