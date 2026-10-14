#!/usr/bin/env python3
"""rtk Hopper bridge (SKELETON, UNVERIFIED against real Hopper).

Implements the rtk-hopper protocol v1 server (see packages/hopper-bridge/src/protocol.ts):
newline-delimited JSON over a private Unix socket, per-session token authentication.

What is real and tested here: socket creation (0600, private 0700 directory required), token check
(constant-time), framing, request validation, dispatch, error codes, shutdown. These run under plain
python3 and are exercised by the package tests.

What is NOT verified: every call into the Hopper Python API. Those are marked "UNVERIFIED" below, were
written from memory of Hopper's scripting documentation and have never been run inside Hopper. Outside
Hopper (no `Document` global) they raise NotImplementedError, which the server reports as the protocol
error code "not_implemented". Operations with no sketch at all raise NotImplementedError unconditionally.

Usage: hopper_bridge.py --socket PATH --token-file PATH   (or env RTK_HOPPER_SOCKET / RTK_HOPPER_TOKEN_FILE)
"""
import hmac
import json
import os
import socket
import stat
import sys

PROTOCOL_VERSION = 1
MAX_LINE_BYTES = 8 * 1024 * 1024


class Backend(object):
    """Hopper-facing operations. Everything touching the Hopper API is UNVERIFIED."""

    def __init__(self):
        self.doc = None

    @staticmethod
    def _hopper_document():
        # UNVERIFIED: Hopper injects a global `Document` class into script scope; getCurrentDocument() name unverified.
        try:
            return Document.getCurrentDocument()  # noqa: F821 (only defined inside Hopper)
        except NameError:
            raise NotImplementedError("not running inside Hopper: Hopper API unavailable (UNVERIFIED integration)")

    def hello(self, params):
        version = None
        try:
            # UNVERIFIED: Hopper version accessor is unknown; left unset on purpose.
            self._hopper_document()
        except NotImplementedError:
            version = None
        return {"protocol": PROTOCOL_VERSION, "bridge": "rtk-hopper-bridge-skeleton", "hopper_version": version,
                "inside_hopper": version is not None}

    def open_document(self, params):
        # UNVERIFIED: Hopper scripts operate on the document already open in the UI; there is no verified
        # headless "open file" call. A real implementation must (a) verify the loaded file's sha256 equals
        # params["sha256"] and (b) refuse otherwise. Until verified, this raises.
        self.doc = self._hopper_document()
        raise NotImplementedError("open_document: sha256 verification of the Hopper document is not implemented")

    def close_document(self, params):
        self.doc = None
        return {"closed": True}

    def binary_overview(self, params):
        doc = self._hopper_document()
        # UNVERIFIED sketch: segment enumeration API names are from memory.
        segs = []
        for i in range(doc.getSegmentCount()):  # UNVERIFIED
            s = doc.getSegment(i)  # UNVERIFIED
            segs.append({"name": s.getName(), "start": hex(s.getStartingAddress()), "length": s.getLength()})  # UNVERIFIED
        return {"segments": segs}

    def list_procedures(self, params):
        doc = self._hopper_document()
        out = []
        for i in range(doc.getSegmentCount()):  # UNVERIFIED
            seg = doc.getSegment(i)  # UNVERIFIED
            for j in range(seg.getProcedureCount()):  # UNVERIFIED
                p = seg.getProcedureAtIndex(j)  # UNVERIFIED
                ea = p.getEntryPoint()  # UNVERIFIED
                out.append({"entry": hex(ea), "name": doc.getNameAtAddress(ea)})  # UNVERIFIED
        return {"procedures": out}

    def procedure_pseudo_code(self, params):
        doc = self._hopper_document()
        # UNVERIFIED: `Procedure.decompile()` exists in Hopper's Python API per memory; untested.
        seg = doc.getSegmentAtAddress(int(params["address"], 16))  # UNVERIFIED
        proc = seg.getProcedureAtAddress(int(params["address"], 16))  # UNVERIFIED
        return {"pseudo_code": proc.decompile()}  # UNVERIFIED

    def _unimplemented(self, name):
        raise NotImplementedError("%s is not implemented in the skeleton" % name)

    def procedure_info(self, params): self._unimplemented("procedure_info")
    def list_strings(self, params): self._unimplemented("list_strings")
    def search_strings(self, params): self._unimplemented("search_strings")
    def xrefs(self, params): self._unimplemented("xrefs")
    def procedure_callers(self, params): self._unimplemented("procedure_callers")
    def procedure_callees(self, params): self._unimplemented("procedure_callees")


ANALYSIS_METHODS = ("binary_overview", "list_procedures", "procedure_info", "list_strings", "search_strings",
                    "xrefs", "procedure_callers", "procedure_callees", "procedure_pseudo_code")


def _err(rid, code, message):
    return {"v": PROTOCOL_VERSION, "id": rid, "ok": False, "error": {"code": code, "message": message}}


def handle(backend, req, state):
    """Return (response, close_after)."""
    if not isinstance(req, dict) or req.get("v") != PROTOCOL_VERSION or not isinstance(req.get("id"), int) \
            or isinstance(req.get("id"), bool) or req.get("id") < 1 or not isinstance(req.get("method"), str) \
            or not isinstance(req.get("params", {}), dict):
        rid = req.get("id") if isinstance(req, dict) and isinstance(req.get("id"), int) else 0
        return _err(rid, "bad_request", "malformed request envelope"), False
    rid, method, params = req["id"], req["method"], req.get("params", {})
    if not state["authed"]:
        tok = params.get("token")
        if method == "auth" and isinstance(tok, str) and hmac.compare_digest(tok.encode(), state["token"].encode()):
            state["authed"] = True
            return {"v": PROTOCOL_VERSION, "id": rid, "ok": True, "result": {"authenticated": True}}, False
        return _err(rid, "auth_failed", "authentication required with a valid token"), True
    if method == "auth":
        return _err(rid, "bad_request", "already authenticated"), False
    if method == "ping":
        return {"v": PROTOCOL_VERSION, "id": rid, "ok": True, "result": {"pong": True}}, False
    if method == "shutdown":
        state["shutdown"] = True
        return {"v": PROTOCOL_VERSION, "id": rid, "ok": True, "result": {"bye": True}}, True
    if method not in ("hello", "open_document", "close_document") + ANALYSIS_METHODS:
        return _err(rid, "unknown_method", "unknown method: %s" % method), False
    try:
        result = getattr(backend, method)(params)
        return {"v": PROTOCOL_VERSION, "id": rid, "ok": True, "result": result,
                "limitations": ["UNVERIFIED Hopper integration"]}, False
    except NotImplementedError as e:
        return _err(rid, "not_implemented", str(e)), False
    except Exception as e:  # report, never crash the host
        return _err(rid, "internal", "%s: %s" % (type(e).__name__, e)), False


def serve_connection(conn, backend, token, state_out):
    state = {"authed": False, "token": token, "shutdown": False}
    buf = b""
    while True:
        chunk = conn.recv(65536)
        if not chunk:
            break
        buf += chunk
        if len(buf) > MAX_LINE_BYTES and b"\n" not in buf:
            conn.sendall((json.dumps(_err(0, "bad_request", "line too long")) + "\n").encode())
            break
        close = False
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            if not line.strip():
                continue
            try:
                req = json.loads(line.decode("utf-8"))
            except ValueError:
                resp, close = _err(0, "bad_request", "invalid JSON"), False
            else:
                resp, close = handle(backend, req, state)
            conn.sendall((json.dumps(resp) + "\n").encode())
            if close:
                break
        if close:
            break
    state_out["shutdown"] = state["shutdown"]


def check_private_dir(path):
    d = os.path.dirname(os.path.abspath(path))
    st = os.lstat(d)
    if (st.st_mode & 0o077) != 0 or st.st_uid != os.getuid():
        raise SystemExit("refusing to bind: %s must be mode 0700 and owned by the current user" % d)


def main(argv):
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--socket", default=os.environ.get("RTK_HOPPER_SOCKET"))
    ap.add_argument("--token-file", default=os.environ.get("RTK_HOPPER_TOKEN_FILE"))
    a = ap.parse_args(argv)
    if not a.socket or not a.token_file:
        raise SystemExit("--socket and --token-file (or env RTK_HOPPER_SOCKET / RTK_HOPPER_TOKEN_FILE) are required")
    check_private_dir(a.socket)
    tst = os.lstat(a.token_file)
    if not stat.S_ISREG(tst.st_mode) or (tst.st_mode & 0o077) != 0 or tst.st_uid != os.getuid():
        raise SystemExit("token file must be a regular file with mode 0600 owned by the current user")
    with open(a.token_file, "r") as f:
        token = f.read().strip()
    if len(token) < 32:
        raise SystemExit("token too short")
    old = os.umask(0o177)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        srv.bind(a.socket)
    finally:
        os.umask(old)
    os.chmod(a.socket, 0o600)
    srv.listen(1)
    backend = Backend()
    out = {"shutdown": False}
    try:
        while not out["shutdown"]:
            conn, _ = srv.accept()
            try:
                serve_connection(conn, backend, token, out)
            finally:
                conn.close()
    finally:
        srv.close()
        try:
            os.unlink(a.socket)
        except OSError:
            pass


if __name__ == "__main__":
    main(sys.argv[1:])
