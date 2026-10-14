# rea-triage (prototype of the malware-triage layer REA does not provide)

A single-file, dependency-free Node script plus `rules.json` and `demo-rules.yar`. It consumes **REA Evidence** (CLI `--json` output or MCP transcripts) and adds the missing malware-oriented layer: IOC extraction (URLs, IPv4, base64-decoded configuration, embedded-resource hashes, toolchain facts), rule matching (ATT&CK-style tags, severity) and a Markdown/JSON report in which **every finding cites the originating Evidence ID**. It runs nothing and reads only files.

```
node rea-triage.mjs rules.json <out-prefix> <evidence.json | mcp-transcript.json>...
yara -s -r demo-rules.yar <directory>        # signature layer (YARA 4.5.0), one target per invocation
```

## Real run (inputs: outputs of the manual tests in ../../27-manual-test-log.md)
Command: `node rea-triage.mjs rules.json out <js.json go.json od.json dn-members.json dn-native.json apk-pkg.json pe.json pcap.json bl-weak.json t2.json>` → 19 Evidence records, **11 findings, 8 IOCs** ([examples/triage-report.md](examples/triage-report.md)):
- IOCs recovered: the base64-encoded JS C2 URL (decoded from a `literal` node), the .NET `ldstr` URL, the native string `198.51.100.7` (from Ghidra `list_strings`), the PE `RCDATA PAYLOAD sha256=7694ba85…` resource, pcap HTTP URIs, Go toolchain/module.
- Rule hits: process/memory/anti-debug/socket API imports across ELF and .NET, reverse-shell pattern (`dup2`+`connect`), SMS permissions (APK), Electron renderer→main command bridge, `eval`+`request` candidate, RCDATA payload, weak hardening.
- YARA (separate step): both demo rules matched (`c/t`, `jsapp/src/main.js`) — [examples/yara-output.txt](examples/yara-output.txt).

## Known limitations (observed, not hypothetical)
- Rule R-EXEC-001 (process creation) did **not** fire for the .NET sample: REA's call edges expose the member name `Start` plus a token, not a declaring-type-qualified `Process::Start` in the field this script reads; the rule list was written before that was checked. Fix = resolve `target_token` through `member_refs`.
- Rules are name matches, so they are weak: a benign program importing `connect` also matches R-NET-002. Treat as triage hints.
- IOC extraction only scans fields it knows (JS literals, .NET `ldstr`, native strings, pcap URIs, PE resources). Strings inside decompiled pseudocode, WASM data segments and APK dex strings are not scanned yet.
- No scoring, no TI enrichment, no STIX/MISP export, no persistence — these are the next steps if this becomes a product.
