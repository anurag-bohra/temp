# rea-triage report

Inputs: 10 files, 19 Evidence records. Findings are rule matches over REA Evidence, **not verdicts**; each cites Evidence IDs.

## Findings

| Rule | Severity | Tag | Title | Detail | Evidence |
|---|---|---|---|---|---|
| R-NET-001 | medium | command-and-control | Hard-coded network endpoint in code or data | https://c2.example.invalid/task, https://c2.example.invalid/stage2, http://127.0.0.1:8765/beacon?id=42&host=lab, http://127.0.0.1:8765/task, 198.51.100.7 | ev_a5c759608cc…, ev_6a34563b3db… |
| R-MEM-001 | high | defense-evasion | Executable memory allocation (loader/shellcode pattern) | VirtualAlloc | ev_6a34563b3db…, ev_a91cc1abfa4… |
| R-ANTI-001 | medium | defense-evasion | Anti-debugging API | ptrace | ev_00c00adeed0… |
| R-NET-002 | medium | command-and-control | Socket / outbound connection API | connect, socket, inet_pton, GetStringAsync | ev_00c00adeed0…, ev_6a34563b3db… |
| R-FD-001 | high | execution | File descriptor redirection to socket (reverse-shell pattern) | dup2, connect | ev_00c00adeed0… |
| R-OBF-001 | low | obfuscation | Base64 decode of configuration or payload | FromBase64String | ev_6a34563b3db… |
| R-MOB-001 | high | mobile-collection | Premium SMS / SMS access permission | android.permission.SEND_SMS, android.permission.READ_SMS | ev_f25d0b89619… |
| R-JS-001 | high | privilege-escalation | Renderer-to-main command execution bridge (Electron) | ipc-handler, child-process, context-bridge-api | ev_a5c759608cc… |
| R-JS-002 | high | execution | Dynamic code evaluation of network-derived data (candidate) | request, eval-expression | ev_a5c759608cc… |
| R-PE-001 | medium | payload-staging | Embedded payload-like PE resource (RCDATA, non-icon) | RCDATA resource present |  |
| R-HARD-001 | info | vuln-surface | Weak binary hardening (no canary and executable stack) | no canary + executable stack indicator |  |

## IOCs

| Kind | Value | Context | Evidence |
|---|---|---|---|
| base64-decoded | https://c2.example.invalid/task | js literal src/config.js (decoded) | ev_a5c759608cc… |
| url | https://c2.example.invalid/task | js literal src/config.js (decoded) | ev_a5c759608cc… |
| toolchain | go go1.24.7 module beacon | Go build info | ev_e23f9b96c05… |
| url | https://c2.example.invalid/stage2 | .NET ldstr | ev_6a34563b3db… |
| embedded-resource | RCDATA PAYLOAD sha256=7694ba85520e09b810ef713d536ca9d60476967246edc9fa0eee090f0bbdb4f1 bytes=33 | PE resource | ev_245439d4a05… |
| url | http://127.0.0.1:8765/beacon?id=42&host=lab | pcap http | ev_0e6c0f04b60… |
| url | http://127.0.0.1:8765/task | pcap http | ev_0e6c0f04b60… |
| ipv4 | 198.51.100.7 | native string @0x102004 | ev_bdb695097a0… |
