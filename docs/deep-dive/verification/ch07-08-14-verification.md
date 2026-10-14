# Verification log: chapters 07, 08, 14

Method: each claim was checked against `/home/user/morluto/rea` (HEAD f75b1a4) by reading cited line ranges, importing `dist/` modules, and RUN tests (Ghidra 12.1.4 + JDK 21 via the MCP driver and CLI; synthetic detection fixtures via `parseBinaryTarget`; hostile ZIP fixtures via `rea inspect-artifact` / `extract-artifact`). Hopper is not installed: chapter 07 is code-verified only. Mermaid validator `scratchpad/mv/check.mjs`: all three chapters pass.

Summary: ch07 total 63: CONFIRMED 53, CORRECTED 9, UNVERIFIABLE 1; ch08 total 62: CONFIRMED 56, CORRECTED 4, UNVERIFIABLE 2; ch14 total 67: CONFIRMED 58, CORRECTED 9, UNVERIFIABLE 0.

Scratch material: `scratchpad/v/` (step files g1-g4, cancel.mjs, det/, det2/, ax/).

## Chapter 07 (Hopper, DOC/code only)

| # | Claim | Verdict | Evidence | Fix |
|---|---|---|---|---|
| 1 | Provider identity `{id:hopper,name:Hopper Disassembler,version:null}` (Capabilities.ts:7-12) | CONFIRMED | file lines 7-12 match verbatim | - |
| 2 | Committed version is `launcher-sha256:<digest>` (HopperAnalysisProfile.ts:76-80) | CONFIRMED | lines 76-80 | - |
| 3 | `HopperProvider implements AnalysisProviderCandidate` at HopperProvider.ts:43 | CONFIRMED | line 43 | - |
| 4 | Registered as one of `[hopper, ghidra, ida]` in composition/binary.ts | CONFIRMED | binary.ts:29-32 `new AnalysisProviderRegistry([hopper, ghidra, ida], ...)` | - |
| 5 | HOPPER_OPERATIONS has 36 entries | CONFIRMED | node import of dist: length 36 | - |
| 6 | Operation array cited at Capabilities.ts:14-61 | CORRECTED | array is 15-52, MUTATING_OPERATIONS 54-61 | cite split |
| 7 | Descriptors generated for 36 ops + `search_bytes` (37) with reason "Masked byte search has not been verified for Hopper." | CONFIRMED | CAPABILITIES.length = 37; text at lines 66-70 | - |
| 8 | Descriptor block cited 63-108 | CORRECTED | starts at 64 | 64-108 |
| 9 | Effects block cited 75-83 | CORRECTED | 75-82 (requiresRoot at 82) | 75-82 |
| 10 | Effects values launchesProcess/mayShowUi true, network false, mayWriteFilesystem=mutating | CONFIRMED | lines 75-82 | - |
| 11 | Operation matrix O/H/G/I for every row incl. 6 Ghidra-only and 13 Hopper-only | CONFIRMED | computed from dist: HOPPER/GHIDRA/IDA/OFFICIAL lists, 41 rows identical | - |
| 12 | 41 official-proxy tools, 35 Hopper-supported, 6 Ghidra-only | CONFIRMED | OFFICIAL_TOOL_CONTRACTS.length=41; 41-6=35 | - |
| 13 | All 41 report readOnlyHint:false | CONFIRMED | mcp-tool-catalog.json: 41/41 readOnlyHint false, kind official-proxy | - |
| 14 | registerOfficialTools loops contracts (33-46), runOfficialOperation 128-137, Evidence build 78-98 | CONFIRMED | sed of ranges | - |
| 15 | MCP tool name is bridge method 1:1 via HopperProvider.ts:309-316 | CORRECTED | same lines also divert regex search_* to HopperRegexSearch | note added |
| 16 | Bridge `_dispatch` is a closed set, `Unknown bridge method` at 1024 | CONFIRMED | bridge lines 736,1024 | - |
| 17 | health returns name/version 1.0.0/run_id/process_id (738-744) | CONFIRMED | lines 738-744 | - |
| 18 | `_document()` rejects other document names (178-192) | CONFIRMED | lines 178-192 | - |
| 19 | EXHAUSTIVE_ANALYSIS_METHODS 137-155, require_analysis_complete 57-63 | CONFIRMED | lines match; 15 methods | - |
| 20 | Symbol-name limit 1024 UTF-16 units (line 16) | CONFIRMED | HOPPER_SYMBOL_NAME_UTF16_UNITS = 1024 | - |
| 21 | Address parsing prefers symbol over bare hex, unsigned 64-bit bound (239-263) | CONFIRMED | lines 239-263 | - |
| 22 | Request key set exactly {id,token,method,params} (1044) | CONFIRMED | line 1044 | - |
| 23 | Token compare hmac.compare_digest after isascii (1054-1058) | CONFIRMED | lines 1054-1058 | - |
| 24 | All bridge errors code -32000; unexpected exceptions redacted (1129-1140) | CONFIRMED | _safe_diagnostic | - |
| 25 | Socket chmod 0600 + listen(1) (1147-1150) | CONFIRMED | 1149-1150 | - |
| 26 | Reconnect wait 30 s = HOPPER_SHUTDOWN_TIMEOUT_MS | CONFIRMED | HopperSessionValues.ts:6 30_000; bootstrap divides by 1000 | - |
| 27 | Progress/diagnostic event sequence, terminal progress | CONFIRMED | bridge lines 1060-1100 | - |
| 28 | Protocol zod schema cited protocol.ts:11-83 | CORRECTED | ends at 79 | 11-79 |
| 29 | Request line `JSON.stringify({id,token,method,params})` HopperClient.ts:187 | CONFIRMED | line 187 | - |
| 30 | Token = randomBytes(32).hex (64 chars) HopperClient.ts:367 | CONFIRMED | line 367 | - |
| 31 | parseHopperServerInfo requires name, positive safe pid, run_id equality (16-35) | CONFIRMED | lines 16-35 | - |
| 32 | SESSION_ROOT = /tmp on macOS else tmpdir (line 82); PrivateRuntimeRoot prefix rea- | CONFIRMED | lines 82, 355-359 | - |
| 33 | Launch argv `[loaderArgs, --analysis, -Y, bootstrap, --executable\|--database, path]` (BridgeLauncher.ts:206-215) | CONFIRMED | lines 206-215 | - |
| 34 | Bootstrap source text (396-411) incl. REA_RECONNECT_TIMEOUT_SECONDS | CONFIRMED | lines 396-411 | - |
| 35 | Bootstrap mode 0600 and removed on non-success paths (345-356, 289-294) | CONFIRMED | lines match | - |
| 36 | Startup timeout default 120000, max 2147483647 | CONFIRMED | providerStartupTimeout.ts:7,14,17-21; docs/installation.md:597 | - |
| 37 | `REA_MANAGED_LINUX_HOPPER_LAUNCHER` is a config variable | CORRECTED | TS constant `"/opt/hopper/bin/Hopper"` (LinuxHopper.ts:343), not an env var | table row rewritten |
| 38 | `REA_X11_DIAGNOSTIC` is a config variable | CORRECTED | stdout prefix `REA_X11_DIAGNOSTIC=` (LinuxPrivateDisplayDiagnostic.ts:9) | table row rewritten |
| 39 | Linux launcher candidates /opt/hopper/bin/Hopper, ~/.local/share/rea/hopper/bin/Hopper, /opt/hopper-v4/bin/hopper, /usr/bin/hopper | CONFIRMED | LinuxHopper.ts:340-358 (managed first); order added | - |
| 40 | macOS pre-launch `open --hide --background -a` + 5 s wait (512-533) | CONFIRMED | HOPPER_BACKGROUND_STARTUP_MS=5_000 | - |
| 41 | Linux wrapper python3 helper args and unshare --user --map-root-user --mount --propagation private (447-494) | CONFIRMED | lines 447-494 | - |
| 42 | Saved .hop declined on macOS (HopperProvider.ts:117-124) | CONFIRMED | lines 117-124 | - |
| 43 | Team ID 2AMA2753NF; DMG Hopper-6.6.0 34 846 271 bytes | CONFIRMED | domain/hopperPublisher.ts:3-11 | - |
| 44 | Linux pins Hopper 6.4.2 deb/rpm/arch with lengths 35755772/32264475/29405968; two SHA-256 build digests | CONFIRMED | LinuxHopper.ts:17-44; hopper-demo-x11.py:23-26 | - |
| 45 | DEMO_CLICK_LEFT=116, DEMO_CLICK_BOTTOM=22, 1280x1024 screen | CONFIRMED | hopper-demo-x11.py:27-35 | - |
| 46 | FAT magics and `hopperMachOImageSchema` (<=128 arches) 22-31 | CONFIRMED | HopperAnalysisProfile.ts:48-50, HopperMachOImage.ts:22-31 | - |
| 47 | Loader args -l Mach-O/FAT/ELF/WinPE with --intel-32/--intel-64/--armv7/--aarch64 | CONFIRMED | HopperAnalysisProfile.ts:151-177 | - |
| 48 | Target support: declines ELF MIPS/RISC-V/PPC, raw-binary, dos-mz/com (104-167) | CONFIRMED | lines 104-167 | - |
| 49 | Availability codes unsupported_host / executable_missing (69-102) | CONFIRMED | lines 69-102 (status `unavailable`) | - |
| 50 | Cleanup method choice shutdown vs shutdown_document (CleanupHopper 159-215) | CONFIRMED | requestShutdown | - |
| 51 | Cleanup ordering and runtime-retained message (62-134) | CONFIRMED | lines 72-134 | - |
| 52 | Lease directory /tmp/rea-hopper-<uid>, stale detection via ECONNREFUSED, `<socket>.recovery` | CONFIRMED | HopperTargetLease.ts:27-30,85-95,312 | - |
| 53 | Queue timeout bound 2147483647; callerState waiting\|cancelled | CONFIRMED | HopperRequestQueue.ts:21,34,65 | - |
| 54 | Regex worker 5 s deadline (MATCHING_DEADLINE_MS) | CONFIRMED | HopperRegexSearch.ts:18 | - |
| 55 | hopperOperationStage maps health=connection, procedure_pseudo_code=decompilation | CONFIRMED | HopperOperationStage.ts:4-9 | - |
| 56 | `isSnapshotCacheable` at AnalysisSnapshotCache.ts:67-77 | CORRECTED | definition at 71-85 and also requires `cachePolicy !== live` | 71-85 |
| 57 | Failure table cites HopperClient.ts:937-972 for process loss | CORRECTED | HopperProcessError constructed at 137-164, 680, 782, 832, 849, 924, 965 | cite replaced |
| 58 | BinarySession cites 261-371 (open), 513-548 (cleanup retry), 679-779, 711, 781-814 | CONFIRMED | function boundaries match (#openWithinTransition 261, #retireClient 513, #execute 679, invalidate 711, #observeRuntimeAvailability 781) | - |
| 59 | Apple-Event injection guard BridgeLauncher.ts:276-285 | CONFIRMED | regex /["\\\r\n]/ | - |
| 60 | No save/export in bridge (persistence caveat) | CONFIRMED | grep saveDocument\|writeDatabase none | - |
| 61 | Bridge imports only json,hmac,os,socket,typing | CONFIRMED | lines 8-12 | - |
| 62 | `open_binary` does not start Hopper (lazy launch) | UNVERIFIABLE | Hopper not installed; code path identical to Ghidra where RUN showed open_binary 19-640 ms and first op paying startup | none |
| 63 | All 3 Mermaid blocks parse | CONFIRMED | check.mjs: checked 3, failed 0 | - |

## Chapter 08 (Ghidra, code + RUN)

| # | Claim | Verdict | Evidence | Fix |
|---|---|---|---|---|
| 1 | Bridge file `ReaGhidraBridge.java` is 4 878 lines | CONFIRMED | wc -l = 4878 | - |
| 2 | Ghidra 12.1.x verified 12.1.4; JDK 21+ (Policy.ts:4-6,58-98) | CONFIRMED | SUPPORTED_GHIDRA_VERSION 12.1.4, JAVA_MAJOR 21; RUN doctor: ghidra-version 12.1.4, java 21.0.12.1 accepted | - |
| 3 | Ghidra identity `{id:ghidra,name:Ghidra,version:null}` (Capabilities.ts:13-18) | CONFIRMED | lines 13-18 | - |
| 4 | Committed version = observed Ghidra version (Profile.ts:98) | CONFIRMED | line 98; RUN provider.version "12.1.4" in Evidence | - |
| 5 | GhidraProvider.ts:78 implements AnalysisProviderCandidate; second deep provider | CONFIRMED | line 78; binary.ts | - |
| 6 | Static only; bridge dispatch closed set 429-476 | CONFIRMED | switch lines 429-476; default method_unavailable | - |
| 7 | One Program per session; list_documents returns one name | CONFIRMED | RUN: ["target-c9c84e179642.bin"] | - |
| 8 | Temp copy `target-<sha12>.<ext>` mode 0600 | CONFIRMED | RUN: target-c9c84e179642.bin 0600; PE: target-1e8b460b745b.exe | - |
| 9 | Headless uses `-readOnly -deleteProject` | CONFIRMED | RUN JVM argv | - |
| 10 | 16 inventory + 13 function = 29 operations (Inventory 25-48, Function 46-60, Session 14-26) | CONFIRMED | dist GHIDRA_OPERATIONS.length=29 | - |
| 11 | 26 read-only + 3 mutating | CONFIRMED | mutators in GHIDRA_MUTATING_OPERATIONS; RUN binary_session shows mutates_artifact only on 3 ops | - |
| 12 | Address regex described as `0x`-hex or `<space>:0x<hex>` | CORRECTED | regex makes `0x` optional (bare hex accepted) (InventoryValues.ts:65-70) | text fixed |
| 13 | `read_bytes` default length 256, min 1 | CONFIRMED | RUN: default returned 256 bytes; length 0 rejected | - |
| 14 | `search_bytes` limit 1..1000 default 100 | CONFIRMED | RUN: limit 5000 rejected (<=1000); Java requireBoundedInteger(...,1,1000) | - |
| 15 | `search_bytes` wildcards / pagination | CONFIRMED | RUN: pattern `55 48 89 e5` found 2 matches with segment, file_offset, procedure | - |
| 16 | `address_to_file_offset` returns file offset | CONFIRMED | RUN: 0x101229 -> 4649 | - |
| 17 | `annotate_native_function` needs >=1 change; schema verbatim | CONFIRMED | RUN: rejected with "Supply at least one annotation change"; rename+comment succeeded | - |
| 18 | `set_addresses_names` per-address success map | CONFIRMED | RUN: {"0x101229":true,"0x10125b":true} | - |
| 19 | Ghidra implements 29 of the 41 official-proxy tools | CORRECTED | 28 official tools (analyze_function is the 29th op but not official) | text fixed |
| 20 | Capability generation: mayShowUi false, mayWriteFilesystem true for all ops, cachePolicy snapshot | CONFIRMED | RUN binary_session groups: launches_process+may_write_filesystem on all, no may_show_ui | - |
| 21 | healthLimitations text verbatim (26-31) | CONFIRMED | also visible verbatim in RUN Evidence limitations | - |
| 22 | Windows mutators advertised unavailable unsupported_host with stated reason | CONFIRMED | Capabilities.ts:200-214 (not run, Windows) | - |
| 23 | Runtime root prefix rea-ghidra-, dot-free parent (SessionRoot.ts:31-55) | CONFIRMED | RUN /tmp/rea-ghidra-XXXXXX; code comment | - |
| 24 | Socket path limits 103/107 bytes, fallback rea-ghidra-socket-* (Transport.ts) | CONFIRMED | Transport.ts:34,42 | - |
| 25 | Snapshot opens O_NONBLOCK, hashes, throws AnalysisArtifactChangedError (23-104) | CONFIRMED | TargetSnapshot.ts:46,62,67,88,109 | - |
| 26 | Launcher writes session.json 0600 with token; ownership.json 0600 | CONFIRMED | RUN stat 600; ownership keys listed | - |
| 27 | Descriptor key set (verbatim, Launcher 241-256) and Java DESCRIPTOR_KEYS 127-135 | CONFIRMED | RUN session.json fields; Java lines 127-135 | - |
| 28 | Java deletes descriptor on POSIX (196-198); verifies version and SHA-256 (216-228) | CONFIRMED | Bridge.java lines | - |
| 29 | JVM direct launch: LaunchSupport -envvars and -vmargs; argv skeleton (JavaLaunch 160-191) | CONFIRMED | RUN argv and launch_support diagnostics show both modes | - |
| 30 | Default heap `-Xmx2G`, `-XX:ParallelGCThreads=2`, `-XX:CICompilerCount=2` | CONFIRMED | RUN argv | - |
| 31 | `GHIDRA_HEADLESS_MAXMEM` > `GHIDRA_MAXMEM` > 2G | CONFIRMED | RUN GHIDRA_HEADLESS_MAXMEM=1G -> -Xmx1G; code line 172 | - |
| 32 | Caller `_JAVA_OPTIONS`/`JAVA_TOOL_OPTIONS` cleared | CONFIRMED | RUN /proc/<pid>/environ empty values | - |
| 33 | HOME/TMPDIR/XDG_* redirected into runtime root | CONFIRMED | RUN environ | - |
| 34 | Headless arg skeleton: pre/post scripts, NoReturnFix non-Windows, bridge last | CONFIRMED | RUN ELF: only NoReturnFix + Bridge post-scripts; PE same; Launcher.ts:555-719 | - |
| 35 | DOS MZ/COM/PSP/raw loaders and lanes (Launcher 611-660) | CONFIRMED | code; RUN raw: BinaryLoader, caller-supplied-v1 | - |
| 36 | Transport: UNIX socket rw------- on POSIX; loopback TCP on Windows (261-357) | CONFIRMED | RUN srw------- socket; Windows DOC | - |
| 37 | Startup `ping` handshake and session-info schema (Startup 33-61, SessionValues 37-106,143-181) | CONFIRMED | code; RUN handshake passes (profile_digest in diagnostics) | - |
| 38 | Shutdown ack {shutdown:true,project_ephemeral:true} (SessionValues 184-189; Java 393-399) | CONFIRMED | lines match | - |
| 39 | Response schema verbatim (protocol.ts:6-22), no progress events | CONFIRMED | lines 6-22 | - |
| 40 | 10 s progress heartbeat during startup (Client 235-262) | CONFIRMED | setInterval 10_000 at line 261 | - |
| 41 | Bridge error codes list | CORRECTED | also ambiguous, annotation_readback_mismatch, invalid_function_name, regex_stack_exhausted; Node remaps unknown procedure to invalid_request | text extended |
| 42 | Startup deadline default 330 000 ms | CONFIRMED | providerStartupTimeout.ts:4; RUN with 3000 ms -> provider_timeout (details.timeout_ms 3000) | - |
| 43 | Shutdown request timeout 10 s (SHUTDOWN_TIMEOUT_MS) | CONFIRMED | GhidraClient.ts:79,788; RUN close ~0.5 s | - |
| 44 | Cancel active request kills session; annotations lost | UNVERIFIABLE | code path read (Client 167-171, 491-510); RUN abort at 60 ms did not interrupt a 600 ms call, so not reproduced | documented in 9.1 |
| 45 | `open_binary` does not start Ghidra (even for PE) | CONFIRMED | RUN open 19-101 ms ELF, 640 ms PE, 10 ms raw; first op 16-50 s | - |
| 46 | PE/seeds/extension/soft-float targets call client.start() before each op (ProviderClient 813-832) | CONFIRMED | code lines 813-832 | - |
| 47 | Profile parameter keys and example values (section 5 table) | CONFIRMED | RUN ELF profile printed all keys with identical values; process_launch inspected-jvm-launch-support-v1 | - |
| 48 | `language_selection` values | CORRECTED | also `caller-supplied-v1` (raw); absent for header-detected ELF | text fixed |
| 49 | Analysis seeds TSV format, limits 32 MiB/1e6/2000, label needs name | CONFIRMED | Seeds.ts:15-17,64-120; RUN label seed -> `seeded_main` applied, profile entries {function 1,label 1} | - |
| 50 | Disabled analyzers <=32 names, <=120 chars; `ghidra-default+disabled:<names>` | CONFIRMED | ghidraDisabledAnalyzers.ts:3-4; RUN preset string `ghidra-default+disabled:Stack` | - |
| 51 | NoReturnFix names malloc,__tls_get_addr,memcpy,memset,strlen,__errno_location | CONFIRMED | NoReturnFix.java:23 | - |
| 52 | Target admission: executable only; universal Mach-O >1 slice refused; supported arch set (66-75, 161-222) | CONFIRMED | lines 66-75,161-222 | - |
| 53 | Raw-binary language table (x86 32/64, ARM v7, AArch64 v8A, 6502) | CONFIRMED | RawBinaryLanguage.ts:20-48 | - |
| 54 | Env schema `environment.ts:33-69` and cspec-requires-language (134-149) | CONFIRMED | lines match | - |
| 55 | REA_SWIFTC_COMPILE_TIMEOUT_MS default 120 000 | CONFIRMED | providerStartupTimeout.ts:11 | - |
| 56 | NativeAOT limits 128 MiB / 64 MiB / 4 MiB; extension JAR <=8 MiB; extension schema (Extensions.ts:20-30) | CONFIRMED | nativeAotPe.ts:9-13; Extensions.ts:69 and 20-30 | - |
| 57 | Windows P0 details (Node >=22.19, Job Objects, DACL) | UNVERIFIABLE | Windows-only; DOC | - |
| 58 | BinarySession.ts:410-416 external-mutation refusal text | CONFIRMED | line 414 | - |
| 59 | inspect_native_load_image: DOS/COM/raw only; ELF returns unsupported | CONFIRMED | RUN ELF status unsupported; raw verified | - |
| 60 | Per-op timing note: first query up to 330 s | CONFIRMED | RUN first-op 16-50 s on tiny samples, bound is the timeout | - |
| 61 | Linux ps (procps) prerequisite | CONFIRMED | docs/installation.md:335-339 | - |
| 62 | All 3 Mermaid blocks parse | CONFIRMED | check.mjs: checked 3, failed 0 | - |

## Chapter 14 (native, Apple, archives; code + RUN)

| # | Claim | Verdict | Evidence | Fix |
|---|---|---|---|---|
| 1 | Two classifiers: admission 4096-byte prefix (Resolver 301,459), inventory 8192 (ArtifactHash.ts:19) | CONFIRMED | lines 301,459,19 | - |
| 2 | XML plist probe cap 1 MiB | CONFIRMED | appleArchiveFormat.ts:7 | - |
| 3 | BINARY_ARCHITECTURES list (binaryTargetTypes.ts:4-13) | CONFIRMED | 8 values | - |
| 4 | ELF machine map 3,62,8,20,40,183,243; other => unsupported ELF architecture | CONFIRMED | binaryTarget.ts:543-563; RUN patched ELFs -> mips/powerpc/arm/riscv, 0x1234 rejected | - |
| 5 | ELF fixed-header checks (class, data, version, ehsize) | CONFIRMED | elfFixedHeader.ts:14-56 | - |
| 6 | Mach-O thin magics, CPU map | CONFIRMED | binaryTarget.ts:529-541; RUN thin x86_64/arm64 headers admitted | - |
| 7 | Fat magics, <=128 arches, host slice selection | CONFIRMED | RUN fat(x86_64+arm64): x64 host -> x86_64 slice@4096, arm64 host -> arm64 | - |
| 8 | Fat with count 0 / >128 | CORRECTED | count 0 is `malformed`; >128 is `not-fat` | text fixed |
| 9 | Fat without host arch fails with `FAT binary has no host-compatible <arch>` | CORRECTED | message prints Node arch spelling (x64, ia32, riscv64) | text fixed |
| 10 | Java class cafebabe not mistaken for fat Mach-O | CONFIRMED | RUN javaclass.class -> file_format_rejected | - |
| 11 | PE detection, machine codes 0x14c/0x8664/0x1c0/0x1c2/0x1c4/0xaa64 | CONFIRMED | peMachine.ts:10-24; RUN pe_demo x86_64, Stager.dll x86 managed | - |
| 12 | PE managed = CLI directory non-zero; role from characteristics 0x0002/0x2000 | CONFIRMED | binaryTarget.ts:316-330; RUN managed=true/false, role application | - |
| 13 | DOS MZ validation parseDosMzHeader | CONFIRMED | RUN malformed MZ -> `invalid DOS MZ header size or empty load module` | - |
| 14 | DOS COM never sniffed; length 1..65 280 | CONFIRMED | RUN 65280 admitted, 65281 rejected | - |
| 15 | COM/raw failures use load_selection_rejected | CORRECTED | COM length failure is `file_format_rejected`; raw pairing errors are load_selection_rejected | text fixed |
| 16 | raw-binary admission rules (regex, ARM alignment, width) | CONFIRMED | RUN all 5 variants matched the stated rejections | - |
| 17 | ZIP magic variants PK 03 04 / 05 06 / 07 08; suffix picks family | CONFIRMED | zipPackageFormat.ts:21-47; RUN suffix matrix (.zip .ipa .apk .msix .msixbundle .appx .hap) | - |
| 18 | Root `.app` zip => app-pack | CONFIRMED | RUN x.app (file) -> archive app-pack | - |
| 19 | ZIP-magic file named .exe is an archive | CONFIRMED | RUN named_exe.exe -> archive zip | - |
| 20 | ASAR admission trusts `.asar` suffix alone | CONFIRMED | RUN fake.asar and real.asar both `archive asar` | - |
| 21 | ASAR inventory header predicate | CORRECTED | also requires stringLength <= payloadSize-4 | text fixed |
| 22 | Fake .asar fails with reason `format` when opened | CORRECTED | true for extract_artifact; inspect_artifact succeeds with root `file`, 1 node | text fixed |
| 23 | DMG requires `koly` at size-512; PKG requires xar! | CONFIRMED | RUN koly.dmg archive dmg, fake.dmg rejected, fake.pkg archive pkg | - |
| 24 | bplist00 and XML plist regardless of extension | CONFIRMED | RUN bplist.dat / xmlnoext.dat -> artifact plist | - |
| 25 | WASM refused with wasm_requires_static_inspection | CONFIRMED | RUN wasm.wasm, m.wasm | - |
| 26 | `.hop` after WASM probe; renamed WASM refused | CORRECTED | true without explicit kind; explicit kind=database skips probe; ZIP-magic .hop -> database | text fixed |
| 27 | Directory handling: .app resolved, other dir refused | CONFIRMED | RUN plain_dir -> directory_requires_file; My.app resolved | - |
| 28 | `.app` safety: unsafe CFBundleExecutable, executable must stay inside programs dir | CONFIRMED | RUN Evil.app and Sym.app messages | - |
| 29 | JS/source map suffix-only | CONFIRMED | RUN a.js, a.js.map | - |
| 30 | Router: archive/artifact targets have no deep provider; aux providers always composed | CONFIRMED | SessionProviderRouter.ts:112; auxiliaryAnalysisProviders.ts:17-52; Hopper/Ghidra/IDA supportability code | - |
| 31 | Capability gate BinarySessionExecution.ts:66-80 | CONFIRMED | lines 66-80; RUN inspect-macho/asset-catalog -> capability_unavailable | - |
| 32 | Duplicate operation names throw TypeError (CompositeProvider 120-140) | CONFIRMED | lines 129-132 | - |
| 33 | Platform matrix: DMG/universal children macOS only; PKG root-hash only | CONFIRMED | reader.ts:20-43,60-79; RUN dmg/pkg limitation strings | - |
| 34 | Effect flags metadata (ArtifactProviderMetadata 16-27, NativeMacOSProviderMetadata 14-17,36-52) | CONFIRMED | lines 14-26 / 12-17 / 35-47 (off by 1-2) | - |
| 35 | Allow-listed native tools set (CommandRunner 279-291), 60 s timeout, 64 MiB output | CONFIRMED | CommandRunner.ts:21,23,279-290 | - |
| 36 | inspect_pe_resources schema defaults 64 MiB/16384, max 512 MiB/65536 | CONFIRMED | peResources.ts:19-45; RUN limits enforced | - |
| 37 | PE resources budget METADATA_BYTES 8 MiB at :15 | CORRECTED | constant at line 20 | text fixed |
| 38 | PE resource output fields and coverage complete | CONFIRMED | RUN demo.exe: coverage complete 6/2, payload sha256 per resource | - |
| 39 | Failure mapping integrity/limit/path\|format | CONFIRMED | RUN limit -> resource_constraint; ELF -> invalid_request | - |
| 40 | AppBundleExecutable 16 MiB plist budget, layouts | CONFIRMED | AppBundleExecutable.ts:19 | - |
| 41 | Directory reader never follows symlinks, identity checks | CONFIRMED | code lines 295-324; zip symlink RUN | - |
| 42 | ZIP reader: central directory only, encrypted never decrypted, symlink target not read | CONFIRMED | RUN sym.zip: `Archive symlink target was not read.`; limitation text | - |
| 43 | ZIP decompression budget max(256 MiB, 500x archive) (artifactDecompressionBudget.ts:19-32) | CONFIRMED | constants 500 and 256 MiB; RUN bomb: 611640*500 = 305820000 in message | - |
| 44 | Nested ZIP not expanded | CONFIRMED | RUN nested.zip -> inner.zip is one zip file occurrence | - |
| 45 | zip-slip/absolute member fails whole inventory (path) | CONFIRMED | RUN slip.zip and abs.zip -> artifact_operation_failed reason path | - |
| 46 | Backslashes are literal name characters | CONFIRMED | RUN bs.zip inventory+extract wrote file `..\..\x` inside root | - |
| 47 | ASAR limits: 16 MiB header, 64 MiB listing (units*2+256) | CONFIRMED | AsarHeader.ts:7; AsarListing.ts:8,83 | - |
| 48 | DMG: hdiutil attach -readonly -nobrowse -plist -mountroot, 120 s | CONFIRMED | NativeDmgArtifactReader.ts:25,383-396 | - |
| 49 | extract_artifact output root injected by adapter tmpdir/rea-extracted-<uuid> | CONFIRMED | registerArtifactTools.ts:35-42; ExtractionDestination.ts; RUN /tmp/rea-extracted-<uuid> | - |
| 50 | Output tree mode 0700, files 0600, no exec bits, tree kept | CONFIRMED | RUN stat; run.sh was 0755 in zip, extracted 0600 | - |
| 51 | Extraction refuses existing root (EEXIST) | CONFIRMED | SafeOutputTree.ts:109-116 | - |
| 52 | Extraction supports directory/ASAR/ZIP/Mach-O only; DMG unsupported | CONFIRMED | ArtifactExtraction.ts:409-427; RUN dmg -> unsupported_target | - |
| 53 | Symlinks never extracted; encrypted entry aborts extraction | CONFIRMED | RUN sym.zip extracted only ok.txt+run.sh; ArtifactExtraction.ts:100-105,139-147 | - |
| 54 | Case-folding clash makes extraction fail | CORRECTED | only on case-insensitive destination; RUN on Linux both files extracted | table fixed |
| 55 | O_CREAT\|O_EXCL\|O_NOFOLLOW 0600; size and hash must equal inventory | CONFIRMED | SafeOutputTree.ts:203-215,230-262 | - |
| 56 | Residual pathname race comment (53-57) | CONFIRMED | lines 53-57 | - |
| 57 | keyed archive limits 200 000 objects/edges, 128 nesting; 64 MiB / 8x decode | CONFIRMED | keyedArchive.ts:111,138,175; KeyedArchiveReader.ts:36-38 | - |
| 58 | IB limits 64/20 000/40 000; 32 MiB input, 256 MiB decode, 64 reported omitted | CONFIRMED | artifactToolContracts.ts:94-96; InterfaceBuilderAnalysis.ts:41-43 | - |
| 59 | `rea-interface-builder/1`; stale ibtool comment at interfaceBuilderGraph.ts:15 | CONFIRMED | line 173; line 15 | - |
| 60 | Asset catalog 64 MiB limits, assetutil 60 s; input limit 1..10000 default 1000 | CONFIRMED | AppleAssetCatalogAnalysis.ts:18-19,259-260; appleAssetCatalog.ts:31-32; RUN unavailable on Linux | - |
| 61 | dyld: roots/architecture schema, outcomes, findings, 8 limitations, concurrency 8 | CONFIRMED | dylibResolution.ts:38-41,121-132; findings.ts; DylibResolutionReader.ts:26; RUN My.app limitations 8, coverage complete | - |
| 62 | Load-command cap 16 MiB; dispatch decoder 64 MiB, 4096 load commands | CONFIRMED | MachoLoadCommandReader.ts:18; AppleDispatchMetadata.ts:191; AppleMachoSelection.ts:174 | - |
| 63 | inspect_signature runs on private snapshot (rea-signature-) | CONFIRMED | SignatureTargetBinding.ts:82-83 | - |
| 64 | inspect_native_dispatch_metadata max_records default 5000 max 20 000; falls back to list_names; description gap | CONFIRMED | enhancedInputs.ts:11-13; NativeDispatchMetadataInspection.ts:18-36; description text lacks mention of binary decode | - |
| 65 | ARTIFACT_ANALYSIS_OPERATIONS (123-126) and artifact input schemas | CONFIRMED | lines 123-126 | - |
| 66 | noteUnreadContainerSuffix cited 127-133 | CORRECTED | 116-126 | cite fixed |
| 67 | 5 Mermaid blocks parse | CONFIRMED | check.mjs: checked 5, failed 0 | - |
