#!/usr/bin/env bash
# Reproduces the lab-round manual tests (docs/deep-dive/27-manual-test-log.md part 2).
# Usage: run-lab.sh <rea-checkout-built> <output-dir>   (run run-all.sh first or let this script build what it needs)
# Lab prerequisites (see 27 for versions): Ghidra 12.1.4 (GHIDRA_INSTALL_DIR), JADX MCP jar (REA_JADX_MCP_JAR), WABT 1.0.42 (REA_WABT_BIN_DIRECTORY),
# binwalk 3.1.0 (REA_BINWALK_COMMAND), tshark/capinfos/prlimit, Node 24 (NODE24), dotnet-sdk-8.0, aapt + dalvik-exchange + android-23 jar, mingw-w64, sqlite3, squashfs-tools, yara, frida (npm rebuild frida).
set -u
REA=${1:?rea checkout}; OUT=${2:?output dir}; HERE=$(cd "$(dirname "$0")" && pwd); W=$OUT/work; mkdir -p "$W" "$OUT/results" "$OUT/mcp"
R="node $REA/scripts/rea.mjs"; DRV="node $HERE/mcp-driver/drive.mjs $REA"
: "${GHIDRA_INSTALL_DIR:=/opt/lab/ghidra_12.1.4_PUBLIC}"; : "${REA_JADX_MCP_JAR:=/opt/lab/jadx-mcp.jar}"; : "${REA_WABT_BIN_DIRECTORY:=/opt/lab/wabt-1.0.42/bin}"
: "${REA_BINWALK_COMMAND:=/opt/lab/binwalk3/bin/binwalk}"; : "${NODE24:=/opt/lab/node24/node_modules/node/bin/node}"
export GHIDRA_INSTALL_DIR REA_JADX_MCP_JAR REA_WABT_BIN_DIRECTORY REA_BINWALK_COMMAND REA_PWNTOOLS_PYTHON=$(which python3) REA_TSHARK_COMMAND=$(which tshark) REA_CAPINFOS_COMMAND=$(which capinfos) REA_TSHARK_PRLIMIT_COMMAND=$(which prlimit)
# --- samples ---
cp "$HERE/samples/c2-like.c" "$W/t.c"; gcc -O0 -o "$W/t" "$W/t.c"
cp "$HERE/samples/vuln.c" "$W/v.c"; gcc -O2 -fstack-protector-strong -fPIE -pie -Wl,-z,relro,-z,now -D_FORTIFY_SOURCE=2 -o "$W/hard" "$W/v.c" 2>/dev/null
mkdir -p "$W/dn" && cp "$HERE/samples/dotnet/"* "$W/dn/" && (cd "$W/dn" && DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 dotnet build -c Release -o out >/dev/null 2>&1)
mkdir -p "$W/apk/src/com/demo/spy" "$W/apk/classes" && cp "$HERE/samples/apk/MainActivity.java" "$W/apk/src/com/demo/spy/" && cp "$HERE/samples/apk/AndroidManifest.xml" "$W/apk/" && (cd "$W/apk" && AJ=/usr/lib/android-sdk/platforms/android-23/android.jar && javac -source 8 -target 8 -cp $AJ -d classes src/com/demo/spy/MainActivity.java 2>/dev/null; dalvik-exchange --dex --output=classes.dex classes >/dev/null 2>&1; aapt package -f -M AndroidManifest.xml -I $AJ -F demo.apk && zip -q -j demo.apk classes.dex)
mkdir -p "$W/pe" && cp "$HERE/samples/pe/"* "$W/pe/" && (cd "$W/pe" && printf 'MZ-fake-embedded-payload-for-test' > payload.bin && x86_64-w64-mingw32-windres r.rc -O coff -o r.o && x86_64-w64-mingw32-gcc p.c r.o -o demo.exe)
mkdir -p "$W/wasm" && wat2wasm "$HERE/samples/wasm/m.wat" -o "$W/wasm/m.wasm"
rm -f "$W/app.sqlite"; sqlite3 "$W/app.sqlite" "create table cookies(host text,name text,value text); insert into cookies values('example.invalid','session','tok_demo_123'),('c2.example.invalid','id','42'); create table settings(k text,v text); insert into settings values('beacon_interval','60');"
mkdir -p "$W/fw/root/bin" && cp "$W/t" "$W/fw/root/bin/updater" && mksquashfs "$W/fw/root" "$W/fw/rootfs.squashfs" -noappend -quiet >/dev/null && head -c 4096 /dev/urandom > "$W/fw/pad.bin" && cat "$W/fw/pad.bin" "$W/fw/rootfs.squashfs" > "$W/fw/firmware.bin"
# loopback HTTP capture (beacon-like requests)
(cd "$W" && python3 -m http.server 8765 --bind 127.0.0.1 >/dev/null 2>&1 & echo $! > "$W/http.pid"); sleep 1; (timeout 8 tshark -i lo -f "tcp port 8765" -w "$W/beacon.pcapng" >/dev/null 2>&1 &); sleep 2
curl -s -A "UpdaterBot/1.0" "http://127.0.0.1:8765/beacon?id=42&host=lab" -o /dev/null; curl -s -A "UpdaterBot/1.0" -X POST -d k=v http://127.0.0.1:8765/task -o /dev/null; sleep 7; kill "$(cat "$W/http.pid")" 2>/dev/null
# --- tests ---
cat > "$W/s-native.json" <<JSON
[{"tool":"open_binary","args":{"path":"$W/t","provider_id":"ghidra"}},{"tool":"binary_overview"},{"tool":"list_procedures"},{"tool":"search_strings","args":{"pattern":"198.51","mode":"literal"}},
 {"tool":"xrefs","args":{"address":"0x102004"}},{"tool":"resolve_containing_procedure","args":{"address":"0x10125b"}},{"tool":"analyze_function","args":{"procedure":"main"}},
 {"tool":"batch_decompile","args":{"addresses":["check","main"]}},{"tool":"inspect_native_api","args":{"procedure":"main"}},{"tool":"trace_call_path","args":{"start":"main","goal":"check","direction":"forward"}},
 {"tool":"trace_native_values","args":{"procedure":"main","max_depth":2}},{"tool":"set_address_name","args":{"address":"0x101229","name":"anti_debug_check"}},
 {"tool":"record_unknown","args":{"question":"Is the C2 address ever overridden at runtime?","severity":"medium","domain":"protocol","required_authority":"controlled-replay","required_confidence":"observed","required_environment":null,"recommended_probes":[{"operation":"capture_process_scenario","rationale":"lab replay"}],"relationships":[],"supporting_evidence_ids":[],"contradicting_evidence_ids":[]}},
 {"tool":"list_unknowns"},{"tool":"get_evidence_bundle","args":{"detail":"summary"}},{"tool":"export_evidence_bundle","args":{"path":"$OUT/mcp/bundle.json","overwrite":true}},{"tool":"close_binary"}]
JSON
$DRV "$W/s-native.json" "$OUT/mcp/native-ghidra.json" > "$OUT/results/L1-native-ghidra.log" 2>&1
$R inspect-managed-artifact "$W/dn/out/Stager.dll" --json > "$OUT/results/L2-dn-artifact.json" 2>/dev/null; $R inspect-managed-members "$W/dn/out/Stager.dll" --json > "$OUT/results/L2-dn-members.json" 2>/dev/null; $R inspect-managed-native-boundaries "$W/dn/out/Stager.dll" --json > "$OUT/results/L2-dn-native.json" 2>/dev/null
$R inspect-android-package "$W/apk/demo.apk" --json > "$OUT/results/L3-apk-package.json" 2>/dev/null; $R search-android-classes "$W/apk/demo.apk" MainActivity --json > "$OUT/results/L3-apk-search.json" 2>/dev/null
$R inspect-android-method "$W/apk/demo.apk" com.demo.spy.MainActivity exfil --json > "$OUT/results/L3-apk-method.json" 2>/dev/null; $R trace-android-references "$W/apk/demo.apk" com.demo.spy.MainActivity --method-name exfil --json > "$OUT/results/L3-apk-refs.json" 2>/dev/null
$R inspect-pe-resources "$W/pe/demo.exe" --json > "$OUT/results/L4-pe.json" 2>/dev/null; $R inspect-wasm-artifact "$W/wasm/m.wasm" --json > "$OUT/results/L5-wasm.json" 2>/dev/null
$NODE24 "$REA/scripts/rea.mjs" inspect-sqlite-database "$W/app.sqlite" --table cookies --row-limit 5 --json > "$OUT/results/L6-sqlite.json" 2>/dev/null
$R inspect-firmware-regions "$W/fw/firmware.bin" --json > "$OUT/results/L7-firmware.json" 2>/dev/null
$R inspect-pcap-capture "$W/beacon.pcapng" --json > "$OUT/results/L8-pcap.json" 2>/dev/null
$R inspect-packet-capture "$W/beacon.pcapng" --fields ip.src --fields ip.dst --fields http.request.uri --fields http.user_agent --display_filter http.request --json > "$OUT/results/L8-packet-fields.json" 2>/dev/null
mkdir -p "$W/cwd"; printf '{"executable":"%s","arguments":["hello"],"working_directory":"%s","timeout_ms":10000,"filesystem_observation_paths":["%s"]}' "$W/hard" "$W/cwd" "$W/cwd" > "$W/cap.json"
$R capture-process "$W/cap.json" --json > "$OUT/results/L9-capture-a.json" 2>/dev/null; $R capture-process "$W/cap.json" --json > "$OUT/results/L9-capture-b.json" 2>/dev/null
$R compare-process-captures "$OUT/results/L9-capture-a.json" "$OUT/results/L9-capture-b.json" --json > "$OUT/results/L9-compare-identical-runs.json" 2>/dev/null
yara -s -r "$HERE/../prototype/rea-triage/demo-rules.yar" "$W" 2>/dev/null | grep -v "^0x" > "$OUT/results/L10-yara.txt"
ls -la "$OUT/results"
