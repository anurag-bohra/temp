#!/usr/bin/env bash
# Reproduces every manual test in docs/deep-dive/27-manual-test-log.md
# Usage: run-all.sh <path-to-rea-checkout-already-built> <output-dir>
# Prereqs (Linux x64): node 22.19+, gcc, go, objdump, python3 with pwntools==4.15.0 pyelftools==0.33 unicorn==2.1.2, zip, gdb (optional), prlimit.
# Build REA first:  npm ci --ignore-scripts && npx tsc -p tsconfig.build.json && node scripts/bundle-runtime.mjs
#                   node scripts/generate-product-catalog.mjs && node scripts/generate-mcp-tool-catalog.mjs   (optional catalogs)
set -u
REA=${1:?rea checkout}; OUT=${2:?output dir}; HERE=$(cd "$(dirname "$0")" && pwd)
W=$OUT/work; mkdir -p "$W" "$OUT/results"; R="node $REA/scripts/rea.mjs"
export REA_PWNTOOLS_PYTHON=$(which python3)
# ---- build demo samples (all benign; nothing here is executed except the crash demo in T9) ----
cp -r "$HERE/samples/jsapp-v1" "$W/jsapp1"; cp -r "$W/jsapp1" "$W/jsapp2"; cp "$HERE/samples/jsapp-v2-diff/main.js" "$W/jsapp2/src/main.js"
mkdir -p "$W/go" "$W/c" "$W/vuln" "$W/evm" "$W/core"; cp "$HERE/samples/go-main.go" "$W/go/main.go"; cp "$HERE/samples/c2-like.c" "$W/c/t.c"; cp "$HERE/samples/vuln.c" "$W/vuln/v.c"; cp "$HERE/samples/evm.hex" "$W/evm/c.hex"
(cd "$W/go" && go mod init beacon >/dev/null 2>&1 && go build -o beacon .)
gcc -O0 -o "$W/c/t" "$W/c/t.c"
gcc -O0 -fno-stack-protector -z execstack -no-pie -Wl,-z,norelro -o "$W/vuln/weak" "$W/vuln/v.c" 2>/dev/null
gcc -O2 -fstack-protector-strong -fPIE -pie -Wl,-z,relro,-z,now -D_FORTIFY_SOURCE=2 -o "$W/vuln/hard" "$W/vuln/v.c" 2>/dev/null
(cd "$W" && zip -qr sample.zip jsapp1)
# ---- tests ----
$R analyze-javascript-application "$W/jsapp1" --json > "$OUT/results/T1-js-v1.json" 2>/dev/null
$R analyze-javascript-application "$W/jsapp2" --json > "$OUT/results/T1b-js-v2.json" 2>/dev/null
node -e 'const f=require("fs"),a=JSON.parse(f.readFileSync(process.argv[1]));f.writeFileSync(process.argv[2],JSON.stringify({source:{kind:"inline",evidence:a},view:{kind:"summary"}}));f.writeFileSync(process.argv[3],JSON.stringify({source:{kind:"inline",evidence:a},view:{kind:"page",collection:"modules",offset:0,limit:5}}));f.writeFileSync(process.argv[4],JSON.stringify({application:a,direction:"both",seed:{kind:"module",match:"exact",value:"src/net.js",case_sensitive:false}}))' "$OUT/results/T1-js-v1.json" "$W/v-summary.json" "$W/v-page.json" "$W/trace-in.json"
$R inspect-analysis-view "$W/v-summary.json" --json > "$OUT/results/T2-view-summary.json" 2>/dev/null
$R inspect-analysis-view "$W/v-page.json" --json > "$OUT/results/T3-view-modules-page.json" 2>/dev/null
$R trace-application-feature "$W/trace-in.json" --json > "$OUT/results/T4-trace-net-js.json" 2>/dev/null
node -e 'const f=require("fs");f.writeFileSync(process.argv[3],JSON.stringify({left:JSON.parse(f.readFileSync(process.argv[1])),right:JSON.parse(f.readFileSync(process.argv[2]))}))' "$OUT/results/T1-js-v1.json" "$OUT/results/T1b-js-v2.json" "$W/cmp-in.json"
$R compare-application-versions "$W/cmp-in.json" --json > "$OUT/results/T5-compare-v1-v2.json" 2>/dev/null
$R inspect-go-binary "$W/go/beacon" --json > "$OUT/results/T6-go.json" 2>/dev/null
$R inspect-artifact "$W/sample.zip" --json > "$OUT/results/T7-zip.json" 2>/dev/null
$R inspect-with-objdump "$W/c/t" symbols --json > "$OUT/results/T8-objdump-symbols.json" 2>/dev/null
$R inspect-binary-layout "$W/vuln/weak" --json > "$OUT/results/T9a-layout-weak.json" 2>/dev/null
$R inspect-binary-layout "$W/vuln/hard" --json > "$OUT/results/T9b-layout-hard.json" 2>/dev/null
# crash demo: runs the deliberately vulnerable demo program with an oversized argument to create a core file (needs core dumps enabled)
( ulimit -c unlimited; cd "$W/core" && "$W/vuln/weak" "$(python3 -c 'print("A"*200)')" ) >/dev/null 2>&1
CORE=$(ls "$W/core"/core* 2>/dev/null | head -1)
[ -n "$CORE" ] && $R inspect-recorded-crash "$CORE" --json > "$OUT/results/T10-recorded-crash.json" 2>/dev/null
$R inspect-evm-interface "$W/evm/c.hex" hex --json > "$OUT/results/T11-evm.json" 2>/dev/null
sha256sum "$W/go/beacon" "$W/c/t" "$W/vuln/weak" "$W/vuln/hard" "$W/sample.zip" > "$OUT/results/binary-hashes.txt"
ls -la "$OUT/results"
