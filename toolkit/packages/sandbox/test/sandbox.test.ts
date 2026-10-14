import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createServer, type Server } from "node:http";
import { chmodSync, existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseEvidence } from "@rtk/evidence";
import { runSandboxed, probeCapabilities, parseStrace, type SandboxResult, type Capabilities } from "../src/index.ts";

const gcc = (() => { try { execFileSync("gcc", ["--version"], { stdio: "ignore" }); return true; } catch { return false; } })();
let dir = ""; let caps: Capabilities;
const bins: Record<string, string> = {};
const SRC: Record<string, string> = {
  loop: `int main(void){ for(;;){} }`,
  forkstorm: `#include <unistd.h>
#include <stdio.h>
int main(void){ int n=0; for(int i=0;i<100000;i++){ pid_t p=fork(); if(p==0){ sleep(30); _exit(0);} if(p<0) break; n++; } printf("forked=%d\\n",n); fflush(stdout); return 0; }`,
  daemon: `#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
int main(void){ pid_t p=fork(); if(p>0){ printf("parent-exits\\n"); fflush(stdout); return 0; }
 setsid(); pid_t q=fork(); if(q>0) _exit(0); sleep(60); return 0; }`,
  flood: `#include <unistd.h>
#include <string.h>
int main(void){ char b[4096]; memset(b,'A',sizeof b); for(;;){ if(write(1,b,sizeof b)<0) break; } return 0; }`,
  crasher: `int main(void){ volatile int *p=0; *p=1; return 0; }`,
  connector: `#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
int main(int c,char**v){ int s=socket(AF_INET,SOCK_STREAM,0); struct sockaddr_in a={0}; a.sin_family=AF_INET; a.sin_port=htons(atoi(v[1])); inet_pton(AF_INET,"127.0.0.1",&a.sin_addr);
 if(connect(s,(struct sockaddr*)&a,sizeof a)==0){ const char*r="GET / HTTP/1.0\\r\\n\\r\\n"; write(s,r,strlen(r)); char buf[256]; read(s,buf,sizeof buf); printf("connected\\n"); } else printf("connect-failed:%s\\n",strerror(errno)); return 0; }`,
};
before(async () => {
  dir = mkdtempSync(join(tmpdir(), "rtk-sbx-test-")); chmodSync(dir, 0o755);
  caps = await probeCapabilities();
  if (gcc) for (const [n, s] of Object.entries(SRC)) { writeFileSync(join(dir, n + ".c"), s); const out = join(dir, `${n}_${randomBytes(4).toString("hex")}`); execFileSync("gcc", ["-O0", "-o", out, join(dir, n + ".c")]); chmodSync(out, 0o755); bins[n] = out; }
  writeFileSync(join(dir, "envdump.sh"), "#!/bin/sh\nenv\n"); chmodSync(join(dir, "envdump.sh"), 0o755); bins.envdump = join(dir, "envdump.sh");
  writeFileSync(join(dir, "writer.sh"), "#!/bin/sh\necho hello > out.txt\nmkdir sub\necho x > sub/y.bin\nexit 3\n"); chmodSync(join(dir, "writer.sh"), 0o755); bins.writer = join(dir, "writer.sh");
  writeFileSync(join(dir, "view.sh"), "#!/bin/sh\necho pid=$$\nls /\necho ---\nls /proc | head -n 3\necho ---\nif echo x > /sample/zz 2>/dev/null; then echo sample-writable; else echo sample-readonly; fi\ncat /etc/passwd 2>&1 | head -n 1\nid -u\n"); chmodSync(join(dir, "view.sh"), 0o755); bins.view = join(dir, "view.sh");
});
after(() => { if (dir) rmSync(dir, { recursive: true, force: true }); });

const res = (e: { normalized_result: unknown }) => e.normalized_result as SandboxResult;
const needGcc = (t: { skip: (m: string) => void }) => { if (!gcc) { t.skip("gcc missing"); return false; } return true; };
const sha = (p: string) => createHash("sha256").update(readFileSync(p)).digest("hex");
const procsWith = (needle: string) => readdirSync("/proc").filter((n) => /^\d+$/u.test(n)).filter((n) => { try { return readFileSync(`/proc/${n}/cmdline`, "latin1").includes(needle); } catch { return false; } });

test("capability probe reports levels honestly", () => {
  assert.equal(caps.levels.process, true);
  console.log("# probe:", JSON.stringify({ levels: caps.levels, strace: caps.strace, root: caps.isRoot, notes: caps.notes }));
});

test("Evidence envelope: provider, operation, authority, environment, sample digest", async () => {
  const ev = await runSandboxed({ sample: bins.envdump!, isolation: "process" });
  parseEvidence(JSON.parse(JSON.stringify(ev)));
  assert.equal(ev.provider.id, "rtk-sandbox"); assert.equal(ev.operation, "run_sandboxed");
  assert.equal(ev.authority, "controlled-replay"); assert.equal(ev.confidence, "observed");
  assert.equal(ev.environment?.isolation, "process"); assert.equal(ev.environment?.platform, process.platform);
  assert.equal(ev.subject?.digest.sha256, sha(bins.envdump!));
  assert.ok(ev.limitations.some((l) => /not a virtual machine/u.test(l)));
  assert.ok(ev.limitations.some((l) => /Process-level isolation only/u.test(l)));
});

test("environment is not inherited except explicit allowlist; scratch removed; sample unmodified", async () => {
  process.env.RTK_TEST_SECRET = "hunter2-should-not-leak"; process.env.RTK_TEST_ALLOWED = "visible";
  try {
    const before = sha(bins.envdump!);
    const r = res(await runSandboxed({ sample: bins.envdump!, isolation: "process", inheritEnv: ["RTK_TEST_ALLOWED"], env: { EXPLICIT: "1" } }));
    assert.ok(!r.stdout.text.includes("hunter2")); assert.ok(!r.stdout.text.includes("RTK_TEST_SECRET"));
    assert.match(r.stdout.text, /RTK_TEST_ALLOWED=visible/u); assert.match(r.stdout.text, /EXPLICIT=1/u);
    assert.deepEqual(r.env_keys, ["EXPLICIT", "HOME", "LANG", "PATH", "RTK_SANDBOX_TOKEN", "RTK_TEST_ALLOWED", "TMPDIR"]);
    assert.equal(r.cleanup.scratch_removed, true); assert.equal(existsSync(r.cleanup.scratch_path), false); assert.equal(r.cleanup.mounts_leaked, false);
    assert.equal(r.sample.unmodified, true); assert.equal(sha(bins.envdump!), before); assert.equal(r.sample.sha256_before, before);
    assert.equal(r.run_as_uid, caps.isRoot ? 65534 : process.getuid!());
  } finally { delete process.env.RTK_TEST_SECRET; delete process.env.RTK_TEST_ALLOWED; }
});

test("filesystem diff of scratch dir (added files with sha256), exit code captured", async () => {
  const r = res(await runSandboxed({ sample: bins.writer!, isolation: "process", files: { "pre.txt": "preexisting" } }));
  assert.equal(r.status, "exited"); assert.equal(r.exit_code, 3);
  const byPath = Object.fromEntries(r.filesystem.scratch_changes.map((c) => [c.path, c]));
  assert.equal(byPath["<scratch>/out.txt"]!.status, "added");
  assert.equal(byPath["<scratch>/out.txt"]!.sha256, createHash("sha256").update("hello\n").digest("hex"));
  assert.equal(byPath["<scratch>/sub/y.bin"]!.status, "added");
  assert.ok(!("<scratch>/pre.txt" in byPath));
});

test("observed paths diff: added/modified/removed outside scratch (process level)", async () => {
  const obs = mkdtempSync(join(tmpdir(), "rtk-obs-")); chmodSync(obs, 0o777);
  try {
    writeFileSync(join(obs, "keep.txt"), "a");
    writeFileSync(join(dir, "obswriter.sh"), `#!/bin/sh\necho new > ${obs}/new.txt\n`); chmodSync(join(dir, "obswriter.sh"), 0o755);
    const r = res(await runSandboxed({ sample: join(dir, "obswriter.sh"), isolation: "process", observePaths: [obs] }));
    assert.deepEqual(r.filesystem.observed_changes.map((c) => [c.path.replace(obs, "<obs>"), c.status]), [["<obs>/new.txt", "added"]]);
  } finally { rmSync(obs, { recursive: true, force: true }); }
});

test("wall-clock timeout kills a busy loop", async (t) => {
  if (!needGcc(t)) return;
  const r = res(await runSandboxed({ sample: bins.loop!, limits: { wallTimeMs: 600 } }));
  assert.equal(r.status, "timeout"); assert.equal(r.signal, "SIGKILL");
  assert.ok(r.wall_ms >= 550 && r.wall_ms < 5000, `wall ${r.wall_ms}`);
  assert.equal(r.process_tree.verified_no_survivors, true);
  assert.ok(r.cpu_ms_lower_bound > 100, `cpu ${r.cpu_ms_lower_bound}`);
});

test("RLIMIT_CPU stops a loop before the wall timeout", async (t) => {
  if (!needGcc(t)) return;
  const r = res(await runSandboxed({ sample: bins.loop!, limits: { wallTimeMs: 8000, cpuSeconds: 1 } }));
  assert.notEqual(r.status, "timeout"); assert.equal(r.status, "signaled");
  assert.ok(["SIGXCPU", "SIGKILL"].includes(r.signal ?? ""), String(r.signal));
});

test("setsid + double-fork daemon is detected as survivor and killed", async (t) => {
  if (!needGcc(t)) return;
  const name = bins.daemon!.split("/").pop()!;
  const r = res(await runSandboxed({ sample: bins.daemon!, limits: { wallTimeMs: 5000 } }));
  assert.equal(r.status, "exited"); assert.equal(r.exit_code, 0); assert.match(r.stdout.text, /parent-exits/u);
  const all = [...r.process_tree.processes, ...r.process_tree.survivors_at_exit];
  assert.ok(r.process_tree.survivors_at_exit.length >= 1, "daemon must be reported as outliving the sample");
  assert.ok(r.process_tree.killed_pids.length >= 1);
  assert.ok(r.process_tree.processes.some((p) => p.escaped_session), "escaped session recorded");
  assert.equal(r.process_tree.verified_no_survivors, true);
  assert.deepEqual(procsWith(name), [], "no process of the sample survives on the host");
  assert.ok(all.length >= 2);
});

test("fork storm is bounded by RLIMIT_NPROC", async (t) => {
  if (!needGcc(t)) return;
  if (!caps.isRoot) t.diagnostic("not root: NPROC counts the whole uid");
  const r = res(await runSandboxed({ sample: bins.forkstorm!, trace: false, limits: { maxProcesses: 40, wallTimeMs: 15000 } }));
  const n = Number(/forked=(\d+)/u.exec(r.stdout.text)?.[1]);
  assert.ok(n > 5 && n <= 40, `forked ${n}`);
  assert.equal(r.process_tree.verified_no_survivors, true);
  assert.ok(r.process_tree.max_concurrent <= 40 + 8, `max concurrent ${r.process_tree.max_concurrent}`);
  assert.deepEqual(procsWith(bins.forkstorm!.split("/").pop()!), []);
});

test("output flood is capped with truncation flag", async (t) => {
  if (!needGcc(t)) return;
  const r = res(await runSandboxed({ sample: bins.flood!, limits: { maxOutputBytes: 4096, maxTotalOutputBytes: 2 * 1024 * 1024, wallTimeMs: 8000 } }));
  assert.equal(r.stdout.truncated, true); assert.equal(r.stdout.bytes_kept, 4096); assert.equal(r.stdout.text.length, 4096);
  assert.ok(r.stdout.bytes_total > 4096); assert.equal(r.status, "output-limit");
  assert.equal(r.process_tree.verified_no_survivors, true);
});

test("crasher: SIGSEGV is reported with core-signal flag", async (t) => {
  if (!needGcc(t)) return;
  const r = res(await runSandboxed({ sample: bins.crasher!, isolation: "process" }));
  assert.equal(r.status, "signaled"); assert.equal(r.signal, "SIGSEGV"); assert.equal(r.core.signal_implies_core, true);
  assert.ok(Array.isArray(r.core.core_files));
});

test("network: namespace isolation blocks the host localhost server; process level may reach it", async (t) => {
  if (!needGcc(t)) return;
  let conns = 0; let reqs = 0;
  const server: Server = createServer((_q, s) => { reqs++; s.end("hi"); }); server.on("connection", () => { conns++; });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as { port: number }).port;
  try {
    const p = res(await runSandboxed({ sample: bins.connector!, args: [String(port)], isolation: "process" }));
    assert.match(p.stdout.text, /connected/u, "process level can reach host loopback");
    assert.ok(conns >= 1 && reqs >= 1, "server saw the connection");
    if (caps.strace) { const c = p.network.attempts.find((a) => a.syscall === "connect" && a.family === "AF_INET"); assert.ok(c && c.succeeded && c.port === port && c.address === "127.0.0.1", JSON.stringify(p.network.attempts)); assert.equal(p.network.any_connect_succeeded, true); }
    if (!caps.levels["namespace-lite"]) { t.diagnostic("namespaces unavailable: isolated half skipped"); return; }
    const seen = conns;
    const n = res(await runSandboxed({ sample: bins.connector!, args: [String(port)], isolation: "namespace" }));
    assert.match(n.stdout.text, /connect-failed/u); assert.equal(conns, seen, "server must see ZERO connections under namespace isolation");
    assert.ok(n.namespaces.includes("net") && n.namespaces.includes("pid"));
    if (caps.strace) { const c = n.network.attempts.find((a) => a.syscall === "connect" && a.family === "AF_INET"); assert.ok(c && !c.succeeded && /^(ENETUNREACH|ECONNREFUSED|EADDRNOTAVAIL)$/u.test(c.errno ?? ""), JSON.stringify(n.network.attempts)); assert.equal(n.network.any_connect_succeeded, false); }
    assert.equal(n.process_tree.verified_no_survivors, true);
  } finally { server.close(); }
});

test("container level: private pid ns, restricted filesystem view, read-only sample, honest label", async (t) => {
  if (!caps.levels.container) { t.skip("container level unsupported on this host"); return; }
  const ev = await runSandboxed({ sample: bins.view!, isolation: "namespace" });
  const r = res(ev); const lines = r.stdout.text.split("\n");
  assert.equal(r.achieved_level, "container"); assert.equal(ev.environment?.isolation, "container");
  assert.match(lines[0]!, /^pid=\d{1,2}$/u, `PID inside namespace should be tiny: ${lines[0]}`);
  const rootLs = lines.slice(1, lines.indexOf("---"));
  for (const hostOnly of ["home", "root", "opt", "var", "srv", "mnt"]) assert.ok(!rootLs.includes(hostOnly), `host dir /${hostOnly} visible: ${rootLs}`);
  assert.ok(rootLs.includes("work") && rootLs.includes("sample") && rootLs.includes("tmp") && rootLs.includes("usr"));
  assert.match(r.stdout.text, /sample-readonly/u); assert.ok(!/sample-writable/u.test(r.stdout.text));
  assert.match(r.stdout.text, /No such file|cat:/u, "no host /etc/passwd");
  if (caps.isRoot) assert.match(r.stdout.text, /\n65534\n?$/u);
  assert.ok(ev.limitations.some((l) => /pivot_root/u.test(l) && /never virtual-machine/u.test(l)));
  assert.equal(r.cleanup.mounts_leaked, false);
});

test("namespace-lite is labelled process (no filesystem restriction)", async (t) => {
  if (!caps.levels["namespace-lite"] || caps.levels.container) { t.skip("host supports container level (or no namespaces)"); return; }
  const ev = await runSandboxed({ sample: bins.envdump!, isolation: "namespace" });
  assert.equal(ev.environment?.isolation, "process"); assert.ok(ev.limitations.some((l) => /NO restricted filesystem view/u.test(l)));
});

test("strace log parser", () => {
  const p = parseStrace(`12 connect(3, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("127.0.0.1")}, 16) = -1 ENETUNREACH (Network is unreachable)\n12 socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 3\n13 execve("/bin/ls", ["ls", "-l"], 0x7ffd /* 5 vars */) = 0\n`);
  assert.equal(p.net.length, 2); assert.deepEqual([p.net[0]!.port, p.net[0]!.address, p.net[0]!.errno, p.net[0]!.succeeded], [8080, "127.0.0.1", "ENETUNREACH", false]);
  assert.equal(p.net[1]!.succeeded, true); assert.deepEqual(p.execs[0]!.argv, ["ls", "-l"]);
});
