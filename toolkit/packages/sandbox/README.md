# @rtk/sandbox

Owned, resource-bounded, optionally namespace-isolated execution of **one sample** for controlled detonation. It is the only package in the toolkit allowed to execute a sample, and it is the "real sandbox" that REA says it does not provide. The result is an `Evidence` record (`provider rtk-sandbox`, `operation run_sandboxed`, `authority controlled-replay`, `confidence observed`).

```ts
import { runSandboxed, probeCapabilities } from "@rtk/sandbox";
const ev = await runSandboxed({ sample: "/path/to/demo", args: [], isolation: "auto" /* | "process" | "namespace" */, limits: { wallTimeMs: 10_000 } });
ev.environment   // { id, platform, architecture, isolation: "process" | "container" }
ev.normalized_result  // see "Captured"
```
CLI: `node bin/rtk-sandbox.ts spec.json` (or JSON on stdin) prints Evidence; `--probe` prints which levels this host supports.

## Isolation levels (achieved level is probed by actually running a trivial program through each)
| level | what it is | `environment.isolation` |
|---|---|---|
| `process` | own session/process group, `prlimit` rlimits (NPROC, AS, CPU, FSIZE, CORE, NOFILE), env allowlist, copy of the sample in a read-only dir, fresh scratch cwd, output caps, wall timeout, tree kill + /proc survivor sweep, uid 65534 (via `setpriv`) when run as root. **No** network or filesystem isolation. | `process` |
| `namespace-lite` | `process` + `unshare --net --pid --fork --kill-child --mount-proc --ipc --uts` (`--user --map-root-user` when not root). No network at all (the loopback interface is down), private PID namespace and /proc. The sample can still read the host filesystem. | `process` (not enough for the container label) |
| `container` | `namespace-lite` + private mount namespace and `pivot_root` into a minimal tmpfs root: read-only `/usr /bin /lib* /sbin`, read-only sample copy at `/sample`, private tmpfs `/tmp`, rw scratch at `/work`, minimal `/dev`, no host `/etc`/home; capabilities and bounding set dropped, `no_new_privs`, uid 65534. | `container` |

`isolation: "auto"` (default) uses the best level; `"namespace"` requires at least `namespace-lite` and throws `IsolationUnavailableError` otherwise; `"process"` forces the weakest. Nothing is ever labelled `virtual-machine`: the sample shares the host kernel, there is no seccomp filter and no cgroup limit (memory is per-process RLIMIT_AS, process count RLIMIT_NPROC per uid, which only bites when the sandbox uid is not root, hence the uid drop). The Evidence `limitations` array states the achieved level and the namespaces used.

## Captured (`normalized_result`)
stdout/stderr (bounded, `truncated`, `bytes_total`, sha256; the run is killed at `maxTotalOutputBytes`, status `output-limit`), exit code / signal / status (`exited|signaled|timeout|output-limit`), wall time, CPU time and peak RSS/HWM (sampled from /proc every ~20 ms: lower bounds), process-tree records (pid, ppid, sid, exe, cmdline, first/last seen, how it was attributed) and samples over time, `execve` events from strace (covers short-lived children), survivors at sample exit and killed pids, `verified_no_survivors`, filesystem diff of the scratch dir and of `observePaths` (`path, status added|removed|modified, sha256`), network syscalls (`strace -f -e trace=network,execve`: socket/connect/bind/... with address, port, errno), core detection (signal implies core, `core_pattern`, core files found in scratch), sample sha256 before/after (+ the copy that actually ran), cleanup verification (scratch removed, no leaked mounts in `/proc/self/mountinfo`).

Survivor detection finds escapees (setsid, double fork, reparented to init) by session, process group, ppid chain, a random `RTK_SANDBOX_TOKEN` in the environment, cwd and exe path; under strace the sample's own exit is read from the strace log, because strace outlives the sample while any traced descendant lives.

## Verified (test/sandbox.test.ts, 14 pass / 1 skip in this container: root, strace 6.8, util-linux 2.39; all levels available)
benign C demos compiled at test time: infinite loop (wall timeout kills; RLIMIT_CPU kills before the wall timeout), setsid + double-fork daemon (reported as survivor, killed, no process left on the host), fork storm (bounded by RLIMIT_NPROC, no survivors), output flood (capped at 4096 bytes, truncation flag, killed), SIGSEGV crasher (signal + core flag), connector to a node HTTP server on host 127.0.0.1: `process` level reaches it (server counts the connection, strace shows connect succeeded), `namespace` level: **server sees zero connections**, connect fails (strace errno). Also: env not inherited except allowlist, scratch removed and no mounts leaked, sample sha256 unchanged, scratch and observed-path diffs, container view (tiny PID, no `/home /root /opt /var`, read-only `/sample`, no host `/etc/passwd`, uid 65534), Evidence envelope fields, strace parser. The skipped test is `namespace-lite labelled process` (skipped when the host supports `container`). Tests skip cleanly when gcc is missing or a level is unsupported.

## NOT implemented / not verified
- Not a VM: no seccomp, no cgroups, shared kernel; kernel exploits, side channels and ptrace-aware samples are out of scope. A sample can detect strace.
- The non-root `--user --map-root-user` path is implemented but **not tested** here (the container runs as root); under a user namespace the uid drop is skipped.
- Loopback is left down inside the net namespace (no `ip` tool), so a sample cannot even talk to itself over 127.0.0.1.
- Without strace, network attempts and short-lived processes are not observed (stated in `limitations`); in untraced namespace runs a signal death shows as exit code 128+N.
- CPU/RSS are polled lower bounds; process tree samples can miss processes living < 20 ms.
- Core files are only detected when `core_pattern` is a plain relative name; the sample is non-dumpable after the uid drop, so none appeared in tests.
- Stdin is closed (`/dev/null`); no TTY/PTY, no interactive samples. Windows/macOS hosts unsupported.
- Samples must be directly executable (ELF or `#!` script with an interpreter present in the sandbox view).

## UnknownRegistry: closing an Unknown with sandbox evidence
No helper code is shipped; `@rtk/unknowns` already exposes the rule: `evidenceQualifies(unknown, evidence)` (authority equal, confidence >=, environment id/platform/architecture/isolation >=). Using it as `closesUnknown(evidence, unknown) = evidenceQualifies(unknown, evidence).ok`:
```ts
import { evidenceQualifies } from "@rtk/unknowns";
const closesUnknown = (evidence, unknown) => evidenceQualifies(unknown, evidence).ok;
```
A capture from this package has `authority: controlled-replay`, `confidence: observed` and `environment.isolation` of `process` or `container` (ranked none < process < container < virtual-machine). An Unknown that requires `isolation: "virtual-machine"` is therefore **not** closed by any namespace-level capture: verified by running `runSandboxed({isolation:"namespace"})` and `evidenceQualifies` on this host: against `container` -> `ok: true`; against `virtual-machine` -> `ok: false`, problem `isolation container < required virtual-machine`. Closing it needs evidence from a real VM run (a different provider that can truthfully report `virtual-machine`).
