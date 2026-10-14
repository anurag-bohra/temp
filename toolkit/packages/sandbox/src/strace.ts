// Parsing of `strace -f -e trace=network,execve` logs.
export interface NetAttempt { pid: number | null; syscall: string; family: string | null; address: string | null; port: number | null; result: string; errno: string | null; succeeded: boolean }
export interface ExecEvent { pid: number | null; path: string; argv: string[]; succeeded: boolean }
export interface StraceParse { net: NetAttempt[]; execs: ExecEvent[]; lines: number }

const NET_SYSCALLS = new Set(["socket", "connect", "bind", "listen", "accept", "accept4", "sendto", "sendmsg", "sendmmsg", "recvfrom", "socketpair"]);
const LINE = /^(?:(\d+)\s+)?(\w+)\((.*)\)\s+=\s+(-?\d+|\?)(?:\s+(\w+))?/u;
export function parseStrace(text: string): StraceParse {
  const net: NetAttempt[] = []; const execs: ExecEvent[] = []; let lines = 0;
  for (const line of text.split("\n")) {
    const m = LINE.exec(line); if (!m) continue; lines++;
    const pid = m[1] ? Number(m[1]) : null; const sc = m[2]!; const args = m[3]!; const ret = m[4]!; const errno = m[5] && /^[A-Z]+$/u.test(m[5]) ? m[5] : null;
    const ok = ret !== "?" && Number(ret) >= 0;
    if (sc === "execve") {
      const path = /^"((?:[^"\\]|\\.)*)"/u.exec(args)?.[1] ?? "";
      const argvText = /\[((?:"(?:[^"\\]|\\.)*"(?:\.\.\.)?(?:,\s*)?)*)\]/u.exec(args)?.[1] ?? "";
      const argv = [...argvText.matchAll(/"((?:[^"\\]|\\.)*)"/gu)].map((x) => x[1]!);
      execs.push({ pid, path, argv, succeeded: ok });
    } else if (NET_SYSCALLS.has(sc)) {
      const family = /sa_family=(AF_\w+)/u.exec(args)?.[1] ?? (sc === "socket" || sc === "socketpair" ? /(AF_\w+)/u.exec(args)?.[1] ?? null : null);
      const port = /sin6?_port=htons\((\d+)\)/u.exec(args)?.[1];
      const address = /inet_addr\("([^"]+)"\)/u.exec(args)?.[1] ?? /inet_pton\(AF_INET6, "([^"]+)"/u.exec(args)?.[1] ?? /sun_path="((?:[^"\\]|\\.)*)"/u.exec(args)?.[1] ?? null;
      net.push({ pid, syscall: sc, family, address, port: port ? Number(port) : null, result: ret, errno, succeeded: ok });
    }
  }
  return { net, execs, lines };
}
