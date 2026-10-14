export interface Indicator { id: string; category: string; description: string; method: string; target: string; opcode?: string }

interface Rule { id: string; category: string; description: string; re: RegExp }
const R = (id: string, category: string, description: string, re: RegExp): Rule => ({ id, category, description, re });

/** Rules over `Type::Name` call targets. These are triage hints, not verdicts: legitimate code calls all of these. */
export const CALL_RULES: Rule[] = [
  R("process-start", "execution", "starts a process", /^System\.Diagnostics\.Process::Start\b/u),
  R("assembly-load", "dynamic-code", "loads an assembly at runtime", /^System\.Reflection\.Assembly::(Load|LoadFrom|LoadFile|LoadWithPartialName|UnsafeLoadFrom)\b/u),
  R("assembly-context-load", "dynamic-code", "loads an assembly via AssemblyLoadContext", /^System\.Runtime\.Loader\.AssemblyLoadContext::(LoadFromStream|LoadFromAssemblyPath|LoadFromNativeImagePath)\b/u),
  R("activator", "dynamic-code", "reflective instantiation", /^System\.Activator::CreateInstance\b/u),
  R("method-invoke", "dynamic-code", "reflective invocation", /^System\.Reflection\.(MethodBase|MethodInfo)::Invoke\b/u),
  R("http-client", "network", "HTTP client use", /^System\.Net\.Http\.HttpClient::/u),
  R("web-client", "network", "WebClient use", /^System\.Net\.WebClient::/u),
  R("web-request", "network", "WebRequest use", /^System\.Net\.(Http)?WebRequest::/u),
  R("socket", "network", "raw socket / TCP use", /^System\.Net\.Sockets\.(Socket|TcpClient|UdpClient)::/u),
  R("base64-decode", "obfuscation", "Base64 decoding", /^System\.Convert::FromBase64(String|CharArray)\b/u),
  R("delegate-from-fnptr", "native-exec", "native function pointer to delegate", /^System\.Runtime\.InteropServices\.Marshal::GetDelegateForFunctionPointer\b/u),
  R("marshal-alloc", "native-exec", "unmanaged memory allocation / copy", /^System\.Runtime\.InteropServices\.Marshal::(AllocHGlobal|AllocCoTaskMem|Copy|WriteIntPtr)\b/u),
  R("dyn-code-emit", "dynamic-code", "runtime IL emission", /^System\.Reflection\.Emit\.(ILGenerator|DynamicMethod|AssemblyBuilder|MethodBuilder)::/u),
  R("registry", "persistence-surface", "registry access", /^Microsoft\.Win32\.(Registry|RegistryKey)::/u),
  R("file-delete", "filesystem", "file deletion", /^System\.IO\.File::Delete\b/u),
  R("crypto-aes", "crypto", "symmetric crypto", /^System\.Security\.Cryptography\.(Aes|Rijndael|TripleDES|DES|RC2)[A-Za-z]*::/u),
  R("gzip", "obfuscation", "decompression", /^System\.IO\.Compression\.(GZipStream|DeflateStream)::/u),
];

export const PINVOKE_RULES: { id: string; category: string; description: string; re: RegExp }[] = [
  R("pinvoke-virtualalloc", "native-exec", "P/Invoke VirtualAlloc (memory allocation)", /^VirtualAlloc(Ex)?$/u),
  R("pinvoke-virtualprotect", "native-exec", "P/Invoke VirtualProtect", /^VirtualProtect(Ex)?$/u),
  R("pinvoke-createremotethread", "injection", "P/Invoke CreateRemoteThread", /^(CreateRemoteThread(Ex)?|NtCreateThreadEx|QueueUserAPC|RtlCreateUserThread)$/u),
  R("pinvoke-writeprocessmemory", "injection", "P/Invoke WriteProcessMemory", /^(WriteProcessMemory|NtWriteVirtualMemory)$/u),
  R("pinvoke-openprocess", "injection", "P/Invoke OpenProcess", /^OpenProcess$/u),
  R("pinvoke-loadlibrary", "dynamic-code", "P/Invoke LoadLibrary/GetProcAddress", /^(LoadLibrary[AW]?|GetProcAddress)$/u),
  R("pinvoke-setwindowshook", "hooking", "P/Invoke SetWindowsHookEx / GetAsyncKeyState", /^(SetWindowsHookEx[AW]?|GetAsyncKeyState)$/u),
];

export function deriveIndicators(
  edges: { caller: string; opcode: string; target: string }[],
  pinvokes: { entry_point: string; dll: string | null; declaring_method: string }[],
): Indicator[] {
  const out: Indicator[] = []; const seen = new Set<string>();
  const add = (i: Indicator) => { const k = `${i.id}|${i.method}|${i.target}`; if (!seen.has(k)) { seen.add(k); out.push(i); } };
  for (const e of edges) {
    const tn = e.target.replace(/\(.*$/su, "");
    for (const r of CALL_RULES) if (r.re.test(tn)) add({ id: r.id, category: r.category, description: r.description, method: e.caller, target: e.target, opcode: e.opcode });
  }
  for (const p of pinvokes) {
    for (const r of PINVOKE_RULES) if (r.re.test(p.entry_point)) add({ id: r.id, category: r.category, description: `${r.description} [${p.dll ?? "?"}]`, method: p.declaring_method, target: `${p.dll ?? "?"}!${p.entry_point}` });
  }
  return out;
}
