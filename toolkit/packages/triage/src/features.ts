// Built-in, dependency-free structural parsers (no engine required): ELF and PE.
// Purpose: fast, safe triage features (imports, sections, entropy, hardening indicators). They read bytes only.
import { closeSync, openSync, readSync, statSync } from "node:fs";
import { createHash } from "node:crypto";
import { shannonEntropy } from "./identify.ts";

const readAt = (fd: number, off: number, len: number): Buffer => { const b = Buffer.alloc(len); const n = readSync(fd, b, 0, len, off); return n === len ? b : b.subarray(0, n); };
const cstr = (b: Buffer, off: number, max = 512): string => { let e = off; while (e < b.length && b[e] !== 0 && e - off < max) e++; return b.toString("latin1", off, e); };

export interface SectionInfo { name: string; offset: number; size: number; flags: number; entropy: number; executable: boolean; writable: boolean }
export interface ElfFeatures {
  kind: "elf"; class: 32 | 64; endian: "little" | "big"; type: "exec" | "dyn" | "rel" | "core" | "other"; machine: number; entry: string; interpreter: string | null;
  needed: string[]; undefinedSymbols: string[]; definedFunctionCount: number; sections: SectionInfo[];
  hardening: { pie: boolean; relro: "none" | "partial" | "full"; executableStack: boolean | null; bindNow: boolean; stackCanary: boolean | null; nx: boolean | null };
  stripped: boolean; limitations: string[];
}
const ET = ["other", "rel", "exec", "dyn", "core"] as const;

export function parseElf(path: string): ElfFeatures {
  const fd = openSync(path, "r"); const limitations: string[] = [];
  try {
    const size = statSync(path).size; const eh = readAt(fd, 0, 64);
    if (eh.length < 52 || eh.readUInt32BE(0) !== 0x7f454c46) throw new Error("not an ELF file");
    const is64 = eh[4] === 2, le = eh[5] === 1; if (!le) limitations.push("big-endian ELF: header fields not decoded");
    if (!le) return { kind: "elf", class: is64 ? 64 : 32, endian: "big", type: "other", machine: 0, entry: "0x0", interpreter: null, needed: [], undefinedSymbols: [], definedFunctionCount: 0, sections: [], hardening: { pie: false, relro: "none", executableStack: null, bindNow: false, stackCanary: null, nx: null }, stripped: false, limitations };
    const u16 = (b: Buffer, o: number) => b.readUInt16LE(o), u32 = (b: Buffer, o: number) => b.readUInt32LE(o), u64 = (b: Buffer, o: number) => Number(b.readBigUInt64LE(o));
    const type = u16(eh, 16), machine = u16(eh, 18); const entry = is64 ? u64(eh, 24) : u32(eh, 24);
    const phoff = is64 ? u64(eh, 32) : u32(eh, 28), shoff = is64 ? u64(eh, 40) : u32(eh, 32);
    const phentsize = u16(eh, is64 ? 54 : 42), phnum = u16(eh, is64 ? 56 : 44), shentsize = u16(eh, is64 ? 58 : 46), shnum = u16(eh, is64 ? 60 : 48), shstrndx = u16(eh, is64 ? 62 : 50);
    let interpreter: string | null = null; let gnuStackFlags: number | null = null; let relro = false;
    for (let i = 0; i < Math.min(phnum, 256); i++) {
      const ph = readAt(fd, phoff + i * phentsize, phentsize); const pt = u32(ph, 0); const flags = u32(ph, is64 ? 4 : 24); const poff = is64 ? u64(ph, 8) : u32(ph, 4), pfsz = is64 ? u64(ph, 32) : u32(ph, 16);
      if (pt === 3 && pfsz < 4096) interpreter = cstr(readAt(fd, poff, pfsz), 0); if (pt === 0x6474e551) gnuStackFlags = flags; if (pt === 0x6474e552) relro = true;
    }
    const sh: { name: number; type: number; flags: number; off: number; size: number; link: number }[] = [];
    for (let i = 0; i < Math.min(shnum, 512); i++) { const s = readAt(fd, shoff + i * shentsize, shentsize); if (s.length < shentsize) break; sh.push({ name: u32(s, 0), type: u32(s, 4), flags: is64 ? u64(s, 8) : u32(s, 8), off: is64 ? u64(s, 24) : u32(s, 16), size: is64 ? u64(s, 32) : u32(s, 20), link: u32(s, is64 ? 40 : 24) }); }
    const strtab = sh[shstrndx]; const names = strtab && strtab.size < (4 << 20) ? readAt(fd, strtab.off, strtab.size) : Buffer.alloc(0);
    const sections: SectionInfo[] = sh.map((s) => { const data = s.type === 8 || s.size === 0 || s.size > 64 << 20 ? Buffer.alloc(0) : readAt(fd, s.off, Math.min(s.size, 8 << 20)); return { name: cstr(names, s.name), offset: s.off, size: s.size, flags: s.flags, entropy: shannonEntropy(data), executable: (s.flags & 4) !== 0, writable: (s.flags & 1) !== 0 }; });
    const needed: string[] = []; const undefinedSymbols: string[] = []; let definedFunctions = 0; let bindNow = false; let hasSymtab = false;
    const readSymbols = (symIdx: number, undefOnly: boolean): void => {
      const s = sh[symIdx]; if (!s || s.size > 32 << 20) return; const strs = sh[s.link]; if (!strs || strs.size > 32 << 20) return;
      const symData = readAt(fd, s.off, s.size), strData = readAt(fd, strs.off, strs.size); const ent = is64 ? 24 : 16;
      for (let o = ent; o + ent <= symData.length; o += ent) {
        const nameOff = u32(symData, o), info = symData[o + (is64 ? 4 : 12)]!, shndx = u16(symData, o + (is64 ? 6 : 14)); const nm = cstr(strData, nameOff);
        if (shndx === 0 && nm) { if (!undefinedSymbols.includes(nm)) undefinedSymbols.push(nm); } else if (!undefOnly && (info & 0xf) === 2 && shndx !== 0) definedFunctions++;
      }
    };
    sh.forEach((s, i) => {
      if (s.type === 11) readSymbols(i, true); // .dynsym
      if (s.type === 2) { hasSymtab = true; readSymbols(i, false); }
      if (s.type === 6 && s.size < (1 << 20)) { // .dynamic
        const d = readAt(fd, s.off, s.size); const strs = sh[s.link]; const sd = strs ? readAt(fd, strs.off, strs.size) : Buffer.alloc(0); const ent = is64 ? 16 : 8;
        for (let o = 0; o + ent <= d.length; o += ent) { const tag = is64 ? u64(d, o) : u32(d, o), val = is64 ? u64(d, o + 8) : u32(d, o + 4); if (tag === 1) needed.push(cstr(sd, val)); if (tag === 24) bindNow = true; if (tag === 30 && (val & 8)) bindNow = true; if (tag === 0x6ffffffb && (val & 1)) bindNow = true; if (tag === 0) break; }
      }
    });
    const canary = undefinedSymbols.includes("__stack_chk_fail") || undefinedSymbols.includes("__stack_chk_guard") ? true : (hasSymtab || undefinedSymbols.length ? false : null);
    return { kind: "elf", class: is64 ? 64 : 32, endian: "little", type: ET[type] ?? "other", machine, entry: "0x" + entry.toString(16), interpreter, needed, undefinedSymbols, definedFunctionCount: definedFunctions, sections,
      hardening: { pie: ET[type] === "dyn" && interpreter !== null, relro: relro ? (bindNow ? "full" : "partial") : "none", executableStack: gnuStackFlags === null ? null : (gnuStackFlags & 1) !== 0, bindNow, stackCanary: canary, nx: gnuStackFlags === null ? null : (gnuStackFlags & 1) === 0 },
      stripped: !hasSymtab, limitations: [...limitations, "Hardening values are static indicators from program headers/symbols; the stack canary indicator is inferred from an undefined __stack_chk_* symbol.", `file size ${size} bytes; sections beyond 512 and symbol tables beyond 32 MiB are ignored`] };
  } finally { closeSync(fd); }
}

export interface PeImport { dll: string; functions: string[] }
export interface PeFeatures {
  kind: "pe"; pe32plus: boolean; machine: number; timestamp: number; subsystem: number; entryRva: string; isDotNet: boolean; isDll: boolean;
  sections: SectionInfo[]; imports: PeImport[]; importCount: number; imphash: string | null; hasResources: boolean; overlayBytes: number; limitations: string[];
}
export function parsePe(path: string): PeFeatures {
  const fd = openSync(path, "r"); const limitations: string[] = [];
  try {
    const fsize = statSync(path).size; const dos = readAt(fd, 0, 64); if (dos.length < 64 || dos.readUInt16LE(0) !== 0x5a4d) throw new Error("not a PE file (no MZ)");
    const lfanew = dos.readUInt32LE(0x3c); const hdr = readAt(fd, lfanew, 24 + 240); if (hdr.length < 24 || hdr.readUInt32LE(0) !== 0x4550) throw new Error("PE signature missing");
    const machine = hdr.readUInt16LE(4), nsec = hdr.readUInt16LE(6), timestamp = hdr.readUInt32LE(8), optSize = hdr.readUInt16LE(20), chars = hdr.readUInt16LE(22);
    const opt = hdr.subarray(24); const magic = opt.readUInt16LE(0); const pe32plus = magic === 0x20b; if (magic !== 0x10b && magic !== 0x20b) throw new Error("unknown optional header magic");
    const entryRva = opt.readUInt32LE(16), subsystem = opt.readUInt16LE(68); const ddBase = pe32plus ? 112 : 96; const nDirs = opt.readUInt32LE(ddBase - 4);
    const dd = (i: number) => (i < nDirs && ddBase + i * 8 + 8 <= opt.length ? { rva: opt.readUInt32LE(ddBase + i * 8), size: opt.readUInt32LE(ddBase + i * 8 + 4) } : { rva: 0, size: 0 });
    const secTable = readAt(fd, lfanew + 24 + optSize, nsec * 40); const secs: { name: string; vsize: number; vaddr: number; rawsize: number; rawptr: number; ch: number }[] = [];
    for (let i = 0; i < Math.min(nsec, 96); i++) { const o = i * 40; if (o + 40 > secTable.length) break; secs.push({ name: cstr(secTable, o, 8), vsize: secTable.readUInt32LE(o + 8), vaddr: secTable.readUInt32LE(o + 12), rawsize: secTable.readUInt32LE(o + 16), rawptr: secTable.readUInt32LE(o + 20), ch: secTable.readUInt32LE(o + 36) }); }
    const rva2off = (rva: number): number | null => { for (const s of secs) if (rva >= s.vaddr && rva < s.vaddr + Math.max(s.vsize, s.rawsize)) return s.rawptr + (rva - s.vaddr); return null; };
    const sections: SectionInfo[] = secs.map((s) => ({ name: s.name, offset: s.rawptr, size: s.rawsize, flags: s.ch, entropy: s.rawsize && s.rawsize < 64 << 20 ? shannonEntropy(readAt(fd, s.rawptr, Math.min(s.rawsize, 8 << 20))) : 0, executable: (s.ch & 0x20000000) !== 0, writable: (s.ch & 0x80000000) !== 0 }));
    const imports: PeImport[] = []; let importCount = 0; const imp = dd(1);
    const impOff = imp.rva ? rva2off(imp.rva) : null;
    if (impOff !== null) {
      for (let i = 0; i < 512; i++) {
        const d = readAt(fd, impOff + i * 20, 20); if (d.length < 20 || d.readUInt32LE(12) === 0) break;
        const nameOff = rva2off(d.readUInt32LE(12)); const dll = nameOff === null ? "?" : cstr(readAt(fd, nameOff, 256), 0); const thunkRva = d.readUInt32LE(0) || d.readUInt32LE(16); const tOff = rva2off(thunkRva); const fns: string[] = [];
        if (tOff !== null) for (let j = 0; j < 4096; j++) {
          const esz = pe32plus ? 8 : 4; const e = readAt(fd, tOff + j * esz, esz); if (e.length < esz) break; const val = pe32plus ? e.readBigUInt64LE(0) : BigInt(e.readUInt32LE(0)); if (val === 0n) break;
          const ordFlag = pe32plus ? (val >> 63n) & 1n : (val >> 31n) & 1n;
          if (ordFlag) fns.push(`ord${Number(val & 0xffffn)}`); else { const hn = rva2off(Number(val & 0x7fffffffn)); if (hn !== null) fns.push(cstr(readAt(fd, hn + 2, 256), 0)); }
        }
        importCount += fns.length; imports.push({ dll, functions: fns });
      }
    } else if (imp.rva) limitations.push("import directory RVA does not map into a section");
    const imphashInput: string[] = []; for (const m of imports) { const dllBase = m.dll.toLowerCase().replace(/\.(dll|ocx|sys)$/u, ""); for (const f of m.functions) imphashInput.push(`${dllBase}.${f.startsWith("ord") ? f : f.toLowerCase()}`); }
    const imphash = imphashInput.length ? createHash("md5").update(imphashInput.join(",")).digest("hex") : null;
    const lastEnd = secs.reduce((m, s) => Math.max(m, s.rawptr + s.rawsize), 0);
    return { kind: "pe", pe32plus, machine, timestamp, subsystem, entryRva: "0x" + entryRva.toString(16), isDotNet: dd(14).rva !== 0, isDll: (chars & 0x2000) !== 0, sections, imports, importCount, imphash, hasResources: dd(2).rva !== 0, overlayBytes: Math.max(0, fsize - lastEnd),
      limitations: [...limitations, "Imports are read from the static import directory only; delay-load, bound and runtime-resolved imports are not listed.", "imphash follows the common pefile convention (lower-cased dll base + function, md5); ordinals for non-exported names are not resolved."] };
  } finally { closeSync(fd); }
}
