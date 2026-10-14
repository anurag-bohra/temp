// RtkExport.java - read-only JSON snapshot exporter for rtk ghidra-bridge.
// Run: analyzeHeadless <proj> <name> -import <copy> -postScript RtkExport.java <out.json> [key=value,...] -deleteProject
// Options (second arg, comma separated): decompTimeout=<sec per function>, decompBudget=<sec total>,
//   maxFunctions=<n decompiled>, maxSymbols=<n>, maxStrings=<n>
// It never modifies the program (no transactions are opened) and writes only the output JSON file.
//@category RTK

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;

public class RtkExport extends GhidraScript {
    private final StringBuilder sb = new StringBuilder(1 << 20);

    private static String addr(Address a) {
        if (a == null) return null;
        if (a.isExternalAddress() || !a.isMemoryAddress()) return a.toString();
        return "0x" + Long.toHexString(a.getOffset());
    }

    private void str(String s) {
        if (s == null) { sb.append("null"); return; }
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20 || c == 0x7f || (c >= 0xd800 && c <= 0xdfff && !validPair(s, i))) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
            }
        }
        sb.append('"');
    }
    private static boolean validPair(String s, int i) {
        char c = s.charAt(i);
        if (Character.isHighSurrogate(c)) return i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1));
        return i > 0 && Character.isHighSurrogate(s.charAt(i - 1));
    }
    private void sbStr(StringBuilder target, String v) {
        int mark = sb.length(); str(v); target.append(sb, mark, sb.length()); sb.setLength(mark);
    }
    private void key(String k) { str(k); sb.append(':'); }
    private void kv(String k, String v) { key(k); str(v); }
    private void kv(String k, long v) { key(k); sb.append(v); }
    private void kv(String k, boolean v) { key(k); sb.append(v); }
    private void kvAddr(String k, Address a) { key(k); String s = addr(a); if (s == null) sb.append("null"); else str(s); }

    private static long opt(Map<String, String> o, String k, long d) {
        try { return o.containsKey(k) ? Long.parseLong(o.get(k)) : d; } catch (NumberFormatException e) { return d; }
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) throw new IllegalArgumentException("usage: RtkExport.java <out.json> [opts]");
        File out = new File(args[0]);
        Map<String, String> o = new HashMap<>();
        if (args.length > 1 && !args[1].isEmpty()) for (String kvp : args[1].split(",")) { String[] p = kvp.split("=", 2); if (p.length == 2) o.put(p[0], p[1]); }
        long perFn = opt(o, "decompTimeout", 30);
        long budgetMs = opt(o, "decompBudget", 600) * 1000L;
        long maxFns = opt(o, "maxFunctions", 5000);
        long maxSyms = opt(o, "maxSymbols", 50000);
        long maxStrs = opt(o, "maxStrings", 50000);

        Program p = currentProgram;
        Listing listing = p.getListing();
        FunctionManager fm = p.getFunctionManager();
        ReferenceManager rm = p.getReferenceManager();
        SymbolTable st = p.getSymbolTable();
        List<String> warnings = new ArrayList<>();

        sb.append('{');
        kv("schema", "rtk-ghidra-snapshot/1"); sb.append(',');
        key("ghidra_version"); str(ghidra.framework.Application.getApplicationVersion()); sb.append(',');

        // program
        key("program"); sb.append('{');
        kv("name", p.getName()); sb.append(',');
        kv("format", p.getExecutableFormat()); sb.append(',');
        kv("language_id", p.getLanguageID().getIdAsString()); sb.append(',');
        kv("processor", p.getLanguage().getProcessor().toString()); sb.append(',');
        kv("endian", p.getLanguage().isBigEndian() ? "big" : "little"); sb.append(',');
        kv("pointer_size", p.getDefaultPointerSize()); sb.append(',');
        kv("compiler_spec", p.getCompilerSpec().getCompilerSpecID().getIdAsString()); sb.append(',');
        kvAddr("image_base", p.getImageBase()); sb.append(',');
        kv("executable_sha256", p.getExecutableSHA256()); sb.append(',');
        key("entry_points"); sb.append('[');
        boolean first = true;
        AddressIterator epi = st.getExternalEntryPointIterator();
        while (epi.hasNext()) {
            Address a = epi.next();
            if (!first) sb.append(','); first = false;
            sb.append('{'); kvAddr("address", a); sb.append(','); Symbol s = st.getPrimarySymbol(a); kv("name", s == null ? null : s.getName()); sb.append('}');
        }
        sb.append("]}"); sb.append(',');

        // memory blocks
        key("memory_blocks"); sb.append('[');
        first = true;
        for (MemoryBlock b : p.getMemory().getBlocks()) {
            if (!first) sb.append(','); first = false;
            sb.append('{'); kv("name", b.getName()); sb.append(',');
            kvAddr("start", b.getStart()); sb.append(','); kvAddr("end", b.getEnd()); sb.append(',');
            kv("size", b.getSize()); sb.append(',');
            kv("read", b.isRead()); sb.append(','); kv("write", b.isWrite()); sb.append(','); kv("execute", b.isExecute()); sb.append(',');
            kv("initialized", b.isInitialized()); sb.append(','); kv("overlay", b.isOverlay()); sb.append(','); kv("volatile", b.isVolatile());
            sb.append('}');
        }
        sb.append("],");

        // functions
        List<Function> fns = new ArrayList<>();
        FunctionIterator fi = fm.getFunctions(true);
        while (fi.hasNext()) fns.add(fi.next());
        key("functions"); sb.append('[');
        first = true;
        for (Function f : fns) {
            if (!first) sb.append(','); first = false;
            sb.append('{');
            kvAddr("entry", f.getEntryPoint()); sb.append(',');
            kv("name", f.getName()); sb.append(',');
            kv("external", f.isExternal()); sb.append(',');
            kv("thunk", f.isThunk()); sb.append(',');
            Function tt = f.isThunk() ? f.getThunkedFunction(true) : null;
            kvAddr("thunk_target", tt == null ? null : tt.getEntryPoint()); sb.append(',');
            kv("signature", f.getPrototypeString(true, false)); sb.append(',');
            kv("calling_convention", f.getCallingConventionName()); sb.append(',');
            kv("namespace", f.getParentNamespace().getName(true)); sb.append(',');
            key("body"); sb.append('[');
            if (!f.isExternal()) {
                boolean fr = true;
                for (AddressRange r : f.getBody().getAddressRanges()) {
                    if (!fr) sb.append(','); fr = false;
                    sb.append('{'); kvAddr("start", r.getMinAddress()); sb.append(','); kvAddr("end", r.getMaxAddress()); sb.append('}');
                }
            }
            sb.append("],");
            key("callers"); sb.append('[');
            boolean fc = true;
            TreeMap<String, String> callers = new TreeMap<>();
            for (Function c : f.getCallingFunctions(monitor)) callers.put(addr(c.getEntryPoint()), c.getName());
            for (Map.Entry<String, String> e : callers.entrySet()) { if (!fc) sb.append(','); fc = false; sb.append('{'); kv("entry", e.getKey()); sb.append(','); kv("name", e.getValue()); sb.append('}'); }
            sb.append("],");
            key("callees"); sb.append('[');
            fc = true;
            TreeMap<String, String> callees = new TreeMap<>();
            for (Function c : f.getCalledFunctions(monitor)) callees.put(addr(c.getEntryPoint()), c.getName());
            for (Map.Entry<String, String> e : callees.entrySet()) { if (!fc) sb.append(','); fc = false; sb.append('{'); kv("entry", e.getKey()); sb.append(','); kv("name", e.getValue()); sb.append('}'); }
            sb.append("],");
            // call sites, flagging computed (indirect) calls so callers can reason about call-graph completeness
            key("call_sites"); sb.append('[');
            fc = true;
            boolean indirect = false;
            if (!f.isExternal()) {
                InstructionIterator ii = listing.getInstructions(f.getBody(), true);
                while (ii.hasNext()) {
                    Instruction ins = ii.next();
                    FlowType ft = ins.getFlowType();
                    if (!ft.isCall()) continue;
                    Address tgt = null;
                    for (Reference r : ins.getReferencesFrom()) if (r.getReferenceType().isCall()) { tgt = r.getToAddress(); break; }
                    boolean comp = ft.isComputed() && tgt == null;
                    if (comp) indirect = true;
                    if (!fc) sb.append(','); fc = false;
                    sb.append('{'); kvAddr("site", ins.getAddress()); sb.append(','); kvAddr("target", tgt); sb.append(','); kv("indirect", ft.isComputed()); sb.append(','); kv("unresolved", comp); sb.append('}');
                }
            }
            sb.append("],");
            kv("has_unresolved_indirect_calls", indirect); sb.append(',');
            key("locals"); sb.append('[');
            fc = true;
            if (!f.isExternal()) {
                for (Variable v : f.getAllVariables()) {
                    if (!fc) sb.append(','); fc = false;
                    sb.append('{'); kv("name", v.getName()); sb.append(','); kv("type", v.getDataType().getName()); sb.append(',');
                    kv("length", v.getLength()); sb.append(',');
                    kv("storage", v.getVariableStorage().toString()); sb.append(',');
                    kv("parameter", v instanceof Parameter); sb.append(',');
                    kv("stack_offset", v.hasStackStorage() ? v.getStackOffset() : 0); sb.append(',');
                    kv("stack", v.hasStackStorage());
                    sb.append('}');
                }
            }
            sb.append("]}");
        }
        sb.append("],");

        // defined strings with xrefs
        key("strings"); sb.append('[');
        first = true; long ns = 0; boolean strTrunc = false;
        DataIterator di = listing.getDefinedData(true);
        while (di.hasNext()) {
            Data d = di.next();
            StringDataInstance sdi = StringDataInstance.getStringDataInstance(d);
            if (sdi == null || sdi == StringDataInstance.NULL_INSTANCE) continue;
            String v = sdi.getStringValue();
            if (v == null) continue;
            if (ns >= maxStrs) { strTrunc = true; break; }
            ns++;
            if (!first) sb.append(','); first = false;
            sb.append('{'); kvAddr("address", d.getAddress()); sb.append(','); kv("value", v); sb.append(',');
            kv("encoding", sdi.getCharsetName()); sb.append(','); kv("data_type", d.getDataType().getName()); sb.append(','); kv("length", d.getLength()); sb.append(',');
            key("xrefs"); sb.append('[');
            boolean fx = true;
            for (Reference r : rm.getReferencesTo(d.getAddress())) {
                if (!fx) sb.append(','); fx = false;
                Function cf = fm.getFunctionContaining(r.getFromAddress());
                sb.append('{'); kvAddr("from", r.getFromAddress()); sb.append(','); kv("type", r.getReferenceType().getName()); sb.append(',');
                kv("function", cf == null ? null : cf.getName()); sb.append(','); kvAddr("function_entry", cf == null ? null : cf.getEntryPoint()); sb.append('}');
            }
            sb.append("]}");
        }
        sb.append("],"); kv("strings_truncated", strTrunc); sb.append(',');

        // imports / externals
        key("externals"); sb.append('[');
        first = true;
        ExternalManager em = p.getExternalManager();
        for (String lib : em.getExternalLibraryNames()) {
            ExternalLocationIterator eli = em.getExternalLocations(lib);
            while (eli.hasNext()) {
                ExternalLocation el = eli.next();
                if (!first) sb.append(','); first = false;
                sb.append('{'); kv("library", lib); sb.append(','); kv("label", el.getLabel()); sb.append(',');
                kv("original_name", el.getOriginalImportedName()); sb.append(','); kvAddr("address", el.getAddress()); sb.append(',');
                kv("function", el.getFunction() != null); sb.append('}');
            }
        }
        sb.append("],");

        // symbols
        key("symbols"); sb.append('[');
        first = true; long nsym = 0; boolean symTrunc = false;
        SymbolIterator si = st.getAllSymbols(true);
        while (si.hasNext()) {
            Symbol s = si.next();
            if (nsym >= maxSyms) { symTrunc = true; break; }
            nsym++;
            if (!first) sb.append(','); first = false;
            sb.append('{'); kv("name", s.getName()); sb.append(','); kvAddr("address", s.getAddress()); sb.append(',');
            kv("type", s.getSymbolType().toString()); sb.append(','); kv("source", s.getSource().toString()); sb.append(',');
            kv("namespace", s.getParentNamespace().getName(true)); sb.append(','); kv("primary", s.isPrimary()); sb.append(','); kv("external", s.isExternal());
            sb.append('}');
        }
        sb.append("],"); kv("symbols_truncated", symTrunc); sb.append(',');

        // decompilation
        key("decompiled"); sb.append('[');
        DecompInterface ifc = new DecompInterface();
        DecompileOptions dopts = new DecompileOptions();
        ifc.setOptions(dopts);
        boolean dok = ifc.openProgram(p);
        if (!dok) warnings.add("decompiler failed to open program: " + ifc.getLastMessage());
        long t0 = System.currentTimeMillis();
        long count = 0;
        first = true;
        for (Function f : fns) {
            if (f.isExternal()) continue;
            if (!first) sb.append(','); first = false;
            sb.append('{'); kvAddr("entry", f.getEntryPoint()); sb.append(','); kv("name", f.getName()); sb.append(',');
            String code = null, err = null; boolean trunc = false;
            StringBuilder hl = new StringBuilder(); hl.append('[');
            if (!dok) { err = "decompiler unavailable"; trunc = true; }
            else if (count >= maxFns) { err = "skipped: maxFunctions reached"; trunc = true; }
            else if (System.currentTimeMillis() - t0 > budgetMs) { err = "skipped: global decompile budget exhausted"; trunc = true; }
            else {
                count++;
                try {
                    DecompileResults r = ifc.decompileFunction(f, (int) perFn, monitor);
                    if (r.decompileCompleted() && r.getDecompiledFunction() != null) {
                        code = r.getDecompiledFunction().getC();
                        ghidra.program.model.pcode.HighFunction hf = r.getHighFunction();
                        if (hf != null) {
                            boolean fh = true;
                            Iterator<ghidra.program.model.pcode.HighSymbol> hs = hf.getLocalSymbolMap().getSymbols();
                            while (hs.hasNext()) {
                                ghidra.program.model.pcode.HighSymbol sym = hs.next();
                                if (!fh) hl.append(','); fh = false;
                                int sz = sym.getDataType() == null ? 0 : sym.getDataType().getLength();
                                hl.append("{\"name\":"); sbStr(hl, sym.getName());
                                hl.append(",\"type\":"); sbStr(hl, sym.getDataType() == null ? null : sym.getDataType().getName());
                                hl.append(",\"size\":").append(sz).append(",\"parameter\":").append(sym.isParameter()).append('}');
                            }
                        }
                    }
                    else { err = r.getErrorMessage() == null ? "decompile failed" : r.getErrorMessage(); trunc = r.isTimedOut(); }
                } catch (Exception e) { err = "exception: " + e; }
            }
            hl.append(']'); kv("code", code); sb.append(','); key("high_locals"); sb.append(hl); sb.append(','); kv("error", err); sb.append(','); kv("truncated", trunc);
            sb.append('}');
        }
        ifc.dispose();
        sb.append("],");
        kv("decompile_ms", System.currentTimeMillis() - t0); sb.append(',');
        key("warnings"); sb.append('[');
        for (int i = 0; i < warnings.size(); i++) { if (i > 0) sb.append(','); str(warnings.get(i)); }
        sb.append("]}");

        File tmp = new File(out.getPath() + ".part");
        Files.write(tmp.toPath(), sb.toString().getBytes(StandardCharsets.UTF_8));
        if (!tmp.renameTo(out)) throw new RuntimeException("could not move snapshot into place");
        println("RTK_EXPORT_OK " + fns.size() + " functions");
    }
}
