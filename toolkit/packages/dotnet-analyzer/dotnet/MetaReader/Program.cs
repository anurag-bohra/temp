// Static reader for .NET (PE/CLI) assemblies. NEVER loads the target: it only parses bytes with
// System.Reflection.Metadata / System.Reflection.PortableExecutable and decodes IL itself.
// Prints one JSON document on stdout. Exit code 0 even for "not managed" (reported in JSON).
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

static class Program
{
    static readonly JsonSerializerOptions Json = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower, DictionaryKeyPolicy = null, WriteIndented = false };

    static int Main(string[] args)
    {
        if (args.Length < 1) { Console.Error.WriteLine("usage: MetaReader <file>"); return 2; }
        object result;
        try { result = Analyze(args[0]); }
        catch (Exception e) { result = new { managed = false, reason = "analysis failed: " + e.GetType().Name + ": " + e.Message }; }
        var stdout = Console.OpenStandardOutput();
        var bytes = JsonSerializer.SerializeToUtf8Bytes(result, Json);
        stdout.Write(bytes, 0, bytes.Length);
        stdout.Flush();
        return 0;
    }

    static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();
    static string Sha256(byte[] b) => Hex(SHA256.HashData(b));
    static string Sha256(ReadOnlySpan<byte> b) => Hex(SHA256.HashData(b));

    // ---- opcode tables obtained by reflection over System.Reflection.Emit.OpCodes (no hand-written table)
    static readonly OpCode[] OneByte = new OpCode[256];
    static readonly bool[] OneByteSet = new bool[256];
    static readonly OpCode[] TwoByte = new OpCode[256];
    static readonly bool[] TwoByteSet = new bool[256];
    static Program()
    {
        foreach (var f in typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static))
        {
            if (f.FieldType != typeof(OpCode)) continue;
            var oc = (OpCode)f.GetValue(null);
            ushort v = (ushort)oc.Value;
            if (oc.Size == 1) { OneByte[v & 0xFF] = oc; OneByteSet[v & 0xFF] = true; }
            else { TwoByte[v & 0xFF] = oc; TwoByteSet[v & 0xFF] = true; }
        }
    }

    sealed class TypeNameProvider : ISignatureTypeProvider<string, object>
    {
        public string GetArrayType(string e, ArrayShape s) => e + "[" + new string(',', Math.Max(0, s.Rank - 1)) + "]";
        public string GetByReferenceType(string e) => e + "&";
        public string GetFunctionPointerType(MethodSignature<string> s) => "fnptr";
        public string GetGenericInstantiation(string g, ImmutableArray<string> a) => g + "<" + string.Join(",", a) + ">";
        public string GetGenericMethodParameter(object c, int i) => "!!" + i;
        public string GetGenericTypeParameter(object c, int i) => "!" + i;
        public string GetModifiedType(string m, string u, bool r) => u;
        public string GetPinnedType(string e) => e;
        public string GetPointerType(string e) => e + "*";
        public string GetPrimitiveType(PrimitiveTypeCode c) => c switch
        {
            PrimitiveTypeCode.Void => "System.Void", PrimitiveTypeCode.Boolean => "System.Boolean", PrimitiveTypeCode.Char => "System.Char",
            PrimitiveTypeCode.SByte => "System.SByte", PrimitiveTypeCode.Byte => "System.Byte", PrimitiveTypeCode.Int16 => "System.Int16",
            PrimitiveTypeCode.UInt16 => "System.UInt16", PrimitiveTypeCode.Int32 => "System.Int32", PrimitiveTypeCode.UInt32 => "System.UInt32",
            PrimitiveTypeCode.Int64 => "System.Int64", PrimitiveTypeCode.UInt64 => "System.UInt64", PrimitiveTypeCode.Single => "System.Single",
            PrimitiveTypeCode.Double => "System.Double", PrimitiveTypeCode.String => "System.String", PrimitiveTypeCode.TypedReference => "System.TypedReference",
            PrimitiveTypeCode.IntPtr => "System.IntPtr", PrimitiveTypeCode.UIntPtr => "System.UIntPtr", PrimitiveTypeCode.Object => "System.Object",
            _ => c.ToString()
        };
        public string GetSZArrayType(string e) => e + "[]";
        public string GetTypeFromDefinition(MetadataReader r, TypeDefinitionHandle h, byte k) => DefName(r, h);
        public string GetTypeFromReference(MetadataReader r, TypeReferenceHandle h, byte k) => RefName(r, h);
        public string GetTypeFromSpecification(MetadataReader r, object c, TypeSpecificationHandle h, byte k)
            => r.GetTypeSpecification(h).DecodeSignature(this, c);
    }
    static readonly TypeNameProvider Prov = new TypeNameProvider();

    static string Q(MetadataReader r, StringHandle ns, StringHandle n)
    {
        var a = r.GetString(ns); var b = r.GetString(n);
        return a.Length == 0 ? b : a + "." + b;
    }
    static string DefName(MetadataReader r, TypeDefinitionHandle h)
    {
        var t = r.GetTypeDefinition(h);
        var decl = t.GetDeclaringType();
        if (!decl.IsNil) return DefName(r, decl) + "/" + r.GetString(t.Name);
        return Q(r, t.Namespace, t.Name);
    }
    static string RefName(MetadataReader r, TypeReferenceHandle h)
    {
        var t = r.GetTypeReference(h);
        if (t.ResolutionScope.Kind == HandleKind.TypeReference) return RefName(r, (TypeReferenceHandle)t.ResolutionScope) + "/" + r.GetString(t.Name);
        return Q(r, t.Namespace, t.Name);
    }
    static string TypeHandleName(MetadataReader r, EntityHandle h)
    {
        switch (h.Kind)
        {
            case HandleKind.TypeDefinition: return DefName(r, (TypeDefinitionHandle)h);
            case HandleKind.TypeReference: return RefName(r, (TypeReferenceHandle)h);
            case HandleKind.TypeSpecification: return r.GetTypeSpecification((TypeSpecificationHandle)h).DecodeSignature(Prov, null);
            case HandleKind.ModuleReference: return "<module:" + r.GetString(r.GetModuleReference((ModuleReferenceHandle)h).Name) + ">";
            default: return "<" + h.Kind + ">";
        }
    }
    static string SigString(MethodSignature<string> s) => "(" + string.Join(",", s.ParameterTypes) + ")";

    sealed class Target { public string Type, Name, Sig, Kind; public string Full => Type + "::" + Name + Sig; }

    static Target ResolveMethodTarget(MetadataReader r, EntityHandle h)
    {
        try
        {
            switch (h.Kind)
            {
                case HandleKind.MethodDefinition:
                {
                    var m = r.GetMethodDefinition((MethodDefinitionHandle)h);
                    return new Target { Type = DefName(r, m.GetDeclaringType()), Name = r.GetString(m.Name), Sig = SigString(m.DecodeSignature(Prov, null)), Kind = "method-def" };
                }
                case HandleKind.MemberReference:
                {
                    var m = r.GetMemberReference((MemberReferenceHandle)h);
                    string sig = m.GetKind() == MemberReferenceKind.Method ? SigString(m.DecodeMethodSignature(Prov, null)) : "";
                    return new Target { Type = TypeHandleName(r, m.Parent), Name = r.GetString(m.Name), Sig = sig, Kind = "member-ref" };
                }
                case HandleKind.MethodSpecification:
                {
                    var ms = r.GetMethodSpecification((MethodSpecificationHandle)h);
                    var t = ResolveMethodTarget(r, ms.Method);
                    if (t != null) t.Kind = "method-spec";
                    return t;
                }
            }
        }
        catch (Exception) { }
        return null;
    }

    static string CtorTypeName(MetadataReader r, EntityHandle ctor)
    {
        try
        {
            if (ctor.Kind == HandleKind.MemberReference) return TypeHandleName(r, r.GetMemberReference((MemberReferenceHandle)ctor).Parent);
            if (ctor.Kind == HandleKind.MethodDefinition) return DefName(r, r.GetMethodDefinition((MethodDefinitionHandle)ctor).GetDeclaringType());
        }
        catch (Exception) { }
        return "<unknown>";
    }

    static string PublicKeyToken(MetadataReader r, BlobHandle pk, AssemblyFlags flags = 0, bool isRef = false)
    {
        if (pk.IsNil) return null;
        var key = r.GetBlobBytes(pk);
        if (key.Length == 0) return null;
        if (isRef && (flags & AssemblyFlags.PublicKey) == 0) return Hex(key); // already a token
        var sha1 = SHA1.HashData(key);
        var tok = new byte[8];
        for (int i = 0; i < 8; i++) tok[i] = sha1[sha1.Length - 1 - i];
        return Hex(tok);
    }

    static string ReadCaString(MetadataReader r, CustomAttribute ca)
    {
        // Fixed single string argument (e.g. TargetFrameworkAttribute(".NETCoreApp,Version=v8.0")).
        try
        {
            var br = r.GetBlobReader(ca.Value);
            if (br.ReadUInt16() != 1) return null;
            return br.ReadSerializedString();
        }
        catch (Exception) { return null; }
    }

    static string ResourceKind(byte[] d)
    {
        if (d.Length >= 2 && d[0] == 'M' && d[1] == 'Z') return "pe";
        if (d.Length >= 4 && d[0] == 'P' && d[1] == 'K' && (d[2] == 3 || d[2] == 5 || d[2] == 7)) return "zip";
        if (d.Length >= 2 && d[0] == 0x1f && d[1] == 0x8b) return "gzip";
        if (d.Length >= 4 && d[0] == 0xCE && d[1] == 0xCA && d[2] == 0xEF && d[3] == 0xBE) return "dotnet-resources";
        return "unknown";
    }

    static object Analyze(string path)
    {
        byte[] file = File.ReadAllBytes(path);
        var info = new Dictionary<string, object> { ["byte_length"] = file.Length, ["sha256"] = Sha256(file) };
        if (file.Length < 64 || file[0] != 'M' || file[1] != 'Z')
            return new { managed = false, reason = "not a PE image (no MZ header)", artifact = info };
        PEReader pe;
        try { pe = new PEReader(new MemoryStream(file, false)); var _ = pe.PEHeaders; }
        catch (Exception e) { return new { managed = false, reason = "invalid or truncated PE image: " + e.Message, artifact = info }; }
        using (pe)
        {
            var hdr = pe.PEHeaders;
            string machine = hdr.CoffHeader.Machine.ToString();
            if (!hdr.IsCoffOnly && hdr.CorHeader == null)
                return new { managed = false, reason = "PE image has no CLI header (native image, not a .NET assembly)", machine, artifact = info };
            if (!pe.HasMetadata)
                return new { managed = false, reason = "CLI header present but no readable metadata", machine, artifact = info };
            MetadataReader r;
            try { r = pe.GetMetadataReader(); }
            catch (Exception e) { return new { managed = false, reason = "corrupt CLI metadata: " + e.Message, machine, artifact = info }; }

            var issues = new List<string>();
            var asmDef = r.IsAssembly ? r.GetAssemblyDefinition() : default;
            var mod = r.GetModuleDefinition();
            object identity = new
            {
                name = r.IsAssembly ? r.GetString(asmDef.Name) : null,
                module_name = r.GetString(mod.Name),
                version = r.IsAssembly ? asmDef.Version.ToString() : null,
                culture = r.IsAssembly ? (asmDef.Culture.IsNil ? "" : r.GetString(asmDef.Culture)) : null,
                mvid = r.GetGuid(mod.Mvid).ToString(),
                public_key_token = r.IsAssembly ? PublicKeyToken(r, asmDef.PublicKey) : null,
                metadata_version = r.MetadataVersion,
                is_assembly = r.IsAssembly,
                machine,
                cor_flags = hdr.CorHeader != null ? hdr.CorHeader.Flags.ToString() : null,
            };

            // custom attributes (assembly + module level) and target framework
            var attrNames = new List<string>();
            string tfm = null;
            void ScanAttrs(CustomAttributeHandleCollection col, string scope)
            {
                foreach (var h in col)
                {
                    var ca = r.GetCustomAttribute(h);
                    var tn = CtorTypeName(r, ca.Constructor);
                    attrNames.Add(scope + ":" + tn);
                    if (tn == "System.Runtime.Versioning.TargetFrameworkAttribute")
                    {
                        tfm = ReadCaString(r, ca);
                        // named property FrameworkDisplayName is not decoded (limitation)
                    }
                }
            }
            if (r.IsAssembly) ScanAttrs(asmDef.GetCustomAttributes(), "assembly");
            ScanAttrs(mod.GetCustomAttributes(), "module");
            foreach (var th in r.TypeDefinitions)
            {
                var t = r.GetTypeDefinition(th);
                foreach (var h in t.GetCustomAttributes())
                    attrNames.Add("type:" + DefName(r, th) + ":" + CtorTypeName(r, r.GetCustomAttribute(h).Constructor));
            }

            var asmRefs = new List<object>();
            foreach (var h in r.AssemblyReferences)
            {
                var a = r.GetAssemblyReference(h);
                asmRefs.Add(new { name = r.GetString(a.Name), version = a.Version.ToString(), public_key_token = PublicKeyToken(r, a.PublicKeyOrToken, a.Flags, true), culture = a.Culture.IsNil ? "" : r.GetString(a.Culture) });
            }
            var modRefs = new List<string>();
            for (int i = 1; i <= r.GetTableRowCount(TableIndex.ModuleRef); i++)
                modRefs.Add(r.GetString(r.GetModuleReference(MetadataTokens.ModuleReferenceHandle(i)).Name));

            var types = new List<object>();
            var methods = new List<object>();
            var edges = new List<object>();
            var pinvokes = new List<object>();
            var literalsByMethod = new List<object>();

            foreach (var th in r.TypeDefinitions)
            {
                var td = r.GetTypeDefinition(th);
                string tname = DefName(r, th);
                string baseName = null;
                try { if (!td.BaseType.IsNil) baseName = TypeHandleName(r, td.BaseType); } catch (Exception) { }
                var mnames = new List<string>();
                foreach (var mh in td.GetMethods())
                {
                    var md = r.GetMethodDefinition(mh);
                    string sig = "()";
                    string ret = null;
                    try { var ms = md.DecodeSignature(Prov, null); sig = SigString(ms); ret = ms.ReturnType; }
                    catch (Exception e) { issues.Add("signature decode failed for method token 0x" + MetadataTokens.GetToken(mh).ToString("x8") + ": " + e.Message); }
                    string name = r.GetString(md.Name);
                    string full = tname + "::" + name + sig;
                    mnames.Add(full);
                    int rva = md.RelativeVirtualAddress;
                    int token = MetadataTokens.GetToken(mh);
                    bool isPinvoke = (md.Attributes & MethodAttributes.PinvokeImpl) != 0;
                    string ilHash = null; int ilLen = 0; string bodyStatus = rva == 0 ? "absent" : "decoded";
                    var lits = new List<string>();
                    if (rva != 0)
                    {
                        try
                        {
                            var body = pe.GetMethodBody(rva);
                            var il = body.GetILBytes() ?? Array.Empty<byte>();
                            ilLen = il.Length;
                            ilHash = Sha256(il);
                            DecodeIl(r, il, full, edges, lits, issues);
                        }
                        catch (Exception e) { bodyStatus = "error"; issues.Add("method body decode failed for " + full + ": " + e.Message); }
                    }
                    if (lits.Count > 0) literalsByMethod.Add(new { method = full, literals = lits });
                    if (isPinvoke)
                    {
                        try
                        {
                            var imp = md.GetImport();
                            string dll = imp.Module.IsNil ? null : r.GetString(r.GetModuleReference(imp.Module).Name);
                            string ep = imp.Name.IsNil ? name : r.GetString(imp.Name);
                            pinvokes.Add(new { dll, entry_point = ep, declaring_method = full, declaring_type = tname, method_name = name, flags = imp.Attributes.ToString() });
                        }
                        catch (Exception e) { issues.Add("pinvoke decode failed for " + full + ": " + e.Message); }
                    }
                    methods.Add(new
                    {
                        full_name = full, declaring_type = tname, name, signature = sig, return_type = ret, token = "0x" + token.ToString("x8"),
                        flags = (int)md.Attributes, flag_names = md.Attributes.ToString(), impl_flags = (int)md.ImplAttributes,
                        rva, il_length = ilLen, il_sha256 = ilHash, body_status = bodyStatus, is_pinvoke = isPinvoke, literals = lits,
                    });
                }
                types.Add(new { full_name = tname, flags = (int)td.Attributes, base_type = baseName, methods = mnames });
            }

            // resources
            var resources = new List<object>();
            try
            {
                var resDir = hdr.CorHeader.ResourcesDirectory;
                foreach (var rh in r.ManifestResources)
                {
                    var res = r.GetManifestResource(rh);
                    string rname = r.GetString(res.Name);
                    if (!res.Implementation.IsNil) { resources.Add(new { name = rname, location = "linked", size = (long?)null, sha256 = (string)null, kind = "linked" }); continue; }
                    try
                    {
                        var sec = pe.GetSectionData(resDir.RelativeVirtualAddress);
                        var rd = sec.GetContent((int)res.Offset, 4);
                        int len = BitConverter.ToInt32(rd.ToArray(), 0);
                        if (len < 0 || len > resDir.Size) throw new BadImageFormatException("resource length out of range");
                        var data = sec.GetContent((int)res.Offset + 4, len).ToArray();
                        resources.Add(new { name = rname, location = "embedded", size = (long?)data.Length, sha256 = Sha256(data), kind = ResourceKind(data) });
                    }
                    catch (Exception e) { issues.Add("resource " + rname + ": " + e.Message); resources.Add(new { name = rname, location = "embedded", size = (long?)null, sha256 = (string)null, kind = "unreadable" }); }
                }
            }
            catch (Exception e) { issues.Add("resources: " + e.Message); }

            // #US heap literals (whole heap)
            var usLits = new List<object>();
            try
            {
                var h = MetadataTokens.UserStringHandle(0);
                int guard = 0;
                do
                {
                    string s = r.GetUserString(h);
                    if (s.Length > 0) usLits.Add(new { token = "0x" + MetadataTokens.GetToken(h).ToString("x8"), value = s });
                    h = r.GetNextHandle(h);
                } while (!h.IsNil && ++guard < 2_000_000);
            }
            catch (Exception e) { issues.Add("#US enumeration: " + e.Message); }

            return new
            {
                managed = true,
                artifact = info,
                identity,
                target_framework = tfm,
                custom_attributes = attrNames,
                assembly_references = asmRefs,
                module_references = modRefs,
                types,
                methods,
                call_edges = edges,
                method_literals = literalsByMethod,
                user_string_literals = usLits,
                pinvokes,
                resources,
                issues,
            };
        }
    }

    static void DecodeIl(MetadataReader r, byte[] il, string caller, List<object> edges, List<string> lits, List<string> issues)
    {
        int i = 0;
        while (i < il.Length)
        {
            int start = i;
            byte b = il[i++];
            OpCode oc;
            if (b == 0xFE)
            {
                if (i >= il.Length) { issues.Add(caller + ": truncated IL at 0x" + start.ToString("x")); return; }
                byte b2 = il[i++];
                if (!TwoByteSet[b2]) { issues.Add(caller + ": unknown two-byte opcode FE " + b2.ToString("x2") + " at 0x" + start.ToString("x")); return; }
                oc = TwoByte[b2];
            }
            else
            {
                if (!OneByteSet[b]) { issues.Add(caller + ": unknown opcode " + b.ToString("x2") + " at 0x" + start.ToString("x")); return; }
                oc = OneByte[b];
            }
            int size;
            switch (oc.OperandType)
            {
                case OperandType.InlineNone: size = 0; break;
                case OperandType.ShortInlineBrTarget: case OperandType.ShortInlineI: case OperandType.ShortInlineVar: size = 1; break;
                case OperandType.InlineVar: size = 2; break;
                case OperandType.InlineI8: case OperandType.InlineR: size = 8; break;
                case OperandType.InlineSwitch:
                {
                    if (i + 4 > il.Length) { issues.Add(caller + ": truncated switch"); return; }
                    long n = BitConverter.ToUInt32(il, i);
                    size = 4 + (int)Math.Min(n * 4, int.MaxValue / 2);
                    break;
                }
                default: size = 4; break; // InlineI, InlineBrTarget, InlineField/Method/Sig/String/Tok/Type, ShortInlineR
            }
            if (i + size > il.Length) { issues.Add(caller + ": truncated operand for " + oc.Name + " at 0x" + start.ToString("x")); return; }
            if (size == 4 && (oc.OperandType == OperandType.InlineMethod || oc.OperandType == OperandType.InlineString))
            {
                int tok = BitConverter.ToInt32(il, i);
                if (oc.OperandType == OperandType.InlineString)
                {
                    try { lits.Add(r.GetUserString(MetadataTokens.UserStringHandle(tok & 0x00FFFFFF))); }
                    catch (Exception e) { issues.Add(caller + ": bad ldstr token 0x" + tok.ToString("x8") + ": " + e.Message); }
                }
                else
                {
                    var t = ResolveMethodTarget(r, MetadataTokens.EntityHandle(tok));
                    if (t != null)
                        edges.Add(new { caller, opcode = oc.Name, target = t.Full, target_type = t.Type, target_name = t.Name, target_kind = t.Kind, il_offset = start });
                    else
                        edges.Add(new { caller, opcode = oc.Name, target = "<unresolved 0x" + tok.ToString("x8") + ">", target_type = (string)null, target_name = (string)null, target_kind = "unresolved", il_offset = start });
                }
            }
            else if (oc.OperandType == OperandType.InlineTok && size == 4)
            {
                // ldtoken may reference a method (rare); record as edge only when it resolves to a method token.
                int tok = BitConverter.ToInt32(il, i);
                int table = tok >>> 24;
                if (table == 0x06 || table == 0x0A || table == 0x2B)
                {
                    var t = ResolveMethodTarget(r, MetadataTokens.EntityHandle(tok));
                    if (t != null) edges.Add(new { caller, opcode = oc.Name, target = t.Full, target_type = t.Type, target_name = t.Name, target_kind = t.Kind, il_offset = start });
                }
            }
            i += size;
        }
    }
}
