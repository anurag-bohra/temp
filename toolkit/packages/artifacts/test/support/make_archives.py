# Builds malicious / legit test archives. Usage: python3 -I make_archives.py <outdir>
import io, os, struct, sys, tarfile, zipfile, subprocess, gzip

out = sys.argv[1]; os.makedirs(out, exist_ok=True)
def p(n): return os.path.join(out, n)

def zinfo(name, mode=0o100644, ctype=zipfile.ZIP_DEFLATED):
    zi = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0)); zi.external_attr = mode << 16; zi.create_system = 3; zi.compress_type = ctype
    return zi

def mkzip(name, items, ctype=zipfile.ZIP_DEFLATED):
    with zipfile.ZipFile(p(name), "w") as z:
        for it in items:
            n, data = it[0], it[1]; mode = it[2] if len(it) > 2 else 0o100644
            z.writestr(zinfo(n, mode, ctype), data)

mkzip("zipslip.zip", [("ok.txt", b"fine"), ("../../evil.txt", b"EVIL")])
mkzip("absolute.zip", [("ok.txt", b"fine"), ("/tmp/rtk-test-abs/x", b"EVIL")])
mkzip("drive.zip", [("C:\\Windows\\x.txt", b"EVIL")])
mkzip("backslash-traversal.zip", [("..\\..\\evil.txt", b"EVIL")])
mkzip("symlink-etc.zip", [("link", b"/etc", 0o120777)])
mkzip("symlink-through.zip", [("link", b"/etc", 0o120777), ("link/passwd", b"EVIL")])
mkzip("symlink-internal-through.zip", [("sub/real.txt", b"x"), ("inner", b"sub", 0o120777), ("inner/f.txt", b"y")])
mkzip("symlink-benign.zip", [("a.txt", b"A"), ("alias", b"a.txt", 0o120777)])
mkzip("dup.zip", [("a.txt", b"one"), ("a.txt", b"two")])
mkzip("case.zip", [("README", b"one"), ("readme", b"two")])
mkzip("ctrl.zip", [("bad\nname.txt", b"x")])
mkzip("overwrite.zip", [("ok.txt", b"from-archive")])
mkzip("modes.zip", [("run.sh", b"#!/bin/sh\necho hi\n", 0o104755), ("data.bin", b"\x00\x01", 0o100666)])
mkzip("many.zip", [("f%03d.txt" % i, b"x") for i in range(200)])
mkzip("bomb.zip", [("zeros.bin", b"\0" * (20 * 1024 * 1024))])
mkzip("bomb-nested.zip", [("inner.zip", open(p("bomb.zip"), "rb").read())], zipfile.ZIP_STORED)
mkzip("bigstored.zip", [("a.bin", os.urandom(600 * 1024)), ("b.bin", os.urandom(600 * 1024))], zipfile.ZIP_STORED)
# NUL in name: same-length replacement in both headers
mkzip("nul.zip", [("AXB.txt", b"x")])
d = open(p("nul.zip"), "rb").read().replace(b"AXB.txt", b"A\0B.txt"); open(p("nul.zip"), "wb").write(d)
# declared-size lies (patch local + central usize)
def patch_usize(src, dst, new):
    d = bytearray(open(p(src), "rb").read())
    l = d.find(b"PK\x03\x04"); struct.pack_into("<I", d, l + 22, new)
    c = d.find(b"PK\x01\x02"); struct.pack_into("<I", d, c + 24, new)
    open(p(dst), "wb").write(bytes(d))
mkzip("lie-src.zip", [("lie.txt", b"A" * 1000)], zipfile.ZIP_STORED)
patch_usize("lie-src.zip", "lie-small.zip", 10)
patch_usize("lie-src.zip", "lie-large.zip", 5000)
mkzip("lie-bomb-src.zip", [("lie.bin", b"\0" * (8 * 1024 * 1024))])
patch_usize("lie-bomb-src.zip", "lie-bomb.zip", 100)
# CRC corruption of a stored entry
mkzip("crc-src.zip", [("c.txt", b"hello world hello world")], zipfile.ZIP_STORED)
d = bytearray(open(p("crc-src.zip"), "rb").read()); i = d.find(b"hello"); d[i] ^= 0x20; open(p("crc.zip"), "wb").write(bytes(d))
# ZipCrypto encrypted entry (Info-ZIP zip)
os.makedirs(p("encsrc"), exist_ok=True); open(p("encsrc/secret.txt"), "w").write("top secret\n")
subprocess.run(["zip", "-q", "-P", "pw", p("enc.zip"), "secret.txt"], cwd=p("encsrc"), check=True)
# kinds + nesting
inner = io.BytesIO()
with zipfile.ZipFile(inner, "w") as z: z.writestr("deep.elf", b"\x7fELF\x02\x01\x01" + b"\0" * 60)
mkzip("kinds.zip", [("a.elf", b"\x7fELF\x02\x01\x01" + b"\0" * 60), ("b.exe", b"MZ" + b"\0" * 62), ("c.sh", b"#!/bin/sh\necho\n"), ("d.dex", b"dex\n035\0" + b"\0" * 40),
    ("e.macho", b"\xcf\xfa\xed\xfe" + b"\0" * 28), ("f.txt", b"plain text\n"), ("g.class", b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + b"\0" * 8), ("nested.zip", inner.getvalue())])
data = b"payload"
for lvl in range(8):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z: z.writestr("level%d.bin" % lvl if lvl == 0 else "level%d.zip" % lvl, data)
    data = b.getvalue()
open(p("nest8.zip"), "wb").write(data)
# truncated + garbage
d = open(p("kinds.zip"), "rb").read(); open(p("truncated.zip"), "wb").write(d[: len(d) // 2]); open(p("garbage.bin"), "wb").write(os.urandom(2000))
# tar variants
def mktar(name, build, mode="w"):
    with tarfile.open(p(name), mode, format=tarfile.GNU_FORMAT) as t: build(t)
def add(t, n, data=b"x", mode=0o644):
    ti = tarfile.TarInfo(n); ti.size = len(data); ti.mode = mode; t.addfile(ti, io.BytesIO(data))
def evil(t):
    add(t, "ok.txt", b"fine"); add(t, "../escape.txt", b"EVIL"); add(t, "/tmp/rtk-test-abs/y", b"EVIL")
    ti = tarfile.TarInfo("dev"); ti.type = tarfile.CHRTYPE; ti.devmajor = 1; ti.devminor = 3; t.addfile(ti)
    ti = tarfile.TarInfo("fifo"); ti.type = tarfile.FIFOTYPE; t.addfile(ti)
    ti = tarfile.TarInfo("sl"); ti.type = tarfile.SYMTYPE; ti.linkname = "/etc/passwd"; t.addfile(ti)
    ti = tarfile.TarInfo("hl"); ti.type = tarfile.LNKTYPE; ti.linkname = "../../etc/shadow"; t.addfile(ti)
mktar("evil.tar", evil)
mktar("tar-slip.tar", lambda t: (add(t, "ok.txt", b"fine"), add(t, "a/../../escape.txt", b"EVIL")))
mktar("tar-dev.tar", lambda t: (add(t, "ok.txt", b"fine"), t.addfile(tarfile.TarInfo("dev"))))
def devonly(t):
    ti = tarfile.TarInfo("dev"); ti.type = tarfile.BLKTYPE; ti.devmajor = 8; t.addfile(ti)
mktar("dev-only.tar", devonly)
def legit(t):
    add(t, "dir/a.txt", b"alpha\n"); add(t, "dir/sub/b.bin", b"\x7fELF" + b"\0" * 60); add(t, "run.sh", b"#!/bin/sh\n", 0o4755)
    ti = tarfile.TarInfo("dir/ln"); ti.type = tarfile.SYMTYPE; ti.linkname = "a.txt"; t.addfile(ti)
mktar("legit.tar.gz", legit, "w:gz"); mktar("legit.tar", legit)
mktar("tarbomb.tar.gz", lambda t: add(t, "zeros", b"\0" * (20 * 1024 * 1024)), "w:gz")
longn = "d/" + "x" * 150 + "/" + "y" * 120 + ".txt"
mktar("longname.tar", lambda t: add(t, longn, b"long"))
with open(p("hello.txt.gz"), "wb") as f: f.write(gzip.compress(b"hello gzip\n"))
open(p("truncated.tar.gz"), "wb").write(open(p("legit.tar.gz"), "rb").read()[:60])
