import os
import lief
import sys

KIND_STUB_RESOLVER = 0x10
KIND_REEXPORT = 0x8
exports = []


def read_ascii(buffer, offset):
    asciiz = b""
    while buffer[offset]:
        asciiz += buffer[offset:offset + 1]
        offset += 1
    return asciiz, offset + 1


def read_uleb(buffer, offset):
    value = 0
    shift = 0
    while True:
        byte = buffer[offset]
        offset += 1
        value = value | ((byte & 0x7f) << shift)
        shift += 7
        if not byte & 0x80:
            break
    return value, offset


def parse_export_trie(buffer, offset, end, label):
    if offset > end:
        return
    value, offset = read_uleb(buffer, offset)
    if value:
        flags, offset = read_uleb(buffer, offset)
        if flags & KIND_STUB_RESOLVER:
            stub, offset = read_uleb(buffer, offset)
            resolver, offset = read_uleb(buffer, offset)
        elif flags & KIND_REEXPORT:
            ordinal, offset = read_uleb(buffer, offset)
            name, offset = read_ascii(buffer, offset)
        else:
            value, offset = read_uleb(buffer, offset)
    child_count = buffer[offset]
    if not child_count:
        exports.append(label)
    offset += 1
    for i in range(child_count):
        node_label, offset = read_ascii(buffer, offset)
        nextnode_offset, offset = read_uleb(buffer, offset)
        parse_export_trie(buffer, nextnode_offset, end, label+node_label)
    return


def main():
    binary_path = sys.argv[1]
    if not os.path.exists(binary_path):
        print("File does not exist.")
    if not lief.is_macho(binary_path):
        print("Not a Macho file")
    else:
        app = lief.parse(binary_path)
        FILE = open(binary_path, "rb")
        export_offset, export_size = app.dyld_info.export_info
        if int(export_offset) == 0 and int(export_size) == 0:
            print("No Exports in this file")
        FILE.seek(int(export_offset))
        contents = FILE.read(export_size)
        parse_export_trie(contents, 0, export_size, b"")
        print(exports)
        print("Child Count is - ", str(len(exports)))


if __name__ == '__main__':
    main()
