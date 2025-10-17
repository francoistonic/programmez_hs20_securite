#!/usr/bin/python3
# (c) 2025, Alphabot42 (@Alphabot42)

# IDA Plugin: Resolve API hashes using MurmurHash2 (seed 32)
# Scans all instructions in all segments for immediate values matching hashed API names.

import idaapi, idautils, idc, struct, os, pefile

# -----------------------------
# MurmurHash2 implementation (seed = 32)
# -----------------------------
def murmurhash2(data, seed=32):
    m = 0x5bd1e995
    r = 24
    length = len(data)
    h = seed ^ length
    data_bytes = bytearray(data.encode('utf-8'))
    i = 0

    while length >= 4:
        k = struct.unpack_from("<I", data_bytes, i)[0]
        k = (k * m) & 0xFFFFFFFF
        k ^= (k >> r)
        k = (k * m) & 0xFFFFFFFF

        h = (h * m) & 0xFFFFFFFF
        h ^= k

        i += 4
        length -= 4

    if length == 3:
        h ^= data_bytes[i + 2] << 16
    if length >= 2:
        h ^= data_bytes[i + 1] << 8
    if length >= 1:
        h ^= data_bytes[i]
        h = (h * m) & 0xFFFFFFFF

    h ^= h >> 13
    h = (h * m) & 0xFFFFFFFF
    h ^= h >> 15

    return h

# -----------------------------
# Load all exports from common DLLs
# -----------------------------
hash_dict = {}

def load_exports_from_dll(dll_path):
    try:
        pe = pefile.PE(dll_path)
        if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            print(f"[!] No export table found in {dll_path}")
            return

        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                api_name = exp.name.decode('utf-8')
                hash_val = murmurhash2(api_name)
                hash_dict[hash_val] = api_name
    except Exception as e:
        print(f"[!] Failed to parse {dll_path}: {e}")

# -----------------------------
# Search for hashed constants and annotate them in IDA
# -----------------------------
def resolve_hashes():
    system32 = os.environ.get('SystemRoot', 'C:\\Windows') + '\\System32'
    dlls = ['kernel32.dll', 'ntdll.dll', 'user32.dll', 'advapi32.dll', 'ws2_32.dll', 'wininet.dll, shell32.dll, crypt32.dll']

    for dll in dlls:
        dll_path = os.path.join(system32, dll)
        load_exports_from_dll(dll_path)

    print(f"[+] Loaded {len(hash_dict)} API hashes from system DLLs")

    # Loop through all instructions and check for hash matches
    for seg_ea in idautils.Segments():
        for head in idautils.Heads(seg_ea, idc.get_segm_end(seg_ea)):
            if idc.is_code(idc.get_full_flags(head)):
                if idc.print_insn_mnem(head) in ['mov', 'push']:
                    opval = idc.get_operand_value(head, 1)
                    if opval in hash_dict:
                        idc.set_cmt(head, f"[API] {hash_dict[opval]}", 0)
                        print(f"[+] Resolved 0x{opval:08X} -> {hash_dict[opval]} at 0x{head:X}")

# -----------------------------
# IDA plugin boilerplate
# -----------------------------
class APIMurmurHashResolver2(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Resolve MurmurHash2 API hashes"
    help = "Attempts to resolve MurmurHash2 hashed APIs"
    wanted_name = "API MurmurHash2 Resolver 2"
    wanted_hotkey = "Alt-F12"

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
        resolve_hashes()
        print("[+] MurmurHash2 API resolution complete.")

    def term(self):
        pass

def PLUGIN_ENTRY():
    return APIMurmurHashResolver()