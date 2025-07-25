import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
import sys
import platform
from modules import port_scanner, brute_forcer

# --- Appearance Detection ---
def detect_dark_mode():
    try:
        if sys.platform == "darwin":  # macOS
            import subprocess
            result = subprocess.run([
                'defaults', 'read', '-g', 'AppleInterfaceStyle'
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return b'Dark' in result.stdout
        elif sys.platform == "win32":  # Windows
            import winreg
            registry = winreg.ConnectRegistry(None, winreg.HKEY_CURRENT_USER)
            key = winreg.OpenKey(registry, r"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize")
            value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
            return value == 0  # 0 = dark, 1 = light
    except Exception:
        pass
    return True  # Default to dark mode

IS_DARK = detect_dark_mode()

# --- Color Palettes ---
LIGHT = {
    'bg': '#f5f5f5',
    'fg': '#23272f',
    'header': '#007acc',
    'desc': '#23272f',
    'button_bg': '#e1e1e1',
    'button_fg': '#007acc',
    'button_active_bg': '#d0d0d0',
    'button_active_fg': '#23272f',
    'entry_bg': '#fff',
    'entry_fg': '#23272f',
    'result_bg': '#fff',
    'result_fg': '#007acc',
    'tooltip_bg': '#ffffe0',
    'tooltip_fg': '#23272f',
}
DARK = {
    'bg': '#23272f',
    'fg': '#e1e1e1',
    'header': '#61dafb',
    'desc': '#e1e1e1',
    'button_bg': '#282c34',
    'button_fg': '#61dafb',
    'button_active_bg': '#3a3f4b',
    'button_active_fg': '#fff',
    'entry_bg': '#181a20',
    'entry_fg': '#61dafb',
    'result_bg': '#181a20',
    'result_fg': '#61dafb',
    'tooltip_bg': '#ffffe0',
    'tooltip_fg': '#23272f',
}
THEME = DARK if IS_DARK else LIGHT

class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tipwindow = None
        widget.bind("<Enter>", self.show_tip)
        widget.bind("<Leave>", self.hide_tip)

    def show_tip(self, event=None):
        if self.tipwindow or not self.text:
            return
        x, y, _, cy = self.widget.bbox("insert")
        x = x + self.widget.winfo_rootx() + 25
        y = y + cy + self.widget.winfo_rooty() + 25
        self.tipwindow = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(tw, text=self.text, justify=tk.LEFT,
                         background=THEME['tooltip_bg'], fg=THEME['tooltip_fg'], relief=tk.SOLID, borderwidth=1,
                         font=("tahoma", "10", "normal"))
        label.pack(ipadx=1)

    def hide_tip(self, event=None):
        tw = self.tipwindow
        self.tipwindow = None
        if tw:
            tw.destroy()

class PentestToolkitGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Penetration Testing Toolkit")
        self.geometry("500x350")
        self.configure(bg=THEME['bg'])
        self.resizable(False, False)

        header = tk.Label(self, text="Penetration Testing Toolkit", font=("Segoe UI", 20, "bold"), fg=THEME['header'], bg=THEME['bg'])
        header.pack(pady=(20, 10))

        desc = tk.Label(self, text="Select a module to begin:", font=("Segoe UI", 12), fg=THEME['desc'], bg=THEME['bg'])
        desc.pack(pady=(0, 20))

        btn_frame = tk.Frame(self, bg=THEME['bg'])
        btn_frame.pack()

        port_btn = tk.Button(btn_frame, text="Port Scanner", width=18, height=2, font=("Segoe UI", 12), bg=THEME['button_bg'], fg=THEME['button_fg'], activebackground=THEME['button_active_bg'], activeforeground=THEME['button_active_fg'], command=self.open_port_scanner, relief=tk.RAISED, bd=2)
        port_btn.grid(row=0, column=0, padx=20, pady=10)
        ToolTip(port_btn, "Scan a target host for open TCP ports in a specified range.")

        brute_btn = tk.Button(btn_frame, text="Brute-Forcer", width=18, height=2, font=("Segoe UI", 12), bg=THEME['button_bg'], fg=THEME['button_fg'], activebackground=THEME['button_active_bg'], activeforeground=THEME['button_active_fg'], command=self.open_brute_forcer, relief=tk.RAISED, bd=2)
        brute_btn.grid(row=0, column=1, padx=20, pady=10)
        ToolTip(brute_btn, "Perform a dictionary attack on HTTP Basic Auth.")

        exit_btn = tk.Button(self, text="Exit", width=10, font=("Segoe UI", 11),
            bg="#d9534f", fg="#fff", activebackground="#c9302c", activeforeground="#fff", command=self.destroy)
        exit_btn.pack(pady=(30, 0))

    def open_port_scanner(self):
        PortScannerWindow(self)

    def open_brute_forcer(self):
        BruteForcerWindow(self)

class PortScannerWindow(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("Port Scanner")
        self.geometry("520x500")
        self.configure(bg=THEME['bg'])
        self.resizable(False, False)

        tk.Label(self, text="Port Scanner", font=("Segoe UI", 16, "bold"), fg=THEME['header'], bg=THEME['bg']).pack(pady=(15, 5))
        tk.Label(self, text="Scan a target host for open TCP ports in a specified range.", font=("Segoe UI", 11), fg=THEME['desc'], bg=THEME['bg']).pack(pady=(0, 15))

        form = tk.Frame(self, bg=THEME['bg'])
        form.pack(pady=5)
        tk.Label(form, text="Target Host:", font=("Segoe UI", 11), fg=THEME['fg'], bg=THEME['bg']).grid(row=0, column=0, sticky="e", pady=5)
        self.target_entry = tk.Entry(form, width=30, font=("Segoe UI", 11), bg=THEME['entry_bg'], fg=THEME['entry_fg'])
        self.target_entry.grid(row=0, column=1, pady=5, padx=10)
        ToolTip(self.target_entry, "IP address or domain name of the target host.")

        tk.Label(form, text="Start Port:", font=("Segoe UI", 11), fg=THEME['fg'], bg=THEME['bg']).grid(row=1, column=0, sticky="e", pady=5)
        self.start_port_entry = tk.Entry(form, width=10, font=("Segoe UI", 11), bg=THEME['entry_bg'], fg=THEME['entry_fg'])
        self.start_port_entry.grid(row=1, column=1, sticky="w", pady=5)
        ToolTip(self.start_port_entry, "First port in the scan range (e.g., 1).")

        tk.Label(form, text="End Port:", font=("Segoe UI", 11), fg=THEME['fg'], bg=THEME['bg']).grid(row=2, column=0, sticky="e", pady=5)
        self.end_port_entry = tk.Entry(form, width=10, font=("Segoe UI", 11), bg=THEME['entry_bg'], fg=THEME['entry_fg'])
        self.end_port_entry.grid(row=2, column=1, sticky="w", pady=5)
        ToolTip(self.end_port_entry, "Last port in the scan range (e.g., 1024).")

        self.progress = ttk.Progressbar(self, orient="horizontal", length=400, mode="determinate")
        self.progress.pack(pady=(10, 0))

        scan_btn = tk.Button(self, text="Scan", font=("Segoe UI", 12), bg=THEME['button_bg'], fg=THEME['button_fg'], activebackground=THEME['button_active_bg'], activeforeground=THEME['button_active_fg'], command=self.scan_ports, relief=tk.RAISED, bd=2)
        scan_btn.pack(pady=10)
        ToolTip(scan_btn, "Start scanning the specified port range.")

        self.result_box = scrolledtext.ScrolledText(self, width=60, height=14, font=("Consolas", 10), bg=THEME['result_bg'], fg=THEME['result_fg'])
        self.result_box.pack(pady=10)

    def scan_ports(self):
        target = self.target_entry.get().strip()
        try:
            start_port = int(self.start_port_entry.get())
            end_port = int(self.end_port_entry.get())
            if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535 and start_port <= end_port):
                raise ValueError
        except ValueError:
            messagebox.showerror("Input Error", "Please enter valid port numbers (1-65535) and ensure start <= end.")
            return
        if not target:
            messagebox.showerror("Input Error", "Please enter a target host.")
            return
        self.result_box.delete(1.0, tk.END)
        self.result_box.insert(tk.END, f"Scanning {target} from port {start_port} to {end_port}...\n")
        self.progress['value'] = 0
        self.progress['maximum'] = end_port - start_port + 1
        self.update_idletasks()
        open_ports = []
        import socket
        for idx, port in enumerate(range(start_port, end_port + 1), 1):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.3)
                result = s.connect_ex((target, port))
                if result == 0:
                    open_ports.append(port)
                    self.result_box.insert(tk.END, f"Port {port}: OPEN\n")
            self.progress['value'] = idx
            self.update_idletasks()
        if not open_ports:
            self.result_box.insert(tk.END, "No open ports found in the specified range.\n")
        else:
            self.result_box.insert(tk.END, f"\nOpen ports: {open_ports}\n")
        self.progress['value'] = 0

class BruteForcerWindow(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("Brute-Forcer")
        self.geometry("520x540")
        self.configure(bg=THEME['bg'])
        self.resizable(False, False)

        tk.Label(self, text="Brute-Forcer", font=("Segoe UI", 16, "bold"), fg=THEME['header'], bg=THEME['bg']).pack(pady=(15, 5))
        tk.Label(self, text="Perform a dictionary attack on HTTP Basic Auth.", font=("Segoe UI", 11), fg=THEME['desc'], bg=THEME['bg']).pack(pady=(0, 15))

        form = tk.Frame(self, bg=THEME['bg'])
        form.pack(pady=5)
        tk.Label(form, text="Target URL:", font=("Segoe UI", 11), fg=THEME['fg'], bg=THEME['bg']).grid(row=0, column=0, sticky="e", pady=5)
        self.url_entry = tk.Entry(form, width=40, font=("Segoe UI", 11), bg=THEME['entry_bg'], fg=THEME['entry_fg'])
        self.url_entry.grid(row=0, column=1, pady=5, padx=10)
        ToolTip(self.url_entry, "URL of the target (e.g., http://example.com/protected)")

        tk.Label(form, text="Username:", font=("Segoe UI", 11), fg=THEME['fg'], bg=THEME['bg']).grid(row=1, column=0, sticky="e", pady=5)
        self.username_entry = tk.Entry(form, width=30, font=("Segoe UI", 11), bg=THEME['entry_bg'], fg=THEME['entry_fg'])
        self.username_entry.grid(row=1, column=1, pady=5, padx=10)
        ToolTip(self.username_entry, "Username to brute-force.")

        tk.Label(form, text="Wordlist Path:", font=("Segoe UI", 11), fg=THEME['fg'], bg=THEME['bg']).grid(row=2, column=0, sticky="e", pady=5)
        self.wordlist_entry = tk.Entry(form, width=30, font=("Segoe UI", 11), bg=THEME['entry_bg'], fg=THEME['entry_fg'])
        self.wordlist_entry.grid(row=2, column=1, pady=5, padx=10)
        ToolTip(self.wordlist_entry, "Path to a password wordlist file.")

        self.progress = ttk.Progressbar(self, orient="horizontal", length=400, mode="determinate")
        self.progress.pack(pady=(10, 0))

        brute_btn = tk.Button(self, text="Start Brute-Force", font=("Segoe UI", 12), bg=THEME['button_bg'], fg=THEME['button_fg'], activebackground=THEME['button_active_bg'], activeforeground=THEME['button_active_fg'], command=self.start_brute_force, relief=tk.RAISED, bd=2)
        brute_btn.pack(pady=10)
        ToolTip(brute_btn, "Start brute-forcing HTTP Basic Auth with the given wordlist.")

        self.result_box = scrolledtext.ScrolledText(self, width=60, height=16, font=("Consolas", 10), bg=THEME['result_bg'], fg=THEME['result_fg'])
        self.result_box.pack(pady=10)

    def start_brute_force(self):
        url = self.url_entry.get().strip()
        username = self.username_entry.get().strip()
        wordlist_path = self.wordlist_entry.get().strip()
        if not url or not username or not wordlist_path:
            messagebox.showerror("Input Error", "Please fill in all fields.")
            return
        try:
            with open(wordlist_path, 'r') as f:
                passwords = [line.strip() for line in f if line.strip()]
        except Exception as e:
            messagebox.showerror("File Error", f"Error reading wordlist: {e}")
            return
        self.result_box.delete(1.0, tk.END)
        self.result_box.insert(tk.END, f"Starting brute-force on {url} with username '{username}'...\n")
        self.progress['value'] = 0
        self.progress['maximum'] = len(passwords)
        self.update_idletasks()
        import requests
        from requests.auth import HTTPBasicAuth
        for idx, password in enumerate(passwords, 1):
            try:
                response = requests.get(url, auth=HTTPBasicAuth(username, password), timeout=5)
                if response.status_code == 200:
                    self.result_box.insert(tk.END, f"Success! Password found: {password}\n")
                    self.progress['value'] = 0
                    return
                else:
                    self.result_box.insert(tk.END, f"Tried: {password}\n")
            except Exception as e:
                self.result_box.insert(tk.END, f"Error: {e}\n")
            self.progress['value'] = idx
            self.update_idletasks()
        self.result_box.insert(tk.END, "Brute-force failed. No valid password found in wordlist.\n")
        self.progress['value'] = 0

if __name__ == "__main__":
    app = PentestToolkitGUI()
    app.mainloop() 