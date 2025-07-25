import hashlib
import os
import json
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import scrolledtext
from tkinter import ttk

HASH_DB_FILE = 'hash_database.json'

def calculate_hash(filepath, algorithm='sha256'):
    hasher = hashlib.new(algorithm)
    try:
        with open(filepath, 'rb') as f:
            while chunk := f.read(4096):
                hasher.update(chunk)
        return hasher.hexdigest()
    except FileNotFoundError:
        return None

def load_hash_database():
    if os.path.exists(HASH_DB_FILE):
        with open(HASH_DB_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_hash_database(db):
    with open(HASH_DB_FILE, 'w') as f:
        json.dump(db, f, indent=4)

def monitor_directory(directory, log_output):
    hash_db = load_hash_database()
    updated_db = {}

    log_output.insert(tk.END, f"\n[INFO] Scanning directory: {directory}\n")
    for root, _, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            file_hash = calculate_hash(filepath)

            updated_db[filepath] = file_hash

            if filepath not in hash_db:
                log_output.insert(tk.END, f"[NEW FILE] {filepath}\n")
            elif hash_db[filepath] != file_hash:
                log_output.insert(tk.END, f"[MODIFIED] {filepath}\n")
            else:
                log_output.insert(tk.END, f"[UNCHANGED] {filepath}\n")

    removed_files = set(hash_db.keys()) - set(updated_db.keys())
    for filepath in removed_files:
        log_output.insert(tk.END, f"[REMOVED] {filepath}\n")

    save_hash_database(updated_db)
    log_output.insert(tk.END, "\n[INFO] Scan complete.\n")
    log_output.see(tk.END)

# GUI Application
def start_gui():
    def browse_directory():
        folder_selected = filedialog.askdirectory()
        if folder_selected:
            dir_entry.delete(0, tk.END)
            dir_entry.insert(0, folder_selected)

    def start_scan():
        directory = dir_entry.get().strip()
        if not os.path.isdir(directory):
            messagebox.showerror("Invalid Directory", "Please select a valid directory.")
            return
        log_output.config(state='normal')
        log_output.delete('1.0', tk.END)
        monitor_directory(directory, log_output)
        log_output.config(state='disabled')

    def on_enter(e):
        e.widget['background'] = '#388e3c'
    def on_leave(e):
        e.widget['background'] = '#4CAF50'

    root = tk.Tk()
    root.title("File Integrity Monitor")
    root.geometry("750x540")
    root.resizable(False, False)
    root.configure(bg="#f4f6fb")

    style = ttk.Style()
    style.theme_use('clam')
    style.configure('TLabel', background="#f4f6fb", font=("Segoe UI", 12))
    style.configure('TEntry', font=("Segoe UI", 11))
    style.configure('TButton', font=("Segoe UI", 11), padding=6)
    style.configure('Header.TLabel', font=("Segoe UI", 20, "bold"), background="#283593", foreground="white")

    # Header
    header = ttk.Label(root, text="File Integrity Monitor", style='Header.TLabel', anchor='center')
    header.pack(fill=tk.X, pady=(0, 15))

    # Directory selection
    dir_frame = tk.Frame(root, bg="#f4f6fb")
    dir_frame.pack(pady=10)

    dir_label = ttk.Label(dir_frame, text="Select Directory to Monitor:")
    dir_label.pack(side=tk.LEFT, padx=(0, 8))

    dir_entry = ttk.Entry(dir_frame, width=50)
    dir_entry.pack(side=tk.LEFT, padx=5)

    browse_btn = ttk.Button(dir_frame, text="Browse", command=browse_directory)
    browse_btn.pack(side=tk.LEFT, padx=5)

    # Start scan button (customized for color and hover)
    scan_btn = tk.Button(root, text="Start Scan", font=("Segoe UI", 13, "bold"), command=start_scan,
                        bg="#4CAF50", fg="white", activebackground="#388e3c", activeforeground="white",
                        relief=tk.FLAT, bd=0, padx=20, pady=6, cursor="hand2")
    scan_btn.pack(pady=15)
    scan_btn.bind("<Enter>", on_enter)
    scan_btn.bind("<Leave>", on_leave)

    # Log output area
    log_frame = tk.Frame(root, bg="#f4f6fb")
    log_frame.pack(pady=10, fill=tk.BOTH, expand=True)

    log_output = scrolledtext.ScrolledText(log_frame, width=90, height=20, font=("Consolas", 11),
                                           bg="#e8eaf6", fg="#1a237e", bd=0, relief=tk.FLAT, wrap=tk.WORD)
    log_output.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
    log_output.config(state='disabled')

    # Footer
    footer = ttk.Label(root, text="© 2024 Elite-Tech | Task 1", font=("Segoe UI", 9), anchor='center', background="#f4f6fb", foreground="#757575")
    footer.pack(side=tk.BOTTOM, fill=tk.X, pady=(0, 5))

    root.mainloop()

# Run the GUI
if __name__ == "__main__":
    start_gui()
