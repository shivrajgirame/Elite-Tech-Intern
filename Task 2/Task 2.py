import tkinter as tk
from tkinter import messagebox, scrolledtext
import requests
from bs4 import BeautifulSoup
import threading

# SQLi and XSS payloads
sql_payloads = ["' OR '1'='1", "'; DROP TABLE users;--", "' OR 1=1--"]
xss_payloads = ['<script>alert("XSS")</script>', '" onmouseover="alert(1)"']

# Main scan function (runs in background thread)
def scan_website_thread(url):
    set_status(f"🔍 Scanning {url}...")
    output.config(state='normal')
    output.delete('1.0', tk.END)
    output.insert(tk.END, f"🔍 Scanning {url}...\n\n")
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')

        if not forms:
            output.insert(tk.END, "No forms found on the page.\n")
            set_status("No forms found.")
            output.config(state='disabled')
            return

        found_vuln = False
        for form in forms:
            action = form.get('action')
            method = form.get('method', 'get').lower()
            form_url = url if not action else requests.compat.urljoin(url, action)
            inputs = form.find_all('input')

            for payload in sql_payloads + xss_payloads:
                data = {}
                for input_tag in inputs:
                    name = input_tag.get('name')
                    if name:
                        data[name] = payload

                if method == 'post':
                    res = requests.post(form_url, data=data)
                else:
                    res = requests.get(form_url, params=data)

                if payload in res.text:
                    vuln_type = "XSS" if "script" in payload else "SQL Injection"
                    output.insert(tk.END, f"🔴 Possible {vuln_type} found at: {form_url}\nPayload: {payload}\n\n")
                    output.tag_add('vuln', f'end-4l', f'end-2l')
                    found_vuln = True

        if not found_vuln:
            output.insert(tk.END, "✅ No vulnerabilities found with current payloads.\n")
        output.insert(tk.END, "\nScan complete.\n")
        set_status("✅ Scan complete.")
        output.config(state='disabled')

    except Exception as e:
        output.insert(tk.END, f"❌ Error: {e}\n")
        set_status("❌ Error occurred.")
        output.config(state='disabled')

# Start thread on button click
def start_scan():
    url = entry_url.get()
    if not url.startswith('http'):
        messagebox.showwarning("Invalid URL", "Please enter a valid URL starting with http or https")
        return
    set_status("Starting scan...")
    scan_thread = threading.Thread(target=scan_website_thread, args=(url,))
    scan_thread.start()

def set_status(msg):
    status_var.set(msg)

# Tkinter GUI
root = tk.Tk()
root.title("Web Vulnerability Scanner")
root.geometry("750x550")
root.resizable(False, False)

# Title
title_label = tk.Label(root, text="Web Vulnerability Scanner", font=("Arial", 20, "bold"), fg="#2c3e50")
title_label.pack(pady=(18, 5))

desc_label = tk.Label(root, text="Scan a website for basic SQL Injection and XSS vulnerabilities.", font=("Arial", 12), fg="#34495e")
desc_label.pack(pady=(0, 15))

# URL Entry Frame
url_frame = tk.Frame(root)
url_frame.pack(pady=5)

url_label = tk.Label(url_frame, text="Website URL:", font=("Arial", 11))
url_label.pack(side=tk.LEFT, padx=(0, 8))

entry_url = tk.Entry(url_frame, width=55, font=("Arial", 11))
entry_url.pack(side=tk.LEFT, padx=(0, 8))
entry_url.insert(0, "https://")

scan_btn = tk.Button(url_frame, text="Scan", command=start_scan, 
    bg="#6ee7b7", fg="#1a202c", font=("Arial", 13, "bold"), 
    width=12, padx=8, pady=4, relief=tk.RAISED, bd=3, activebackground="#34d399", activeforeground="#1a202c")
scan_btn.pack(side=tk.LEFT)

# Output Frame
output_frame = tk.Frame(root)
output_frame.pack(padx=15, pady=15, fill=tk.BOTH, expand=True)

output = scrolledtext.ScrolledText(output_frame, height=20, font=("Consolas", 11), wrap=tk.WORD, state='disabled')
output.pack(fill=tk.BOTH, expand=True)
output.tag_config('vuln', foreground='red', font=("Consolas", 11, "bold"))

# Status Bar
status_var = tk.StringVar()
status_var.set("Ready.")
status_bar = tk.Label(root, textvariable=status_var, bd=1, relief=tk.SUNKEN, anchor=tk.W, font=("Arial", 10), bg="#ecf0f1")
status_bar.pack(side=tk.BOTTOM, fill=tk.X)

# Tooltip for entry
try:
    import idlelib.tooltip as tooltip
    tooltip.Hovertip(entry_url, "Enter the full URL (including http/https) of the website to scan.")
except Exception:
    pass  # Tooltip is optional

root.mainloop()
