import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import threading
import tkinter as tk
from tkinter import scrolledtext

# Common payloads for testing
SQLI_PAYLOADS = ["' OR '1'='1", "\" OR \"1\"=\"1", "'--", "\"--"]
XSS_PAYLOADS = ['<script>alert(1)</script>', '\"><svg/onload=alert(1)>']


def get_forms(url):
    """Extract all forms from a web page."""
    soup = BeautifulSoup(requests.get(url).content, "html.parser")
    return soup.find_all("form")


def get_form_details(form):
    """Extract form details: action, method, inputs."""
    details = {}
    action = form.attrs.get("action", "")
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details


def submit_form(form_details, url, value):
    target_url = urljoin(url, form_details["action"])
    data = {}
    for input in form_details["inputs"]:
        if input["type"] == "text" or input["type"] == "search":
            data[input["name"]] = value
        else:
            data[input["name"]] = "test"
    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    else:
        return requests.get(target_url, params=data)


def scan_sql_injection(url, log_func):
    log_func(f"\n[+] Scanning {url} for SQL Injection...\n")
    try:
        forms = get_forms(url)
        for form in forms:
            form_details = get_form_details(form)
            for payload in SQLI_PAYLOADS:
                response = submit_form(form_details, url, payload)
                if ("syntax error" in response.text.lower() or
                    "mysql" in response.text.lower() or
                    "you have an error in your sql syntax" in response.text.lower()):
                    log_func(f"[!] Possible SQL Injection vulnerability detected in form: {form_details}\n")
                    break
    except Exception as e:
        log_func(f"[!] Error during SQL Injection scan: {e}\n")


def scan_xss(url, log_func):
    log_func(f"\n[+] Scanning {url} for XSS...\n")
    try:
        forms = get_forms(url)
        for form in forms:
            form_details = get_form_details(form)
            for payload in XSS_PAYLOADS:
                response = submit_form(form_details, url, payload)
                if payload in response.text:
                    log_func(f"[!] Possible XSS vulnerability detected in form: {form_details}\n")
                    break
    except Exception as e:
        log_func(f"[!] Error during XSS scan: {e}\n")


def run_scan(url, log_func):
    scan_sql_injection(url, log_func)
    scan_xss(url, log_func)
    log_func("\n[+] Scan complete.\n")


def start_scan_thread(url, log_func):
    thread = threading.Thread(target=run_scan, args=(url, log_func))
    thread.start()


def launch_gui():
    root = tk.Tk()
    root.title("Web Vulnerability Scanner")
    root.geometry("700x500")

    tk.Label(root, text="Enter URL to scan:").pack(pady=5)
    url_entry = tk.Entry(root, width=60)
    url_entry.pack(pady=5)

    result_box = scrolledtext.ScrolledText(root, width=80, height=25)
    result_box.pack(pady=10)

    def log_func(msg):
        result_box.insert(tk.END, msg)
        result_box.see(tk.END)
        root.update_idletasks()

    def on_scan():
        result_box.delete(1.0, tk.END)
        url = url_entry.get().strip()
        if url:
            start_scan_thread(url, log_func)
        else:
            log_func("[!] Please enter a valid URL.\n")

    scan_btn = tk.Button(root, text="Start Scan", command=on_scan)
    scan_btn.pack(pady=5)

    root.mainloop()

if __name__ == "__main__":
    launch_gui()
