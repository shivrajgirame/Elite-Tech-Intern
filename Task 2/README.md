# Web Vulnerability Scanner

A simple, user-friendly desktop application built with Python and Tkinter to scan websites for basic SQL Injection and Cross-Site Scripting (XSS) vulnerabilities.

## Features
- **Graphical User Interface:** Clean, modern, and easy to use.
- **Automated Scanning:** Tests all forms on a given web page for common SQLi and XSS payloads.
- **Detailed Output:** Highlights possible vulnerabilities and provides scan status updates.
- **Status Bar:** Shows real-time scan progress and results.

## Requirements
- Python 3.7+
- The following Python packages:
  - `tkinter` (usually included with Python)
  - `requests`
  - `beautifulsoup4`

## Installation
1. Clone or download this repository.
2. Install the required packages:
   ```bash
   pip install requests beautifulsoup4
   ```

## Usage
1. Run the application:
   ```bash
   python Task\ 2.py
   ```
2. Enter the full URL (including `http` or `https`) of the website you want to scan.
3. Click the **Scan** button.
4. View the results in the output area. Vulnerabilities (if found) will be highlighted in red.

## Notes
- The scanner uses a small set of common SQL Injection and XSS payloads. It is intended for educational and demonstration purposes only.
- This tool does **not** guarantee detection of all vulnerabilities and should **not** be used for malicious purposes.
- Always have permission before scanning any website.

## Limitations
- Only scans forms present on the initial page (does not follow links or handle JavaScript-heavy sites).
- Payloads are basic and may not bypass advanced security measures.

## License
This project is for educational use only. 