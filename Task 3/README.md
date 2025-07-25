# Penetration Testing Toolkit

A modular Python toolkit for penetration testing, featuring plug-and-play modules such as a Port Scanner and Brute-Forcer. Easily extensible for additional modules.

## Features
- **Port Scanner**: Scan target hosts for open TCP ports.
- **Brute-Forcer**: Perform dictionary attacks on services (e.g., SSH, HTTP Basic Auth).

## Installation
```bash
pip install -r requirements.txt
```

## Usage
```bash
python main.py
```
Follow the prompts to select and run a module.

## Extending
Add new modules in the `modules/` directory and update `main.py` to include them.

---

**For educational and authorized testing only.** 