# AES-256 File Encryption/Decryption Tool

A robust Python application to encrypt and decrypt files using AES-256, with a user-friendly graphical interface.

## Features
- Secure AES-256 encryption and decryption
- Password-based key derivation (PBKDF2)
- Simple, intuitive GUI (Tkinter)

## Setup
1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Run the application:**
   ```bash
   python file_crypto_gui.py
   ```

## Usage
1. Launch the app.
2. Click **Browse** to select a file.
3. Enter a password (remember it! You need the same password to decrypt).
4. Click **Encrypt** to create an encrypted file (`.aes` extension), or **Decrypt** to restore the original file.
5. Status messages will appear at the bottom.

## Notes
- The password is never stored. Losing it means you cannot decrypt your files.
- Encrypted files have the `.aes` extension. Decrypted files have `.decrypted` appended.
- If decryption fails, check your password and file integrity.

## Troubleshooting
- If you see errors about missing modules, ensure you installed dependencies with `pip install -r requirements.txt`.
- Tkinter comes with most Python installations. If you have issues, check your Python setup.

## Security
- Uses PBKDF2 with SHA-256 and a random salt for key derivation.
- Uses AES-GCM for authenticated encryption.

---
**For any issues, please open an issue or contact the maintainer.** 