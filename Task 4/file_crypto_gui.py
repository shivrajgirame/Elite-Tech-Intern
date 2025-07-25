import tkinter as tk
from tkinter import filedialog, messagebox
import tkinter.simpledialog as simpledialog
import os
from file_crypto import encrypt_file, decrypt_file

class FileCryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AES-256 File Encryptor/Decryptor")
        self.root.geometry("400x250")
        self.file_path = None
        self.create_widgets()

    def create_widgets(self):
        self.label = tk.Label(self.root, text="Select a file to encrypt or decrypt:")
        self.label.pack(pady=10)

        self.select_btn = tk.Button(self.root, text="Browse", command=self.browse_file)
        self.select_btn.pack(pady=5)

        self.file_label = tk.Label(self.root, text="No file selected")
        self.file_label.pack(pady=5)

        self.pw_label = tk.Label(self.root, text="Enter password:")
        self.pw_label.pack(pady=5)
        self.password_entry = tk.Entry(self.root, show="*", width=30)
        self.password_entry.pack(pady=5)

        self.encrypt_btn = tk.Button(self.root, text="Encrypt", command=self.encrypt)
        self.encrypt_btn.pack(pady=5)
        self.decrypt_btn = tk.Button(self.root, text="Decrypt", command=self.decrypt)
        self.decrypt_btn.pack(pady=5)

        self.status_label = tk.Label(self.root, text="", fg="blue")
        self.status_label.pack(pady=10)

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_path = file_path
            self.file_label.config(text=os.path.basename(file_path))
        else:
            self.file_label.config(text="No file selected")

    def encrypt(self):
        if not self.file_path:
            messagebox.showerror("Error", "No file selected.")
            return
        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "Password required.")
            return
        if not messagebox.askyesno("Overwrite File?", f"This will overwrite {os.path.basename(self.file_path)}. Continue?"):
            return
        try:
            encrypt_file(self.file_path, self.file_path, password)
            self.status_label.config(text=f"Encrypted {os.path.basename(self.file_path)}", fg="green")
            messagebox.showinfo("Encrypted", "The file is encrypted. Please use this application and enter the password to access it.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt(self):
        if not self.file_path:
            messagebox.showerror("Error", "No file selected.")
            return
        password = simpledialog.askstring("Password Required", "Enter password to decrypt:", show="*")
        if not password:
            messagebox.showerror("Error", "Password required.")
            return
        if not messagebox.askyesno("Overwrite File?", f"This will overwrite {os.path.basename(self.file_path)}. Continue?"):
            return
        try:
            decrypt_file(self.file_path, self.file_path, password)
            self.status_label.config(text=f"Decrypted {os.path.basename(self.file_path)}", fg="green")
        except Exception as e:
            messagebox.showerror("Error", str(e))

def main():
    root = tk.Tk()
    app = FileCryptoApp(root)
    root.mainloop()

if __name__ == "__main__":
    main() 