import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

backend = default_backend()

# Constants
SALT_SIZE = 16
KEY_SIZE = 32  # 256 bits
NONCE_SIZE = 12  # For AES-GCM
ITERATIONS = 100_000


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a secret key from the given password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
        backend=backend
    )
    return kdf.derive(password.encode())


def encrypt_file(input_path: str, output_path: str, password: str):
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)

    with open(input_path, 'rb') as f:
        data = f.read()
    encrypted = aesgcm.encrypt(nonce, data, None)

    with open(output_path, 'wb') as f:
        # Write salt + nonce + ciphertext
        f.write(salt + nonce + encrypted)


def decrypt_file(input_path: str, output_path: str, password: str):
    with open(input_path, 'rb') as f:
        file_data = f.read()
    salt = file_data[:SALT_SIZE]
    nonce = file_data[SALT_SIZE:SALT_SIZE+NONCE_SIZE]
    ciphertext = file_data[SALT_SIZE+NONCE_SIZE:]
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    try:
        decrypted = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as e:
        raise ValueError("Decryption failed. Possibly wrong password or corrupted file.") from e
    with open(output_path, 'wb') as f:
        f.write(decrypted) 