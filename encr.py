import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes

# --- XOR Cipher Implementation ---
def xor_encrypt_decrypt(text, key):
    """
    Encrypts or decrypts a string using a simple XOR cipher.
    XOR is its own inverse, so the same function can be used for both.

    Args:
        text (str): The string to be encrypted or decrypted.
        key (str): The key to use for XOR operation.

    Returns:
        str: The encrypted or decrypted string.
    """
