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
    # Ensure key is at least as long as the text for simplicity, or repeat it.
    # For this demo, we'll repeat the key if it's shorter.
    extended_key = (key * (len(text) // len(key) + 1))[:len(text)]
    
    result_chars = []
    for i in range(len(text)):
        # XOR the ASCII values of the characters
        result_chars.append(chr(ord(text[i]) ^ ord(extended_key[i])))
    
    return "".join(result_chars)

def run_xor_demo():
    print("\n--- XOR Cipher Demo ---")
    print("WARNING: XOR cipher is for demonstration/educational purposes only. DO NOT use for real security.")

    message = input("Enter the string you wish to encrypt: ")
    key = input("Enter the XOR key (any string): ")

    if not key:
        print("Key cannot be empty. Aborting XOR demo.")
        return

    # Encrypt
    encrypted_message = xor_encrypt_decrypt(message, key)
    print(f"\nOriginal message: '{message}'")
    print(f"XOR Key used: '{key}'")
    print(f"Encrypted message (raw characters): '{encrypted_message}'")

    # Note: Displaying raw characters might show unprintable characters.
    # For better display, you might want to hex-encode it, but for simplicity, we'll keep it raw.
    print(f"Encrypted message (hex representation): {encrypted_message.encode().hex()}")

    # Decrypt
    decrypt_choice = input("Do you want to decrypt this message now? (yes/no): ").lower()
    if decrypt_choice == 'yes':
        # To decrypt, we use the same function with the same key
        decrypted_message = xor_encrypt_decrypt(encrypted_message, key)
        print(f"Decrypted message: '{decrypted_message}'")
    else:
        print("Skipping decryption.")

# --- Fernet Encryption Demo ---
# Fernet key management functions
FERNET_KEY_FILE = "fernet_secret.key"
