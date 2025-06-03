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

def generate_fernet_key():
    """Generates a Fernet key and saves it to a file."""
    key = Fernet.generate_key()
    with open(FERNET_KEY_FILE, "wb") as key_file:
        key_file.write(key)
    print(f"Fernet key generated and saved to '{FERNET_KEY_FILE}'")
    return key

def load_fernet_key():
    """Loads a Fernet key from a file."""
    if not os.path.exists(FERNET_KEY_FILE):
        return None
    with open(FERNET_KEY_FILE, "rb") as key_file:
        key = key_file.read()
    print(f"Loaded Fernet key from '{FERNET_KEY_FILE}'")
    return key

def run_fernet_demo():
    print("\n--- Fernet Encryption Demo ---")
    print("Fernet is a high-level symmetric encryption scheme, part of the 'cryptography' library.")
    print("It provides authenticated encryption, ensuring both confidentiality and integrity.")

    # Load or generate Fernet key
    key = load_fernet_key()
    if key is None:
        key = generate_fernet_key()

    f = Fernet(key)

    message = input("Enter the string you wish to encrypt: ")
    
    # Encrypt
    # Fernet requires bytes, so encode the string
    encrypted_data = f.encrypt(message.encode('utf-8'))
    print(f"\nOriginal message: '{message}'")
    print(f"Encrypted message (base64 encoded): {encrypted_data.decode('utf-8')}")

    # Decrypt
    decrypt_choice = input("Do you want to decrypt this message now? (yes/no): ").lower()
    if decrypt_choice == 'yes':
        try:
            # Decrypt returns bytes, so decode to string
            decrypted_data = f.decrypt(encrypted_data).decode('utf-8')
            print(f"Decrypted message: '{decrypted_data}'")
        except Exception as e:
            print(f"Error during decryption: {e}. This might happen if the key is incorrect or data is tampered.")
    else:
        print("Skipping decryption.")

# --- AES Encryption Demo (CBC Mode with PKCS7 Padding) ---
# AES key and IV management (for demo purposes, generated on the fly)
# In a real application, these would be managed securely.

def aes_encrypt(plaintext, key, iv):
    """
    Encrypts plaintext using AES in CBC mode with PKCS7 padding.

    Args:
        plaintext (bytes): The data to encrypt.
        key (bytes): The AES key (16, 24, or 32 bytes for AES-128, 192, 256).
        iv (bytes): The Initialization Vector (16 bytes for AES).

    Returns:
        bytes: The encrypted ciphertext.
    """
    # Create a padder for PKCS7 padding
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    # Create an AES cipher object in CBC mode with the given key and IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Encrypt the padded data
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext

def aes_decrypt(ciphertext, key, iv):
    """
    Decrypts ciphertext using AES in CBC mode with PKCS7 padding.

    Args:
        ciphertext (bytes): The data to decrypt.
        key (bytes): The AES key.
        iv (bytes): The Initialization Vector.

    Returns:
        bytes: The decrypted plaintext.
    """
    # Create an AES cipher object in CBC mode with the given key and IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Create an unpadder for PKCS7 padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    unpadded_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    return unpadded_data

def run_aes_demo():
    print("\n--- AES Encryption Demo (CBC Mode) ---")
    print("AES is a widely used symmetric block cipher. This demo uses AES-256 in CBC mode.")
    print("It requires a key and an Initialization Vector (IV).")

    # Generate a random 256-bit key (32 bytes) and a 128-bit IV (16 bytes)
    # These should be securely generated and managed in a real application.
    key = os.urandom(32) # AES-256 key
    iv = os.urandom(16)  # Initialization Vector for CBC mode

    print(f"\nGenerated AES Key (hex): {key.hex()}")
    print(f"Generated AES IV (hex): {iv.hex()}")
    print("NOTE: For real applications, securely store and transmit the key and IV.")

    message = input("Enter the string you wish to encrypt: ")
    
    # Encrypt
    # AES requires bytes, so encode the string
    encrypted_data = aes_encrypt(message.encode('utf-8'), key, iv)
    print(f"\nOriginal message: '{message}'")
    print(f"Encrypted message (hex encoded): {encrypted_data.hex()}")

    # Decrypt
    decrypt_choice = input("Do you want to decrypt this message now? (yes/no): ").lower()
    if decrypt_choice == 'yes':
        try:
            # Decrypt returns bytes, so decode to string
            decrypted_data = aes_decrypt(encrypted_data, key, iv).decode('utf-8')
            print(f"Decrypted message: '{decrypted_data}'")
        except Exception as e:
            print(f"Error during decryption: {e}. This might happen if the key/IV are incorrect or data is tampered.")
    else:
        print("Skipping decryption.")

# --- Main Program Loop ---
def main():
    print("Welcome to the Python Encryption Demos!")
    print("Choose an encryption method to demonstrate.")

    while True:
        print("\n--- Main Menu ---")
        print("1. XOR Cipher (Educational/Simple)")
        print("2. Fernet Encryption (Recommended for General Use)")
        print("3. AES Encryption (Advanced Control)")
        print("4. Quit")

        choice = input("Enter your choice (1-4): ")

        if choice == '1':
            run_xor_demo()
        elif choice == '2':
            run_fernet_demo()
        elif choice == '3':
            run_aes_demo()
        elif choice == '4':
            print("Exiting encryption demos. Goodbye!")
            break
        else:
            print("Invalid choice. Please enter a number between 1 and 4.")

if __name__ == "__main__":
    # Ensure 'cryptography' library is installed: pip install cryptography
    try:
        # Test if cryptography library is available
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives.ciphers import Cipher
    except ImportError:
        print("Error: The 'cryptography' library is not installed.")
        print("Please install it using: pip install cryptography")
        exit()
    
    main()
