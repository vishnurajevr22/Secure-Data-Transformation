from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

# Constants for AES Key Derivation and Encryption
SALT_SIZE = 16       # bytes
KEY_SIZE = 32        # 32 bytes = 256 bits AES key
IV_SIZE = 16         # Initialization Vector size for AES CBC mode
PBKDF2_ITERATIONS = 100000

def pad(data):
    """Apply PKCS#7 padding to data"""
    padding_len = AES.block_size - (len(data) % AES.block_size)
    return data + bytes([padding_len]) * padding_len

def unpad(data):
    """Remove PKCS#7 padding from data"""
    padding_len = data[-1]
    if padding_len < 1 or padding_len > AES.block_size:
        raise ValueError("Invalid padding.")
    if data[-padding_len:] != bytes([padding_len]) * padding_len:
        raise ValueError("Invalid padding bytes.")
    return data[:-padding_len]

def derive_key(password, salt):
    """
    Derives a cryptographic key from the password and salt using PBKDF2.
    """
    return PBKDF2(password, salt, dkLen=KEY_SIZE, count=PBKDF2_ITERATIONS)

def encrypt_audio_with_password(input_audio_path, password, output_path):
    """
    Encrypts the entire audio file using AES-256 CBC with a password.
    Saves the encrypted data as: salt + iv + ciphertext to output_path.
    """
    with open(input_audio_path, 'rb') as f:
        audio_data = f.read()

    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(password.encode('utf-8'), salt)
    iv = get_random_bytes(IV_SIZE)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(audio_data))

    with open(output_path, 'wb') as f:
        f.write(salt)
        f.write(iv)
        f.write(ciphertext)

def decrypt_audio_with_password(enc_file_path, password, output_audio_path):
    """
    Decrypts the encrypted audio file using AES-256 CBC with the password.
    Raises ValueError if password is incorrect or file corrupted.
    """
    with open(enc_file_path, 'rb') as f:
        salt = f.read(SALT_SIZE)
        iv = f.read(IV_SIZE)
        ciphertext = f.read()

    key = derive_key(password.encode('utf-8'), salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    try:
        padded_audio_data = cipher.decrypt(ciphertext)
        audio_data = unpad(padded_audio_data)
    except Exception:
        raise ValueError("Incorrect password or corrupt file.")

    with open(output_audio_path, 'wb') as f:
        f.write(audio_data)
