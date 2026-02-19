from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

# AES constants
SALT_SIZE = 16
KEY_SIZE = 32
IV_SIZE = 16
PBKDF2_ITERATIONS = 100000

def pad(data):
    padding_len = AES.block_size - len(data) % AES.block_size
    return data + bytes([padding_len]) * padding_len

def unpad(data):
    padding_len = data[-1]
    if padding_len < 1 or padding_len > AES.block_size:
        raise ValueError("Invalid padding.")
    if data[-padding_len:] != bytes([padding_len]) * padding_len:
        raise ValueError("Invalid padding bytes.")
    return data[:-padding_len]

def derive_key(password, salt):
    return PBKDF2(password.encode('utf-8'), salt, dkLen=KEY_SIZE, count=PBKDF2_ITERATIONS)

def encrypt_audio_with_password(input_audio_path, password, output_path):
    with open(input_audio_path, 'rb') as f:
        data = f.read()

    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(password, salt)
    iv = get_random_bytes(IV_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data))

    with open(output_path, 'wb') as f:
        f.write(salt)
        f.write(iv)
        f.write(ciphertext)

def decrypt_audio_with_password(enc_path, password, output_audio_path):
    with open(enc_path, 'rb') as f:
        salt = f.read(SALT_SIZE)
        iv = f.read(IV_SIZE)
        ciphertext = f.read()

    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    try:
        padded_data = cipher.decrypt(ciphertext)
        data = unpad(padded_data)
    except Exception:
        raise ValueError("Incorrect password or corrupt file.")

    with open(output_audio_path, 'wb') as f:
        f.write(data)
