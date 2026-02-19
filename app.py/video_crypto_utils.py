from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

SALT_SIZE = 16
KEY_SIZE = 32       # AES-256
IV_SIZE = 16
PBKDF2_ITERATIONS = 100_000

def pad(data):
    padding_len = AES.block_size - (len(data) % AES.block_size)
    return data + bytes([padding_len]) * padding_len

def unpad(data):
    padding_len = data[-1]
    if padding_len < 1 or padding_len > AES.block_size:
        raise ValueError("Invalid padding.")
    if data[-padding_len:] != bytes([padding_len]) * padding_len:
        raise ValueError("Invalid padding bytes.")
    return data[:-padding_len]

def derive_key(password, salt):
    return PBKDF2(password, salt, dkLen=KEY_SIZE, count=PBKDF2_ITERATIONS)

def encrypt_video_with_password(input_video_path, password, output_path):
    with open(input_video_path, 'rb') as f:
        video_data = f.read()

    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(password.encode('utf-8'), salt)
    iv = get_random_bytes(IV_SIZE)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(video_data))

    with open(output_path, 'wb') as f:
        f.write(salt)
        f.write(iv)
        f.write(ciphertext)

def decrypt_video_with_password(enc_file_path, password, output_video_path):
    with open(enc_file_path, 'rb') as f:
        salt = f.read(SALT_SIZE)
        iv = f.read(IV_SIZE)
        ciphertext = f.read()

    key = derive_key(password.encode('utf-8'), salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    try:
        padded_video_data = cipher.decrypt(ciphertext)
        video_data = unpad(padded_video_data)
    except Exception:
        raise ValueError("Incorrect password or corrupt file.")

    with open(output_video_path, 'wb') as f:
        f.write(video_data)
