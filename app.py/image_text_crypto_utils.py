from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import base64

SALT_SIZE = 16
KEY_SIZE = 32  # AES-256
IV_SIZE = 16
PBKDF2_ITERATIONS = 100000

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
    return PBKDF2(password.encode('utf-8'), salt, dkLen=KEY_SIZE, count=PBKDF2_ITERATIONS)

def encrypt_image_to_text(image_path, password):
    with open(image_path, 'rb') as f:
        img_bytes = f.read()
    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(password, salt)
    iv = get_random_bytes(IV_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    enc_bytes = cipher.encrypt(pad(img_bytes))
    encoded_text = base64.b64encode(salt + iv + enc_bytes).decode('utf-8')
    return encoded_text

def decrypt_text_to_image(encoded_text, password, output_image_path):
    combined = base64.b64decode(encoded_text)
    salt = combined[:SALT_SIZE]
    iv = combined[SALT_SIZE:SALT_SIZE+IV_SIZE]
    enc_bytes = combined[SALT_SIZE+IV_SIZE:]
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        img_bytes = unpad(cipher.decrypt(enc_bytes))
    except Exception:
        raise ValueError("Incorrect password or corrupt input text.")
    with open(output_image_path, 'wb') as f:
        f.write(img_bytes)
