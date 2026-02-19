from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from PIL import Image

SALT_SIZE = 16
KEY_SIZE = 32
IV_SIZE = 16
PBKDF2_ITERATIONS = 100000

def pad(msg_bytes):
    padding_len = AES.block_size - len(msg_bytes) % AES.block_size
    return msg_bytes + bytes([padding_len]) * padding_len

def unpad(msg_bytes):
    padding_len = msg_bytes[-1]
    if padding_len < 1 or padding_len > AES.block_size:
        raise ValueError('Invalid padding')
    if msg_bytes[-padding_len:] != bytes([padding_len]) * padding_len:
        raise ValueError('Invalid padding bytes')
    return msg_bytes[:-padding_len]

def derive_key(password, salt):
    return PBKDF2(password.encode('utf-8'), salt, dkLen=KEY_SIZE, count=PBKDF2_ITERATIONS)

def encrypt_message(text, password):
    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(password, salt)
    iv = get_random_bytes(IV_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    msg_bytes = text.encode('utf-8')
    ciphertext = cipher.encrypt(pad(msg_bytes))
    return salt + iv + ciphertext

def decrypt_message(enc_bytes, password):
    if len(enc_bytes) < SALT_SIZE + IV_SIZE + 16:
        raise ValueError("Encrypted message too short.")
    salt = enc_bytes[:SALT_SIZE]
    iv = enc_bytes[SALT_SIZE:SALT_SIZE+IV_SIZE]
    ciphertext = enc_bytes[SALT_SIZE+IV_SIZE:]
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    msg_bytes = cipher.decrypt(ciphertext)
    return unpad(msg_bytes).decode('utf-8')

def bytes_to_bits(data_bytes):
    return ''.join(format(byte, '08b') for byte in data_bytes)

def bits_to_bytes(bits):
    return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))

import struct

def hide_encrypted_text_in_image(cover_img_path, text, password, output_img_path):
    enc_bytes = encrypt_message(text, password)
    length_bytes = struct.pack('>I', len(enc_bytes))  # 4 bytes unsigned int, big-endian
    full_bytes = length_bytes + enc_bytes
    enc_bits = bytes_to_bits(full_bytes)

    img = Image.open(cover_img_path).convert('RGB')
    pixels = list(img.getdata())

    if len(enc_bits) > len(pixels) * 3:
        raise ValueError("Message too large for cover image.")

    bits_idx = 0
    new_pixels = []

    for pixel in pixels:
        r, g, b = pixel
        rgb = []
        for channel in (r, g, b):
            if bits_idx < len(enc_bits):
                rgb.append((channel & 0xFE) | int(enc_bits[bits_idx]))
                bits_idx += 1
            else:
                rgb.append(channel)
        new_pixels.append(tuple(rgb))

    img.putdata(new_pixels)
    img.save(output_img_path)


import struct

def extract_and_decrypt_text_from_image(stego_img_path, password):
    img = Image.open(stego_img_path).convert('RGB')
    pixels = list(img.getdata())

    bits = ''

    # Extract first 32 bits (4 bytes) → length of encrypted message
    for pixel in pixels:
        for channel in pixel:
            bits += str(channel & 1)
            if len(bits) >= 32:  # 32 bits = 4 bytes
                break
        if len(bits) >= 32:
            break

    length_bytes = bits_to_bytes(bits[:32])
    message_length = struct.unpack('>I', length_bytes)[0]

    # Now extract full encrypted message bits: length (32) + message_length * 8 bits
    total_bits_needed = 32 + message_length * 8
    bits = ''
    for pixel in pixels:
        for channel in pixel:
            bits += str(channel & 1)
            if len(bits) >= total_bits_needed:
                break
        if len(bits) >= total_bits_needed:
            break

    enc_bytes = bits_to_bytes(bits[32:total_bits_needed])

    try:
        recovered = decrypt_message(enc_bytes, password)
        return recovered
    except Exception:
        raise ValueError('Decryption failed: Incorrect password or no hidden message found.')
