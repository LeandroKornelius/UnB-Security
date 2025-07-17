import hashlib
import os
from parte_1 import rsa_decrypt
import base64

def mgf1(seed, mask_len, hash_func=hashlib.sha3_256):
    # Generates mask of len mask_len using MGF1 based on SHA-3
    counter = 0
    output=b''

    while len(output) < mask_len:
        c = counter.to_bytes(4, byteorder='big')
        output += hash_func(seed + c).digest()
        counter += 1

    return output[:mask_len]

def emsa_pss_encode(message, em_len, hash_func=hashlib.sha3_256, salt_len=32):
    h_len = hash_func().digest_size
    if em_len < h_len + salt_len + 2:
        raise ValueError('em_len pequeno')

    # Message hash
    m_hash = hash_func(message).digest()

    # Random salt
    salt = os.urandom(salt_len)

    m_prime = b'\x00' * 8 + m_hash + salt
    h = hash_func(m_prime).digest()

    # Generates mask
    ps = b'\x00' * (em_len - salt_len - h_len - 2)
    db = ps + b'\x01' + salt
    db_mask = mgf1(h, em_len - h_len - 1, hash_func)
    masked_db = bytes(x ^ y for x, y in zip(db, db_mask))

    em = masked_db + h + b'\xbc'
    return em

def sign_message(message, private_key):
    d, n = private_key
    em = emsa_pss_encode(message, (n.bit_length() + 7) // 8)

    em_int = int.from_bytes(em, byteorder='big')
    signature_int = rsa_decrypt(em_int, private_key)

    sig_len = (n.bit_length() + 7) // 8
    signature = signature_int.to_bytes(sig_len, byteorder='big')
    return signature

def save_signature(signature: bytes, filename: str):
    with open(filename, 'wb') as f:
        f.write(base64.b64encode(signature))

def load_signature(filename: str) -> bytes:
    with open(filename, 'rb') as f:
        return base64.b64decode(f.read())



