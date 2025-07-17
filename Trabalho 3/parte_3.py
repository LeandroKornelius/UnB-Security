import hashlib

from parte_1 import rsa_encrypt, load_key
from parte_2 import mgf1


def emsa_pss_verify(message, em, em_len, hash_func=hashlib.sha3_256, salt_len=32):
    h_len = hash_func().digest_size
    if em_len < h_len + salt_len + 2:
        return False

    if em[-1] != 0xbc:
        return False

    masked_db = em[:em_len - h_len - 1]
    h = em[em_len - h_len - 1:-1]

    # Remove mask
    db_mask = mgf1(h, em_len - h_len - 1, hash_func)
    db = bytes(x ^ y for x, y in zip(masked_db, db_mask))

    # Ignores the highest bits of the first byte
    num_unused_bits = 8 * em_len - (8 * em_len - 1)
    db = bytes([db[0] & (0xFF >> num_unused_bits)]) + db[1:]

    # Verifies padding and extracts salt
    ps_len = em_len - h_len - salt_len - 2
    if not db[:ps_len] == b'\x00' * ps_len or db[ps_len] != 0x01:
        return False

    salt = db[-salt_len:]

    # Reconstructs h
    m_hash = hash_func(message).digest()
    m_prime = b'\x00' * 8 + m_hash + salt
    h_prime = hash_func(m_prime).digest()

    return h == h_prime


def verify_signature(message, signature, public_key):
    e, n = public_key
    em_len = (n.bit_length() + 7) // 8
    if len(signature) != em_len:
        raise ValueError("Tamanho da assinatura inválido.")

    signature_int = int.from_bytes(signature, byteorder='big')
    em_int = rsa_encrypt(signature_int, public_key)
    em = em_int.to_bytes(em_len, byteorder='big')

    return emsa_pss_verify(message, em, em_len)


def verify_file_signature(message_path, signature_path, pub_key_path):
    import base64

    public_key = load_key(pub_key_path)

    with open(message_path, "rb") as f:
        message = f.read()

    with open(signature_path, "rb") as f:
        signature = base64.b64decode(f.read())

    valid = verify_signature(message, signature, public_key)
    if valid:
        print("Assinatura VÁLIDA!")
    else:
        print("Assinatura INVÁLIDA!")
