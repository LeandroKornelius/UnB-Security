import random
from utils.miller_rabin import isPrime
from math import gcd
import base64

def generate_large_prime(bits=2048, k=10):
    while True:
        # Generates random number with LSB and MSB as 1
        candidate = random.getrandbits(bits) | (1 << bits - 1) | 1
        if isPrime(candidate, k): # Checks if is prime using Miller Rabin
            return candidate

def extended_gcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = extended_gcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = extended_gcd(a, m)
    if g!= 1:
        raise Exception('Inverso modular nao existe')
    return x % m

def generate_keypair(bits=2048):
    # Finds p
    p = generate_large_prime(bits)
    q = generate_large_prime(bits)
    while p == q:
        q = generate_large_prime(bits)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    if gcd(e, phi) != 1:
        e = 3
        while gcd(e, phi) != 1:
            e += 2

    d = modinv(e, phi)

    public_key = (e, n)
    private_key = (d, n)

    return public_key, private_key

def save_key(key, filename):
    encoded = base64.b64encode(f"{key[0]},{key[1]}".encode())
    with open(filename, 'wb') as f:
        f.write(encoded)

def load_key(filename):
    with open(filename, 'rb') as f:
        data = base64.b64decode(f.read()).decode()
        parts = data.split(",")
        return (int(parts[0]), int(parts[1]))

def rsa_encrypt(message_int, public_key):
    e, n = public_key
    return pow(message_int, e, n)

def rsa_decrypt(cipher_int, private_key):
    d, n = private_key
    return pow(cipher_int, d, n)


