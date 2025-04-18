from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import math
import sys
import os

def entropy(bytes):
    counter = {}
    for x in bytes:
        if x in counter:
            counter[x] += 1
        else:
            counter[x] = 1
    total = sum(counter.values())
    return -(sum(x/total*math.log2(x/total) for x in counter.values()))

def mostly_printable(bytes):
    printable = sum(x >= 32 and x < 127 for x in bytes)
    return printable / len(bytes)

file_path = sys.argv[1]
with open(file_path, 'rb') as f:
    key = AESGCM.generate_key(256)
    cipher = AESGCM(key)
    encrypted_file = cipher.encrypt(os.urandom(12), f.read(), None)
    print(f"Entropy (Encrypted): {entropy(encrypted_file)} (Printability: {mostly_printable(encrypted_file) * 100}%)")
    f.seek(0)
    content = f.read()
    print(f"Entropy (Unencrypted): {entropy(content)} (Printability: {mostly_printable(content) * 100}%)")
