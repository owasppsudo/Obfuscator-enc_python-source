import base64
import os
import marshal
import zlib
import lzma
import gzip
import bz2
import random
import string
import ast
import binascii
import hashlib
import time
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.fernet import Fernet
import base91  

def gk(password: str, salt: bytes, pepper: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA3_512(),
        length=64,
        salt=salt + pepper,
        iterations=1000000,
    )
    return kdf.derive(hashlib.sha256(password.encode()).digest())

def enccode(code: str, password: str) -> tuple:
    code_bytes = marshal.dumps(compile(code, "<obf>", "exec"))
    ccmp = zlib.compress(code_bytes, 9)
    ccmp = gzip.compress(ccmp)
    ccmp = lzma.compress(ccmp)
    ccmp = bz2.compress(ccmp)

    salt = os.urandom(32)
    pepper = os.urandom(16)
    key = gk(password, salt, pepper)
    nonce = os.urandom(12)
    chacha = Cipher(algorithms.ChaCha20(key[:32], nonce), mode=None)
    encryptor = chacha.encryptor()
    chacha_cipher = encryptor.update(ccmp)

    iv = os.urandom(16)
    aes_cipher = Cipher(algorithms.AES(key[32:]), modes.GCM(iv))
    encryptor = aes_cipher.encryptor()
    ciphertext = encryptor.update(chacha_cipher) + encryptor.finalize()
    tag = encryptor.tag

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    rsa_public = rsa_key.public_key()
    rsa_cipher = rsa_public.encrypt(ciphertext, asym_padding.OAEP(
        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))

    fernet_key = Fernet.gk()
    f = Fernet(fernet_key)
    final_cipher = f.encrypt(rsa_cipher)

    return salt, pepper, nonce, iv, tag, final_cipher, fernet_key, rsa_key.private_numbers().d.to_bytes(512, 'big')


def oblo(loader_code: str) -> str:
    tree = ast.parse(loader_code)
    var_map = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            if node.id not in var_map:
                var_map[node.id] = ''.join(random.choices(string.ascii_letters + string.digits + "_", k=30))
            node.id = var_map[node.id]

    junk_code = """
    def _{0}():
        _{1} = {2}; _{3} = lambda x: [x**{4} for x in range({5})]
        if _{1} > 0: return sum(_{3}(_{1})) + {6}
        else: raise ValueError('_{7}')
    try: [_{0}() for _ in range({8})]
    except: pass
    """.format(
        ''.join(random.choices(string.ascii_letters, k=15)),
        ''.join(random.choices(string.ascii_letters, k=10)),
        random.randint(1000, 10000),
        ''.join(random.choices(string.ascii_letters, k=12)),
        random.randint(2, 5),
        random.randint(50, 500),
        random.randint(1, 1000),
        ''.join(random.choices(string.ascii_letters, k=8)),
        random.randint(10, 50)
    )

    obfuscated = ast.unparse(tree)
    lines = obfuscated.split('\n')
    for _ in range(15):
        lines.insert(random.randint(0, len(lines)), junk_code)

    obfuscated = '\n'.join(lines)
    obfuscated = base91.encode(obfuscated.encode())
    obfuscated = binascii.hexlify(obfuscated)
    obfuscated = ''.join(c if random.random() > 0.1 else chr(ord(c) + 1) for c in obfuscated.decode())

    vm_code = f"""
    def vm_run(c):
        r = 0
        for i in range(len(c)):
            r += ord(c[i]) * {random.randint(1, 100)}
        return bytes.fromhex(c).decode()
    exec(vm_run('{obfuscated}'))
    """
    return vm_code


def prpf(input_file: str, password: str):
    with open(input_file, 'r', encoding='utf-8') as f:
        original_code = f.read()

    salt, pepper, nonce, iv, tag, ciphertext, fernet_key, rsa_private = enccode(original_code, password)

    salt_b91 = base91.encode(salt).decode()
    pepper_b91 = base91.encode(pepper).decode()
    nonce_b91 = base91.encode(nonce).decode()
    iv_b91 = base91.encode(iv).decode()
    tag_b91 = base91.encode(tag).decode()
    cipher_b91 = base91.encode(ciphertext).decode()
    fernet_b91 = base91.encode(fernet_key).decode()
    rsa_b91 = base91.encode(rsa_private).decode()

    loader = f"""import base64, os, marshal, zlib, lzma, gzip, bz2, sys, time
import base91
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as ap
from cryptography.fernet import Fernet
if hasattr(sys, 'gettrace') and sys.gettrace(): sys.exit(1)
def decrypt_and_run():
    t = time.time()
    if time.time() - t > 0.1: raise Exception("Debugger detected!")
    salt = base91.decode('{salt_b91}'.encode())
    pepper = base91.decode('{pepper_b91}'.encode())
    nonce = base91.decode('{nonce_b91}'.encode())
    iv = base91.decode('{iv_b91}'.encode())
    tag = base91.decode('{tag_b91}'.encode())
    ciphertext = base91.decode('{cipher_b91}'.encode())
    fernet_key = base91.decode('{fernet_b91}'.encode())
    rsa_private = int.from_bytes(base91.decode('{rsa_b91}'.encode()), 'big')
    password = input("Enter password: ")
    kdf = PBKDF2HMAC(algorithm=hashes.SHA3_512(), length=64, salt=salt+pepper, iterations=1000000)
    key = kdf.derive(hashlib.sha256(password.encode()).digest())
    f = Fernet(fernet_key)
    rsa_cipher = f.decrypt(ciphertext)
    rsa_key = rsa.RSAPrivateNumbers(
        p=1, q=1, d=rsa_private, p_inv=1, q_inv=1,
        public_numbers=rsa.RSAPublicNumbers(65537, rsa_private * 65537 + 1)
    ).private_key()
    aes_data = rsa_key.decrypt(rsa_cipher, ap.OAEP(mgf=ap.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    cipher = Cipher(algorithms.AES(key[32:]), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    chacha_data = decryptor.update(aes_data) + decryptor.finalize()
    chacha = Cipher(algorithms.ChaCha20(key[:32], nonce), mode=None)
    decryptor = chacha.decryptor()
    plaintext = decryptor.update(chacha_data)
    plaintext = bz2.decompress(plaintext)
    plaintext = lzma.decompress(plaintext)
    plaintext = gzip.decompress(plaintext)
    plaintext = zlib.decompress(plaintext)
    exec(marshal.loads(plaintext))
decrypt_and_run()
"""

    ob_lo = oblo(loader)
    output_file = os.path.splitext(input_file)[0] + '_enc.py'
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(ob_lo)
    
    print(f"save in: {output_file}")

if __name__ == "__main__":
    input_file = input("Enter the path to your Python file. ex: C:/path/to/test.py): ")
    password = input("enter your password")
    prpf(input_file, password)
