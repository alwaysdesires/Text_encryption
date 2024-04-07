from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from cryptography.hazmat.primitives import serialization, padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding

def generate_aes_key():
    return get_random_bytes(16)  # 16 bytes for AES-128 key, adjust as needed for AES-192 or AES-256

def generate_des_key():
    return get_random_bytes(8)   # 8 bytes for DES key

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def aes_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(pad(plaintext.encode('utf-8'), AES.block_size))
    return ciphertext, cipher.nonce, tag

def aes_decrypt(key, nonce, ciphertext, tag):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode('utf-8')

def des_encrypt(key, plaintext):
    cipher = DES.new(key, DES.MODE_ECB)
    padded_plaintext = pad(plaintext.encode('utf-8'), DES.block_size)
    return cipher.encrypt(padded_plaintext)

def des_decrypt(key, ciphertext):
    cipher = DES.new(key, DES.MODE_ECB)
    padded_plaintext = cipher.decrypt(ciphertext)
    return padded_plaintext.decode('utf-8').rstrip('\0')

def rsa_encrypt(public_key, plaintext):
    ciphertext = public_key.encrypt(
        plaintext.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def rsa_decrypt(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode('utf-8')

# Example usage:
aes_key = generate_aes_key()
des_key = generate_des_key()
rsa_private_key, rsa_public_key = generate_rsa_keys()

plaintext = "Hello, world!"

aes_ciphertext, aes_nonce, aes_tag = aes_encrypt(aes_key, plaintext)
print("AES Encrypted:", aes_ciphertext.hex())

des_ciphertext = des_encrypt(des_key, plaintext)
print("DES Encrypted:", des_ciphertext.hex())

rsa_ciphertext = rsa_encrypt(rsa_public_key, plaintext)
print("RSA Encrypted:", rsa_ciphertext.hex())

decrypted_aes = aes_decrypt(aes_key, aes_nonce, aes_ciphertext, aes_tag)
print("AES Decrypted:", decrypted_aes)

decrypted_des = des_decrypt(des_key, des_ciphertext)
print("DES Decrypted:", decrypted_des)

decrypted_rsa = rsa_decrypt(rsa_private_key, rsa_ciphertext)
print("RSA Decrypted:", decrypted_rsa)

