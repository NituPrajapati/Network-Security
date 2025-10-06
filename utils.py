from Crypto.Cipher import AES, PKCS1_OAEP 
from Crypto.PublicKey import RSA 
from Crypto.Hash import SHA256 
from Crypto.Random import get_random_bytes 
import base64 

# AES Encryption / Decryption 

def aes_encrypt(key, data):
    cipher = AES.new(key, AES.MODE_EAX) 
    ciphertext, tag = cipher.encrypt_and_digest(data.encode()) 
    return { 
        'ciphertext': base64.b64encode(ciphertext).decode(), 
        'nonce': base64.b64encode(cipher.nonce).decode(), 
        'tag': base64.b64encode(tag).decode() 
    } 

def aes_decrypt(key, enc_dict): 
    ciphertext = base64.b64decode(enc_dict['ciphertext']) 
    nonce = base64.b64decode(enc_dict['nonce']) 
    tag = base64.b64decode(enc_dict['tag']) 
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce) 
    data = cipher.decrypt_and_verify(ciphertext, tag) 
    return data.decode() 

# RSA Encryption / Decryption 
def generate_rsa_keys(): 
    key = RSA.generate(2048) 
    private_key = key.export_key() 
    public_key = key.publickey().export_key() 
    return private_key, public_key 

def rsa_encrypt(public_key_bytes, data_bytes): 
    public_key = RSA.import_key(public_key_bytes) 
    cipher_rsa = PKCS1_OAEP.new(public_key) 
    return cipher_rsa.encrypt(data_bytes) 

def rsa_decrypt(private_key_bytes, enc_data_bytes): 
    private_key = RSA.import_key(private_key_bytes) 
    cipher_rsa = PKCS1_OAEP.new(private_key) 
    return cipher_rsa.decrypt(enc_data_bytes) 

# SHA-256 Hash 
def sha256_hash(data): 
    h = SHA256.new(data.encode()) 
    return h.hexdigest() 
