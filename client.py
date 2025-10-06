import requests 
from utils import aes_encrypt, sha256_hash, rsa_encrypt, get_random_bytes 
import base64 

server_url = 'https://127.0.0.1:5000' 
requests.packages.urllib3.disable_warnings()

resp = requests.get(f'{server_url}/get_public_key', verify=False) 
SERVER_PUBLIC_KEY = resp.text.encode() 


AES_KEY = get_random_bytes(16) 


enc_aes_key = rsa_encrypt(SERVER_PUBLIC_KEY, AES_KEY) 
enc_aes_key_b64 = base64.b64encode(enc_aes_key).decode()

 
requests.post(f'{server_url}/send_aes_key', json={'aes_key': enc_aes_key_b64}, verify=False) 


while True:
    message = input("Enter message to send: ")
    if message.lower() == 'exit':
        break 
    enc_dict = aes_encrypt(AES_KEY, message)
    message_hash = sha256_hash(message)
    
    data = { 
        'message': enc_dict,
        'hash': message_hash
    } 

    response = requests.post(f'{server_url}/message', json=data, verify=False) 
    print("Server response:", response.json())