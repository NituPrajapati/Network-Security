from flask import Flask, request, jsonify 
from utils import aes_decrypt, sha256_hash, generate_rsa_keys, rsa_decrypt 
import base64 

app = Flask(__name__) 
PRIVATE_KEY, PUBLIC_KEY = generate_rsa_keys() 


AES_KEY = None 


@app.route('/get_public_key', methods=['GET']) 
def get_public_key(): 
    return PUBLIC_KEY.decode() 


@app.route('/send_aes_key', methods=['POST']) 
def send_aes_key(): 
    global AES_KEY 
    enc_aes_key_b64 = request.json['aes_key'] 
    enc_aes_key = base64.b64decode(enc_aes_key_b64) 
    AES_KEY = rsa_decrypt(PRIVATE_KEY, enc_aes_key) 
    return jsonify({'status': 'AES key received successfully'}) 


@app.route('/message', methods=['POST']) 
def receive_message(): 
    global AES_KEY 
    if AES_KEY is None: 
        return jsonify({'status': 'AES key not set'}), 400 

    data = request.json 
    enc_message = data['message'] 
    enc_message_dict = { 
        'ciphertext': enc_message['ciphertext'], 
        'nonce': enc_message['nonce'], 
        'tag': enc_message['tag'] 
    }

     
    decrypted_message = aes_decrypt(AES_KEY, enc_message_dict) 

   
    client_hash = data['hash'] 
    computed_hash = sha256_hash(decrypted_message) 

    print("Received encrypted message:", enc_message) 
    print("Decrypted message:", decrypted_message) 
    print("Client hash:", client_hash) 
    print("Computed hash:", computed_hash) 

    if client_hash == computed_hash: 
        status = 'success' 
    else: 
        status = 'hash mismatch' 

    return jsonify({'message': decrypted_message, 'status': status}) 

if __name__ == '__main__': 
    
    app.run(ssl_context=('cert/server_cert.pem', 'cert/server_key.pem')) 

if __name__ == '__main__': 
    print("[Server] Starting Flask server...") 
    app.run(ssl_context=('cert/server_cert.pem', 'cert/server_key.pem'), debug=True)