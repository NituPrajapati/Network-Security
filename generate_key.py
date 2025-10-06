from Crypto.PublicKey import RSA 
import os 
 
def generate_keys(name, bits=2048): 
    key = RSA.generate(bits) 
    private_key = key.export_key() 
    public_key = key.publickey().export_key() 
 
    os.makedirs("keys", exist_ok=True) 
    with open(f"keys/{name}_private.pem", "wb") as f: 
        f.write(private_key) 
    with open(f"keys/{name}_public.pem", "wb") as f: 
        f.write(public_key) 
    print(f"{name} RSA key pair generated.") 
 
if __name__ == "__main__": 
    generate_keys("client") 
    generate_keys("server") 