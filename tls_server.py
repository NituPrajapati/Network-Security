import socket, ssl 
 
HOST = "127.0.0.1" 
PORT = 4443 
 
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER) 
context.load_cert_chain(certfile="cert/server_cert.pem", keyfile="cert/server_key.pem") 
 
with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock: 
    sock.bind((HOST, PORT)) 
    sock.listen(5) 
    print(f"TLS server listening at {HOST}:{PORT}") 
    with context.wrap_socket(sock, server_side=True) as ssock: 
        conn, addr = ssock.accept() 
        print("TLS connection established with:", addr) 
        data = conn.recv(1024) 
        print("Received:", data.decode()) 
        conn.sendall(b"TLS server: message received securely")