import socket, ssl

HOST = "127.0.0.1"
PORT = 4443

context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)


context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

with socket.create_connection((HOST, PORT)) as sock:
    with context.wrap_socket(sock, server_hostname=HOST) as ssock:
        print("Connected to TLS server:", ssock.version())
        
    
        ssock.sendall(b"Hello from TLS client!")
        
        
        data = ssock.recv(1024)
        print("Received:", data.decode())
