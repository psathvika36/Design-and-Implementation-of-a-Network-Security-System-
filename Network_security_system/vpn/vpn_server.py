import socket

# Create VPN server
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 9999))
server_socket.listen(1)

print("VPN Server listening on port 9999...")

while True:
    conn, addr = server_socket.accept()
    print(f"Connection established with {addr}")
    while True:
        data = conn.recv(1024)
        if not data:
            break
        print(f"Encrypted message received: {data.decode()}")
        conn.send(b"Message received securely.")
    conn.close()
