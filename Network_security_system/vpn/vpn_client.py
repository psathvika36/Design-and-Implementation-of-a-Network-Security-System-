import socket

# Create VPN client
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 9999))

message = "This is a secure message!"
client_socket.send(message.encode())
response = client_socket.recv(1024)
print(f"Response from server: {response.decode()}")

client_socket.close()
