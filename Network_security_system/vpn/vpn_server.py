import socket
import threading
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import json

# Encryption key (for demonstration purposes, use a more secure key management in production)
ENCRYPTION_KEY = b'Sixteen byte key'

def encrypt_message(message):
    cipher = AES.new(ENCRYPTION_KEY, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    nonce = cipher.nonce
    return base64.b64encode(nonce + tag + ciphertext).decode()

def decrypt_message(enc_message):
    enc_message = base64.b64decode(enc_message)
    nonce, tag, ciphertext = enc_message[:16], enc_message[16:32], enc_message[32:]
    cipher = AES.new(ENCRYPTION_KEY, AES.MODE_EAX, nonce=nonce)
    message = cipher.decrypt_and_verify(ciphertext, tag)
    return message.decode()

# Simulate user authentication (In real-world, use database or external auth)
AUTH_USERS = {'user1': 'password1', 'user2': 'password2'}

def authenticate_user(client_socket):
    client_socket.send("Enter username: ".encode())
    username = client_socket.recv(1024).decode().strip()
    client_socket.send("Enter password: ".encode())
    password = client_socket.recv(1024).decode().strip()

    if AUTH_USERS.get(username) == password:
        client_socket.send(encrypt_message("Authentication successful!").encode())
        return True
    else:
        client_socket.send(encrypt_message("Authentication failed!").encode())
        return False

def handle_client(client_socket, client_address):
    print(f"Connection established with {client_address}")
    
    if not authenticate_user(client_socket):
        client_socket.close()
        return

    while True:
        encrypted_data = client_socket.recv(1024).decode()
        if not encrypted_data:
            break
        
        decrypted_data = decrypt_message(encrypted_data)
        print(f"Encrypted message received: {encrypted_data}")
        print(f"Decrypted message: {decrypted_data}")
        
        # Send back a confirmation message (encrypted)
        response = encrypt_message("Message received securely!")
        client_socket.send(response.encode())

    client_socket.close()

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 9999))
    server_socket.listen(5)

    print("VPN Server listening on port 9999...")

    while True:
        client_socket, client_address = server_socket.accept()
        client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
        client_thread.start()

if __name__ == "__main__":
    start_server()
