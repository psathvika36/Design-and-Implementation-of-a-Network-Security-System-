import socket
from Crypto.Cipher import AES
import base64

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

def connect_to_server():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 9999))
    
    # Authentication
    username = input("Enter username: ")
    client_socket.send(username.encode())
    password = input("Enter password: ")
    client_socket.send(password.encode())
    
    auth_response = client_socket.recv(1024).decode()
    decrypted_response = decrypt_message(auth_response)
    print(f"Server Response: {decrypted_response}")
    
    if "Authentication failed" in decrypted_response:
        client_socket.close()
        return
    
    while True:
        message = input("Enter a message to send (or 'exit' to quit): ")
        if message.lower() == 'exit':
            break
        
        encrypted_message = encrypt_message(message)
        client_socket.send(encrypted_message.encode())
        
        response = client_socket.recv(1024).decode()
        decrypted_response = decrypt_message(response)
        print(f"Server Response: {decrypted_response}")

    client_socket.close()

if __name__ == "__main__":
    connect_to_server()
