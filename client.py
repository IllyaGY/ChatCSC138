
'''
Austin Melendez
Illya Gordyy
Joshua Dye
CSC 138 TCP Chat Room
Due 30 Apr 2024
The program creates a chat client over TCP allowing for multiple users to simulaneously communicate.
'''
#CSC138 TCP CHAT ROOM - CLIENT
import threading
import socket
import sys
import rsa
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# ----------------- AES Helper Functions -----------------
def aes_encrypt(plaintext, key):
    """
    Encrypts the plaintext (a string) using AES in CFB mode.
    A random 16-byte IV is generated and prepended to the ciphertext.
    """
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(plaintext.encode("utf-8")) + encryptor.finalize()
    return iv + ct

def aes_decrypt(ciphertext, key):
    """
    Decrypts the ciphertext (bytes) using AES in CFB mode.
    Assumes the first 16 bytes are the IV.
    """
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    pt = decryptor.update(ct) + decryptor.finalize()
    return pt.decode("utf-8")
# ---------------------------------------------------------

# MAKE USER PICK A USERNAME
username = input("Enter Username: JOIN ")

# ARGUMENT VALIDATION
if len(sys.argv) != 3:
    print("Usage: python3 client.py <address> <port>")
    exit(1)

# CREATING SOCKET
IP = str(sys.argv[1])
port = int(sys.argv[2])
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((IP, port))

# Global AES key variable (will be set after handshake)
aes_key = None

# RESPONSES TO CLIENT FROM SERVER
def handleReceive():
    global aes_key
    while True:
        try:
            data = client.recv(1024)
            if not data:
                print("Server closed connection.")
                client.close()
                break
            # Handshake phase: before the AES key is set, messages are in plaintext.
            if aes_key is None:
                message = data.decode("utf-8")
                # Server is asking for the username.
                if message == "username?":
                    client.send(username.encode("utf-8"))
                # Server is sending its RSA public key.
                elif message.startswith("-----BEGIN"):
                    server_pub = rsa.PublicKey.load_pkcs1(data)
                    # Generate a new AES key (32 bytes for AES-256)
                    aes_key = os.urandom(32)
                    # Encrypt the AES key using the server's RSA public key and send it.
                    encrypted_aes_key = rsa.encrypt(aes_key, server_pub)
                    client.send(encrypted_aes_key)
                else:
                    # Any other handshake message can be printed.
                    print(message)
            else:
                # After handshake, all messages are AES-encrypted.
                message = aes_decrypt(data, aes_key)
                if message == "quit?":
                    print("You have left the chat!")
                    client.close()
                    sys.exit(0)
                print(message)
        except Exception as e:
            print("Connection terminated!", e)
            client.close()
            break

# SENDING COMMANDS FROM CLIENT TO SERVER
def handleSend():
    global aes_key
    # Wait until the AES key has been set by the handshake.
    while aes_key is None:
        pass
    while True:
        try:
            text = input("")
            message = f'{username}: {text}'
            client.send(aes_encrypt(message, aes_key))
        except Exception as e:
            print("Error sending message:", e)
            client.close()
            break

# MULTITHREADING
recv_t = threading.Thread(target=handleReceive)
recv_t.start()

send_t = threading.Thread(target=handleSend)
send_t.start()
