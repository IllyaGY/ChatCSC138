'''
Austin Melendez
Illya Gordyy
Joshua Dye
CSC 138 TCP Chat Room
Due 30 Apr 2024
The program creates a chat server over TCP allowing for multiple users to simulaneously communicate.
'''
#CSC138 TCP CHAT ROOM PROJECT - SERVER
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

# GENERATING L RSA KEYS (used for AES key exchange)
public_key, private_key = rsa.newkeys(2048)
client_keys = {}  # Stores AES keys per client

# CREATING SOCKET
host = "0.0.0.0"
port = int(sys.argv[1])
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((host, port))
# LIMIT CAPACITY TO 10 USERS
server.listen(10)
# LIST OF CONNECTED CLIENTS
clients = []
# LIST OF USERNAMES
usernames = []

# A helper to send encrypted messages to a client using that client’s AES key.
def send_encrypted(client, message):
    key = client_keys.get(client)
    if key:
        client.send(aes_encrypt(message, key))
    else:
        # Fallback (should not occur after handshake)
        client.send(message.encode("utf-8"))

# BROADCAST MESSAGE TO ALL CONNECTED CLIENTS (each encrypted with that client’s AES key)
def broadcast(message):
    for client in clients:
        send_encrypted(client, message)

# LISTEN FOR CLIENT COMMANDS (all messages after handshake are AES-encrypted)
def connectionHandler(client):
    while True:
        try:
            data = client.recv(1024)
            # Decrypt the received data using this client’s AES key
            command = aes_decrypt(data, client_keys[client])
            # Example command format: "username: COMMAND args..."
            parts = command.split(" ")
            if len(parts) < 2:
                send_encrypted(client, "Malformed command")
                continue

            # LIST COMMAND
            if parts[1].upper() == "LIST":
                message = ", ".join(usernames)
                send_encrypted(client, message)
            # MESSAGE COMMAND (direct message)
            elif parts[1].upper() == "MESG":
                if len(parts) < 4:
                    send_encrypted(client, "Usage: <sender>: MESG <target> <message>")
                    continue
                sender = parts[0].rstrip(":")
                target_name = parts[2]
                message_text = " ".join(parts[3:])
                active = False
                for name in usernames:
                    if name == target_name:
                        index = usernames.index(name)
                        target_client = clients[index]
                        active = True
                        send_encrypted(target_client, f"[DM] {sender}: {message_text}")
                if not active:
                    send_encrypted(client, "User not found!")
            # BROADCAST COMMAND
            elif parts[1].upper() == "BCST":
                if len(parts) < 3:
                    send_encrypted(client, "Usage: <sender>: BCST <message>")
                    continue
                sender = parts[0].rstrip(":")
                message_text = " ".join(parts[2:])
                broadcast(f"{sender}: {message_text}")
            # QUIT COMMAND
            elif parts[1].upper() == "QUIT":
                index = clients.index(client)
                username = usernames[index]
                clients.remove(client)
                send_encrypted(client, "quit?")
                client.close()
                broadcast(f"{username} left the chat room!")
                usernames.remove(username)
                break
            # ELSE UNKNOWN COMMAND:
            else:
                send_encrypted(client, "Unknown Command")
        except Exception as e:
            # If the connection terminates unexpectedly, remove the client.
            if client in clients:
                index = clients.index(client)
                username = usernames[index]
                clients.remove(client)
                client.close()
                broadcast(f"{username} left the chat room!")
                usernames.remove(username)
            break
        
# CREATE SERVER AND START LISTENING FOR CONNECTIONS
def createServer():
    try:
        while True:
            print("Server running...")
            # SOCKET GETS CONNECTION
            client, address = server.accept()
            # --- HANDSHAKE PHASE (unencrypted) ---
            client.send("username?".encode("utf-8"))
            username = client.recv(1024).decode("utf-8")
            # Send the RSA public key (in PEM format) for key exchange.
            client.send(public_key.save_pkcs1())
            # Receive the AES key (encrypted with RSA) and decrypt it.
            encrypted_aes_key = client.recv(1024)
            aes_key = rsa.decrypt(encrypted_aes_key, private_key)
            client_keys[client] = aes_key
            # --------------------------------------------------

            # STORE USERNAME OF CLIENT
            usernames.append(username)
            # STORE CLIENT INFO
            clients.append(client)
            # REPLY WITH SUCCESSFUL CONNECTION STATUS
            broadcast(f"{username} connected to the chat!")
            send_encrypted(client, "You connected!")
            # MULTITHREADING to handle this client
            t = threading.Thread(target=connectionHandler, args=(client,))
            t.start()
    except KeyboardInterrupt:
        print("Keyboard Interrupt Detected")
        server.close()
        sys.exit(1)

def main():
    createServer()

if __name__ == "__main__":
    # ARGUMENT VALIDATION
    if len(sys.argv) != 2:
        print("Usage: python3 server.py <port>")
        exit(1)
    main()
