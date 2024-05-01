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

#MAKE USER PICK A USERNAME
username = input("Enter Username: JOIN ")

#ARGUMENT VALIDATION
if len(sys.argv) != 3:
    print("Usage: python3 client.py <address> <port>")
    exit(1)

#CREATING SOCKET
IP = str(sys.argv[1])
port = int(sys.argv[2])
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((IP, port))

#RESPONSES TO CLIENT FROM SERVER
def handleReceive():
    while True:
        try:
            message = client.recv(1024).decode("utf-8")
            if message == "username?":
                client.send(username.encode("utf-8"))
            elif(message == "quit?"):
                print("You have left the chat!")
                sys.exit(1)
            else:
                print(message)
        except:
            print("Connection terminated!")
            client.close()
            break

#SENDING COMMANDS FROM CLIENT TO SERVER
def handleSend():
    while True:
        message = f'{username}: {input("")}'
        client.send(message.encode("utf-8"))

#MULTITHREADING
recv_t = threading.Thread(target=handleReceive)
recv_t.start()

send_t = threading.Thread(target=handleSend)
send_t.start()
