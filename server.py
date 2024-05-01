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

#CREATING SOCKET
host = "0.0.0.0"
port = int(sys.argv[1])
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((host, port))
#LIMIT CAPACITY TO 10 USERS
server.listen(10)
#LIST OF CONNECTED CLIENTS
clients = []
#LIST OF USERNAMES
usernames = []

#BROADCAST MESSAGE TO ALL CONNECTED CLIENTS
def broadcast(message):
    for client in clients:
        client.send(message)

#LISTEN FOR CLIENT COMMANDS
def connectionHandler(client):
    while True:
        try:
            #GIVEN COMMAND
            command = client.recv(1024).decode("utf-8")

            #LIST COMMAND
            if(command.split(" ")[1].upper() == "LIST"):
                message = ""
                for name in usernames:
                    message += name + ", "
                client.send(message.encode("utf-8"))
            #MESSAGE COMMAND
            elif(command.split(" ")[1].upper() == "MESG"):
                active = False
                message = ""
                for text in command.split(" ")[3:]:
                    message +=  text + " "
                target = str(command.split(" ")[2])
                if(command.split(" ")[0].upper() != ""):
                    username = command.split(" ")[0]
                for name in usernames:
                    if(name == target):
                        index = usernames.index(name)
                        target = clients[index]
                        active = True
                        target.send(("[DM] " + username + " " + message).encode("utf-8"))
                if(active == False):
                    client.send("User not found!".encode("utf-8"))
            #BROADCAST COMMAND
            elif(command.split(" ")[1].upper() == "BCST"):
                message = ""
                for text in command.split(" ")[2:]:
                    message += text + " "
                if(command.split(" ")[0].upper() != ""):
                    username = command.split(" ")[0]
                broadcast((username + " " + message).encode("utf-8"))
            #QUIT COMMAND
            elif(command.split(" ")[1].upper() == "QUIT"):
                index = clients.index(client)
                clients.remove(client)
                client.send("quit?".encode("utf-8"))
                client.close()
                username = usernames[index]
                broadcast(f"{username} left the chat room!".encode("utf-8"))
                usernames.remove(username)
            #ELSE UNKNOWN COMMAND:
            else:
                message = "Unknown Command"
                client.send(message.encode("utf-8"))
         #CONNECTION WITH CLIENT TERMINATES WITHOUT CLIENT USING QUIT COMMAND REMOVE THEM
        except:
          index = clients.index(client)
          clients.remove(client)
          client.close()
          username = usernames[index]
          broadcast(f"{username} left the chat room!".encode("utf-8"))
          usernames.remove(username)
          break
        
#CREATE SERVER AND START LISTENING FOR CONNECTIONS
def createServer():
    try:
        while True:
            print("Server running...")
            #SOCKET GETS CONNECTION
            client, address = server.accept()
            client.send("username?".encode("utf-8"))
            username = client.recv(1024).decode("utf-8")
            #STORE USERNAME OF CLIENT
            usernames.append(str(username))
            #STORE CLIENT INFO
            clients.append(client)
            #REPLY WITH SUCCESSFUL CONNECTION STATUS
            broadcast(f"{username} connected to the chat!".encode("utf-8"))
            client.send("You connected!".encode("utf-8"))        
            #MULTITHREADING
            t = threading.Thread(target=connectionHandler, args=(client,))
            t.start()
    #USER CLOSES SERVER WITH INTERRUPT
    except KeyboardInterrupt:
            print("Keyboard Interrupt Detected")
            server.close()
            sys.exit(1)

def main():
    createServer()

if __name__ == "__main__":
    #ARGUMENT VALIDATION
    if len(sys.argv) != 2:
        print("Usage: python3 server.py <port>")
        exit(1)
    main()