import socket
import threading
import statics
import time
import json
from user import User
from typing import List
from statics import *

PORT = 36432
online_users: List[User] = []
online_users_lock = threading.Lock()

def sign_in_request(conn: socket, addr):
    # TODO: implement
    pass

# each client will request online users every 5 seconds, and server responses
def fetch_online_users_request(conn: socket, addr):
    with online_users_lock:
        users_json = json.dumps([json.loads(user.to_json()) for user in online_users])
        conn.sendall(users_json.encode())

# every 3 seconds, server will ping every user to check if they are still online
def ping_users():
    while True:
        time.sleep(3)
        online_users_copy = online_users.copy()
        for user in online_users_copy:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    s.connect((user.ip_address, user.port))
                    s.send(f"{statics.SERVER_PING}".encode())
                    response = s.recv(1024).decode()
                    if response != CLIENT_IS_ONLINE:
                        raise Exception
            except:
                with online_users_lock:
                    online_users.remove(user)
        print(f"at time: {time.time()}, online users: {online_users}")

# this is temporarily and will be removed later on
def temporarily_signin_request(conn: socket, addr):
    conn.send(f"{SERVER_OK}".encode())
    data = conn.recv(1024).decode().split("?")
    conn.send(f"{SERVER_LOGIN_OK}".encode())
    conn.close()
    user = User(is_online=True, ip_address=addr[0], port=data[1], name=data[0])
    with online_users_lock:
        online_users.append(user)

# user requests is handled here
def handle_client_request(conn: socket, addr):
    try:
        while True:
            request = int(conn.recv(1024).decode())
            if request == CLIENT_SIGN_IN_REQUEST:
                sign_in_request(conn, addr)
            elif request == CLIENT_FETCH_ONLINE_USERS_REQUEST:
                fetch_online_users_request(conn, addr)
            elif request == CLIENT_CHECK_SERVER_AVAILABILITY:
                conn.send(f"{SERVER_CONNECT_OK}".encode())
            elif request == CLIENT_TEMPORARILY_LOGIN_REQUEST:
                temporarily_signin_request(conn, addr)
            elif request == CLIENT_LOG_OFF:
                break
        conn.close()
    except:
        print("unexpected error occurred in handle_client_request function")
        conn.close()



# initializing server
def initialize_server():
    socket_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # TCP connection using IPv4
    socket_connection.bind(('127.0.0.1', PORT))
    socket_connection.listen(10)
    # initializing the online user checker thread
    online_users_checker = threading.Thread(target=ping_users)
    online_users_checker.start()

    print("server's ready, pending clients...")
    # create a thread for each client request
    while True:
        client, address = socket_connection.accept()
        print("client connected", address)
        thread = threading.Thread(target=handle_client_request, args=(client, address))
        thread.start()

if __name__ == '__main__':
    initialize_server()