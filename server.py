import socket
import threading
import time
import json
import shutil
from user import User
from typing import List
from statics import *
from pathlib import Path
from log import Log

PORT = 36432
online_users: List[User] = []
online_users_lock = threading.Lock()
log = Log("server") # log file name which is server

def sign_in_request(conn: socket, addr):
    # TODO: implement
    pass

def reset_log_folder():
    folder = Path("logs")
    # Check if it exists before deleting
    if folder.exists() and folder.is_dir():
        shutil.rmtree(folder)
    folder.mkdir(parents=True, exist_ok=True)

# each client will request online users every 5 seconds, and server responses
def fetch_online_users_request(conn: socket, addr):
    with online_users_lock:
        users_json = json.dumps([json.loads(user_.to_json()) for user_ in online_users])
        conn.sendall(users_json.encode())
    log.append_log(f"responded to fetch online users request from {addr}")

# every 3 seconds, server will ping every user to check if they are still online
def ping_users():
    while True:
        time.sleep(3)
        with online_users_lock:
            online_users_copy = online_users.copy()
        for user_ in online_users_copy:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(100)
                    s.connect((user_.ip_address, user_.port))
                    s.send(SERVER_PING.encode())
                    response = s.recv(1024).decode()
                    if response != CLIENT_IS_ONLINE:
                        raise Exception("user sent invalid response")
            except Exception as e:
                log.append_log(f"during pinging, user {user_} did not responded")
                with online_users_lock:
                    online_users.remove(user_)
        with online_users_lock:
            log.append_users_logs("pinged all users, remaining users" ,online_users)

# this is temporarily and will be removed later on
def temporarily_signin_request(conn: socket, addr):
    conn.send(SERVER_OK.encode())
    data = conn.recv(1024).decode().split("?")
    conn.send(SERVER_LOGIN_OK.encode())
    user_ = User(is_online=True, ip_address=addr[0], port=int(data[1]), name=data[0])
    with online_users_lock:
        online_users.append(user_)
    log.append_log(f"user logged in: {user_}")

# user requests is handled here
def handle_client_request(conn: socket, addr):
    try:
        while True:
            request = conn.recv(1024).decode()
            log.append_log(f"received request: {convert_to_request_name(request)} from {addr}")
            if request == CLIENT_SIGN_IN_REQUEST:
                sign_in_request(conn, addr)
            elif request == CLIENT_FETCH_ONLINE_USERS_REQUEST:
                fetch_online_users_request(conn, addr)
            elif request == CLIENT_CHECK_SERVER_AVAILABILITY:
                conn.send(SERVER_CONNECT_OK.encode())
                log.append_log(f"sent server-is-accessible request to {addr}")
            elif request == CLIENT_TEMPORARILY_LOGIN_REQUEST:
                temporarily_signin_request(conn, addr)
            elif request == CLIENT_LOG_OFF:
                conn.send(SERVER_LOG_OFF_OK.encode())
                log.append_log(f"user {addr} logged off")
                with online_users_lock:
                    for user_ in online_users:
                        if user_.address_is_equal(addr[0], addr[1]):
                            online_users.remove(user_)
                            break
                break
            else:
                log.append_log(f"unknown request: {request} from {addr}, connection is closed")
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
    reset_log_folder()
    # initializing the online user checker thread
    online_users_checker = threading.Thread(target=ping_users)
    online_users_checker.start()

    print("server's ready, pending clients...")
    # create a thread for each client request
    while True:
        client, address = socket_connection.accept()
        print("new client")
        log.append_log("client connected with address: " + str(address))
        thread = threading.Thread(target=handle_client_request, args=(client, address))
        thread.start()

if __name__ == '__main__':
    initialize_server()