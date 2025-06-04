import socket
import threading
import time
import json
import shutil
import server_database
from onlineuser import OnlineUser
from typing import List
from statics import *
from pathlib import Path
from log import Log
from timestamp import Timestamp

PORT = 36432
online_users: List[OnlineUser] = []
online_users_lock = threading.Lock()
log = Log("server") # log file name which is server

def receive_image(conn: socket.socket) -> bytes:
    length_bytes = conn.recv(4)
    image_length = int.from_bytes(length_bytes, byteorder='big') # image size is converted into integer
    conn.send(SERVER_OK.encode())
    # receiving image profile
    received_data = b''
    while len(received_data) < image_length:
        chunk = conn.recv(min(4096, image_length - len(received_data)))
        if not chunk:
            break
        received_data += chunk

    conn.send(SERVER_OK.encode())
    return received_data

def send_image(conn: socket.socket, profile_picture: bytes):
    conn.sendall(len(profile_picture).to_bytes(4, byteorder="big"))
    conn.recv(1024).decode()  # user sent buffer
    conn.sendall(profile_picture)
    conn.recv(1024).decode()  # user sent buffer


# when a client filled information to log in, this function is called
def sign_in_request(conn: socket, addr):
    conn.send(SERVER_OK.encode())
    info = conn.recv(1024).decode()
    conn.send(SERVER_OK.encode())
    received_data = receive_image(conn)
    # now we parse user information
    d = json.loads(info)
    conn.recv(1024).decode() # buffer from user
    global log
    username = d['username']
    public_key = d['public_key']
    display_name = d['display_name']
    # running the SQLite query
    db_result = server_database.sign_in_user(username, d["password"], d["email"], public_key, received_data, display_name, log)
    conn.send(db_result.encode())
    if db_result == DATABASE_SIGNIN_SUCCESS:
        log.append_log(f"New user {username} successfully signed in {addr[0]}:{addr[1]}")
        tr_ip_address, port = conn.recv(1024).decode().split(":")
        signed_in_user = OnlineUser(tr_ip_address, int(port), display_name, username, public_key, received_data, Timestamp.get_now())
        time.sleep(1) # a one-second window for client to be able to response
        with online_users_lock:
            online_users.append(signed_in_user)
    else:
        log.append_log(f"{username} with address {addr[0]}:{addr[1]} failed to sign in: {convert_to_request_name(db_result)}")

# when a user wants to login, this function is called
def login_request(conn: socket, addr):
    conn.send(SERVER_OK.encode())
    info = conn.recv(1024).decode()
    d = json.loads(info)
    username = d['username']
    password = d['password']
    db_result = server_database.login_user(username, password)
    conn.send(db_result.encode())
    if db_result == DATABASE_LOGIN_SUCCESS:
        log.append_log(f"user {username} successfully logged in with address: {addr[0]}:{addr[1]}")
        tr_ip_address, port = conn.recv(1024).decode().split(":")
        user_info = server_database.get_user(username)
        online_user = OnlineUser(tr_ip_address, int(port), user_info.name, username, user_info.public_key, user_info.profile_picture, user_info.last_seen)
        conn.sendall(online_user.to_json().encode())
        conn.recv(1024).decode() # user sent buffer
        send_image(conn, online_user.profile_picture)
        time.sleep(1) # a one-second window for client to be able to response
        with online_users_lock:
            online_users.append(online_user)
    else:
        s = convert_to_request_name(db_result)
        invalid = "invalid"
        log.append_log(f"user {username} successfully logged in with address: {addr[0]}:{addr[1]}, error: {db_result if invalid == s else s}")

# resetting log folder
def reset_log_folder():
    folder = Path("logs")
    # Check if it exists before deleting
    if folder.exists() and folder.is_dir():
        shutil.rmtree(folder)
    folder.mkdir(parents=True, exist_ok=True)

# each client will request online users every 5 seconds, and server responses
def fetch_online_users_request(conn: socket, addr):
    conn.send(SERVER_OK.encode())
    conn.recv(1024).decode() # buffer
    online_users_copy: List[OnlineUser] = []
    with online_users_lock:
        online_users_copy = online_users.copy()
    conn.send(f"{len(online_users_copy)}".encode()) # sending length of online clients
    conn.recv(1024).decode() # buffer
    for user_ in online_users_copy:
        conn.send(user_.to_json().encode())
        conn.recv(1024).decode() # client buffer
        send_image(conn, user_.profile_picture)

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
                log.append_log(f"during pinging, user {user_} did not responded, reason: {e}")
                with online_users_lock:
                    online_users.remove(user_)
        with online_users_lock:
            log.append_users_logs("pinged all users, remaining users" ,online_users)

# user requests is handled here
def handle_client_request(conn: socket.socket, addr):
    try:
        request = conn.recv(1024).decode()
        log.append_log(f"received request: {convert_to_request_name(request)} from {addr}")
        if request == CLIENT_SIGN_IN_REQUEST:
            sign_in_request(conn, addr)
        elif request == CLIENT_FETCH_ONLINE_USERS_REQUEST:
            fetch_online_users_request(conn, addr)
        elif request == CLIENT_CHECK_SERVER_AVAILABILITY:
            conn.send(SERVER_CONNECT_OK.encode())
            log.append_log(f"sent server-is-accessible request to {addr}")
        elif request == CLIENT_LOGIN_REQUEST:
            login_request(conn, addr)
        elif request == CLIENT_LOG_OFF:
            conn.send(SERVER_LOG_OFF_OK.encode())
            log.append_log(f"user {addr} logged off")
            with online_users_lock:
                for user_ in online_users:
                    if user_.address_is_equal(addr[0], addr[1]):
                        online_users.remove(user_)
        else:
            log.append_log(f"unknown request: {request} from {addr}, connection is closed")
        conn.close()
    except Exception as e:
        print(f"unexpected error occurred in handle_client_request function: {e}")
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
    server_database.create_users_table_if_not_exists()
    print("server's ready, pending clients...")
    # create a thread for each client request
    while True:
        client, address = socket_connection.accept()
        thread = threading.Thread(target=handle_client_request, args=(client, address))
        thread.start()

if __name__ == '__main__':
    initialize_server()