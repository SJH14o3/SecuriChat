import socket
import threading
import random
import time
import json
from statics import *
from server import PORT
from user import User

isRunning = True
global_socket = None

def log_in(conn: socket, addr):
    # todo: implement
    pass

def sign_up(conn: socket, addr):
    # todo: implement
    pass

# every 5 seconds, a logged in client will fetch online clients
def fetch_online_users():
    while isRunning:
        try:
            time.sleep(5)
            socket_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket_connection.connect(('127.0.0.1', PORT))
            socket_connection.send(f"{CLIENT_FETCH_ONLINE_USERS_REQUEST}".encode())
            data = socket_connection.recv(4096).decode()
            user_dicts = json.loads(data)
            users = [User(**d) for d in user_dicts]
            # todo: remove current user as well
            print(users)
        except:
            print("something went wrong")


# temporarily and will be removed later on
def temporary_signin(conn: socket):
    conn.send(f"{CLIENT_TEMPORARILY_LOGIN_REQUEST}".encode())
    response = int(conn.recv(1024).decode())
    if response != SERVER_OK:
        raise Exception("Server login failed")
    receiver_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    receiver_socket.bind(('127.0.0.1', 0))
    receiver_socket.listen(10)
    local_port = receiver_socket.getsockname()[1]
    username = f"client#{random.randint(0,1000)}?{local_port}"
    conn.send(f"{username}".encode())
    response = int(conn.recv(1024).decode())
    if response != SERVER_LOGIN_OK:
        raise Exception("Server login failed")

    income_connection = threading.Thread(target=receive_connection, args=(conn, local_port))
    income_connection.start()

    fetch_users_thread = threading.Thread(target=fetch_online_users)
    fetch_users_thread.start()
    while True:
        time.sleep(10)

# first make sure that server is online, then sign-in/login process
def connect_to_server():
    try:
        socket_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # TCP connection
        socket_connection.bind(('127.0.0.1', 0))  # 0 for port means that an available port will be assigned
        socket_connection.connect(('127.0.0.1', PORT))
        socket_connection.send(f"{CLIENT_CHECK_SERVER_AVAILABILITY}".encode())
        response = int(socket_connection.recv(1024))
        if response != SERVER_CONNECT_OK:
            raise Exception
        temporary_signin(socket_connection)

    except ConnectionRefusedError:
        print("Connection refused: make sure server is running.")
    except socket.gaierror as e:
        print("Invalid address: Could not resolve hostname.")
    except TimeoutError:
        print("Connection timed out: Server took too long to respond.")
    except socket.error as e:
        print(f"Socket error: {e}.")
    except:
        print("Unidentified error")

# handling messages that are sent to client in a thread
def handle_income_connection(conn: socket, addr):
    request = int(conn.recv(1024).decode())
    if request == SERVER_PING:
        conn.send(f"{CLIENT_IS_ONLINE}".encode())
    conn.close()

# client will wait for connections and creates a thread for each thread
def receive_connection(conn, local_port: int):
    while isRunning:
        transmitter, address = conn.accept()
        thread = threading.Thread(target=handle_income_connection, args=(transmitter, address))
        thread.start()


def main():
    connect_to_server()

if __name__ == '__main__':
    main()