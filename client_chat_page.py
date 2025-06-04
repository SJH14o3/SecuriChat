import json
import socket
import threading
import time
from typing import List

from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel
from log import Log
from onlineuser import OnlineUser
from statics import *
from server import PORT

def receive_image_bytes_from_socket(conn: socket.socket) -> bytes:
    length_bytes = conn.recv(4)
    image_length = int.from_bytes(length_bytes, byteorder='big') # image size is converted into integer
    conn.send(BUFFER.encode())
    # receiving image profile
    received_data = b''
    while len(received_data) < image_length:
        chunk = conn.recv(min(4096, image_length - len(received_data)))
        if not chunk:
            break
        received_data += chunk

    conn.send(BUFFER.encode())
    return received_data

class ClientChatMenu(QWidget):
    def __init__(self, online_user: OnlineUser , receiver_socket: socket.socket, log: Log):
        super().__init__()
        layout = QVBoxLayout()
        welcome = QLabel(f"Welcome, {online_user.username}!")
        layout.addWidget(welcome)
        self.setLayout(layout)
        self.online_user = online_user
        self.receiver_socket = receiver_socket
        self.log = log
        self.isRunning = True
        self.other_online_users: List[OnlineUser] = []

        self.fetch_online_users_thread = threading.Thread(target=self.fetch_online_users)
        self.fetch_online_users_thread.start()

        self.receiver_socket_thread = threading.Thread(target=self.receive_connection)
        self.receiver_socket_thread.start()

        print(f"client is here: {self.online_user}")

    # every 5 seconds, a logged in client will fetch online clients
    def fetch_online_users(self):
        while self.isRunning:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    self.other_online_users.clear()
                    s.connect(('127.0.0.1', PORT))
                    s.send(CLIENT_FETCH_ONLINE_USERS_REQUEST.encode())
                    s.recv(1024).decode() # server OK
                    s.send(BUFFER.encode()) # client OK
                    data = s.recv(1024).decode()
                    count = int(data) # count of online users
                    s.send(BUFFER.encode()) # client OK
                    for _ in range(count):
                        data = s.recv(1024).decode() # user json
                        s.send(BUFFER.encode()) # client OK
                        user_ = OnlineUser.from_json(data)
                        image = receive_image_bytes_from_socket(s)
                        if user_ != self.online_user:
                            user_.profile_picture = image
                            self.other_online_users.append(user_)
                self.log.append_users_logs("other online users fetched", self.other_online_users)
                time.sleep(5)
            except Exception as e:
                print(f"something went wrong: {e}")

    # handling messages that are sent to client in a thread
    def handle_income_connection(self, transmitter, address):
            request = transmitter.recv(1024).decode()
            if request == SERVER_PING:  # responding to server ping which happens every 3 seconds
                transmitter.send(CLIENT_IS_ONLINE.encode())
                self.log.append_log("responded to server ping")
                transmitter.close()

    # client will wait for connections and creates a thread for each thread
    def receive_connection(self):
        self.receiver_socket.listen(10)
        try:
            while self.isRunning:
                transmitter, address = self.receiver_socket.accept()
                thread = threading.Thread(target=self.handle_income_connection, args=(transmitter,address))
                thread.start()
        except OSError as e:
            self.log.append_log(f"receive_connection is closed")

    def close_threads(self):
        self.receiver_socket.close()
