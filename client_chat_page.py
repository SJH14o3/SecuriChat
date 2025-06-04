import json
import socket
import threading
import time
from typing import List
import sys
from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QTextEdit, QListWidget
from PySide6.QtCore import Qt
from log import Log
from onlineuser import OnlineUser
from statics import *
from server import PORT
from peer_connection import PeerConnection

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

def fetch_online_users() -> List[OnlineUser]:
    """Fetch list of online users from server"""
    online_users = []
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(('127.0.0.1', PORT))
        s.send(CLIENT_FETCH_ONLINE_USERS_REQUEST.encode())
        s.recv(1024).decode()  # server OK
        s.send(BUFFER.encode())  # client OK
        count = int(s.recv(1024).decode())  # count of online users
        s.send(BUFFER.encode())  # client OK
        
        for _ in range(count):
            data = s.recv(1024).decode()  # user json
            s.send(BUFFER.encode())  # client OK
            user = OnlineUser.from_json(data)
            image = receive_image_bytes_from_socket(s)
            user.profile_picture = image
            online_users.append(user)
            
    return online_users

class ClientChatMenu(QWidget):
    def __init__(self, online_user: OnlineUser, receiver_socket, log: Log):
        super().__init__()
        self.online_user = online_user
        self.receiver_socket = receiver_socket
        self.log = log
        self.isRunning = True
        self.selected_user = None
        
        # Initialize P2P connection
        self.peer_connection = PeerConnection(
            username=online_user.username,
            private_key=online_user.private_key,
            log=log
        )
        
        # Register message handlers
        self.peer_connection.register_message_handler('text', self.handle_text_message)
        
        self.setup_ui()
        self.start_online_users_updater()

    def setup_ui(self):
        self.setWindowTitle(f"SecuriChat - {self.online_user.display_name}")
        
        # Main layout
        layout = QHBoxLayout()
        
        # Online users section
        users_layout = QVBoxLayout()
        users_label = QLabel("Online Users")
        self.users_list = QListWidget()
        self.users_list.itemClicked.connect(self.user_selected)
        users_layout.addWidget(users_label)
        users_layout.addWidget(self.users_list)
        
        # Chat section
        chat_layout = QVBoxLayout()
        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        self.message_input = QTextEdit()
        self.message_input.setMaximumHeight(100)
        self.send_button = QPushButton("Send")
        self.send_button.clicked.connect(self.send_message)
        
        chat_layout.addWidget(self.chat_display)
        chat_layout.addWidget(self.message_input)
        chat_layout.addWidget(self.send_button)
        
        # Add layouts to main layout
        layout.addLayout(users_layout, 1)
        layout.addLayout(chat_layout, 2)
        
        self.setLayout(layout)

    def user_selected(self, item):
        self.selected_user = item.text()
        self.chat_display.append(f"--- Started chat with {self.selected_user} ---")

    def send_message(self):
        if not self.selected_user:
            self.chat_display.append("Please select a user to chat with")
            return
            
        message = self.message_input.toPlainText().strip()
        if not message:
            return
            
        success = self.peer_connection.send_message(self.selected_user, message)
        if success:
            self.chat_display.append(f"You: {message}")
            self.message_input.clear()
        else:
            self.chat_display.append("Failed to send message")

    def handle_text_message(self, message_dict):
        """Handle incoming text messages"""
        sender = message_dict['sender_id']
        content = message_dict['content']
        self.chat_display.append(f"{sender}: {content}")

    def update_online_users(self, online_users: list):
        """Update the list of online users and their P2P connection info"""
        self.users_list.clear()
        for user in online_users:
            if user.username != self.online_user.username:
                self.users_list.addItem(user.username)
                # Update peer connection info
                self.peer_connection.update_peer(
                    username=user.username,
                    ip=user.ip_address,
                    port=user.port
                )

    def start_online_users_updater(self):
        """Start thread to update online users list"""
        self.updater_thread = threading.Thread(target=self.update_online_users_periodically)
        self.updater_thread.daemon = True
        self.updater_thread.start()

    def update_online_users_periodically(self):
        while self.isRunning:
            try:
                # Get online users from server
                online_users = fetch_online_users()  # You'll need to implement this
                self.update_online_users(online_users)
            except Exception as e:
                self.log.append_log(f"Error updating online users: {str(e)}")
            time.sleep(5)  # Update every 5 seconds

    def close_threads(self):
        """Clean up threads and connections"""
        self.isRunning = False
        self.peer_connection.stop()
        if hasattr(self, 'updater_thread'):
            self.updater_thread.join(timeout=1)
