import json
import random
import socket
import threading
import time
from typing import List, Dict
import sys

from PySide6.QtGui import QPixmap, QColor, QPainter
from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QTextEdit, QListWidget, \
    QSizePolicy, QScrollArea, QListWidgetItem
from PySide6.QtCore import Qt, QSize, Signal
import local_database
from log import Log
from onlineuser import OnlineUser
from statics import *
from server import PORT
from peer_connection import PeerConnection
from timestamp import Timestamp


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

class OtherUsersBox():
    def __init__(self, image_bytes: bytes, display_name, subtitle, latest_message_timestamp: Timestamp, is_online: bool, username: str, has_unread: bool):
        super().__init__()
        self.latest_message_timestamp = latest_message_timestamp
        self.is_online = is_online
        self.username = username
        self.display_name = display_name
        self.image_bytes = image_bytes
        self.subtitle = subtitle
        self.has_unread = has_unread

class CircleIndicator(QWidget):
    def __init__(self, diameter=10, color=Qt.red, parent=None):
        super().__init__(parent)
        self.diameter = diameter
        self.color = QColor(color)
        self.setFixedSize(QSize(diameter, diameter))

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setBrush(self.color)
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(0, 0, self.diameter, self.diameter)

class Morph(QWidget):
    def __init__(self, image_bytes: bytes, display_name, subtitle, latest_message_timestamp: Timestamp, is_online: bool, username: str, has_unread_messages):
        super().__init__()
        main_layout = QHBoxLayout()
        text_layout = QVBoxLayout()
        signs_layout = QVBoxLayout()
        signs_layout.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.latest_message_timestamp = latest_message_timestamp
        self.is_online = is_online
        self.username = username
        self.display_name = display_name
        self.has_unread_messages = has_unread_messages

        # Title
        self.title_label = QLabel(f"<b>{display_name}</b>")
        self.title_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        # Subtitle
        self.subtitle_label = QLabel()
        self.set_subtitle(subtitle)

        # Image
        self.image_label = QLabel()
        self.set_image(image_bytes)

        # Add indicators if needed
        if self.is_online:
            online_circle = CircleIndicator(diameter=10, color=Qt.green)
            signs_layout.addWidget(online_circle)

        if self.has_unread_messages:
            unread_circle = CircleIndicator(diameter=10, color=Qt.red)
            signs_layout.addWidget(unread_circle)

        # Layout composition
        text_layout.addWidget(self.title_label)
        text_layout.addWidget(self.subtitle_label)

        main_layout.addWidget(self.image_label)
        main_layout.addLayout(text_layout)
        main_layout.addStretch()  # Push signs_layout to the right
        main_layout.addLayout(signs_layout)

        self.setLayout(main_layout)

    def set_image(self, image_bytes: bytes):
        byte_array = QByteArray(image_bytes)
        buffer = QBuffer(byte_array)
        buffer.open(QIODevice.ReadOnly)

        image = QPixmap()
        image.loadFromData(buffer.data())

        if not image.isNull():
            image = image.scaled(64, 64, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        else:
            image = QPixmap(64, 64)
            image.fill(Qt.gray)

        self.image_label.setPixmap(image)
        self.image_label.setFixedSize(QSize(64, 64))

    def set_subtitle(self, subtitle: str):
        metrics = self.subtitle_label.fontMetrics()
        elided_text = metrics.elidedText(subtitle, Qt.ElideRight, 400)  # Width in pixels
        self.subtitle_label.setText(elided_text)
        self.subtitle_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.subtitle_label.setTextInteractionFlags(Qt.NoTextInteraction)
        self.subtitle_label.setStyleSheet("""
            QLabel {
                color: gray;
                qproperty-alignment: AlignLeft;
            }
        """)
        self.subtitle_label.setWordWrap(False)
        self.subtitle_label.setMinimumWidth(0)
        self.subtitle_label.setMaximumHeight(20)


class ClientChatMenu(QWidget):
    refresh_ui_signal = Signal()
    def __init__(self, online_user: OnlineUser, receiver_socket, log: Log):
        super().__init__()
        self.online_user = online_user
        self.receiver_socket = receiver_socket
        self.log = log
        self.isRunning = True
        self.selected_user = None
        self.local_database = local_database.LocalDatabase(online_user.username)
        self.latest_messages = self.local_database.get_latest_messages_per_user(self.get_aes_key())
        self.refresh_ui_signal.connect(self.refresh_user_list_ui)
        # Initialize P2P connection
        self.peer_connection = PeerConnection(
            username=online_user.username,
            private_key=self.get_private_key(),
            log=log,
            receiver_socket=self.receiver_socket,
            database=self.local_database,
            aes_key=self.get_aes_key()
        )
        # Register message handlers
        self.peer_connection.register_message_handler('text', self.handle_text_message)

        self.chat_display = QTextEdit()
        self.message_input = QTextEdit()
        self.send_button = QPushButton("Send")
        self.users_layout = QVBoxLayout()
        self.users_list_widget = QListWidget()

        self.setup_ui()
        self.other_users_list: Dict[str, OtherUsersBox] = {}
        self.other_online_users_list: Dict[str, OnlineUser] = {}
        self.updater_thread = threading.Thread(target=self.update_online_users_periodically)
        self.start_online_users_updater()

    def setup_ui(self):
        layout = QHBoxLayout()

        # === LEFT SIDE: User list (chat contacts) ===
        self.users_layout.addWidget(self.users_list_widget)

        # self.users_list_widget.itemSelectionChanged.connect() # TODO

        # === RIGHT SIDE: Chat area ===
        chat_layout = QVBoxLayout()
        self.chat_display.setReadOnly(True)
        self.message_input.setMaximumHeight(100)
        self.send_button.clicked.connect(self.send_message)

        chat_layout.addWidget(self.chat_display)
        chat_layout.addWidget(self.message_input)
        chat_layout.addWidget(self.send_button)

        layout.addLayout(self.users_layout, 1)
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
        self.other_online_users_list.clear()
        for user in online_users:
            if user.username != self.online_user.username:
                self.other_online_users_list[user.username] = user
                # Update peer connection info with public key
                self.peer_connection.update_peer(
                    username=user.username,
                    ip=user.ip_address,
                    port=user.port,
                    public_key=user.public_key
                )

    def start_online_users_updater(self):
        """Start thread to update online users list"""
        self.updater_thread.daemon = True
        self.updater_thread.start()

    def update_online_users_periodically(self):
        while self.isRunning:
            try:
                # Get online users from server
                online_users = fetch_online_users()
                self.update_online_users(online_users)
                self.get_other_users_info()
                self.refresh_ui_signal.emit()
            except Exception as e:
                self.log.append_log(f"Error updating online users: {str(e)}")
                print(e)
            time.sleep(5)  # Update every 5 seconds

    def refresh_user_list_ui(self):
        self.users_list_widget.clear()

        sorted_boxes = sorted(
            self.other_users_list.values(),
            key=lambda box: box.latest_message_timestamp.timestamp,
            reverse=True
        )

        for box in sorted_boxes:
            list_item = QListWidgetItem()
            mo = Morph(box.image_bytes, box.display_name, box.subtitle, box.latest_message_timestamp, box.is_online, box.username, box.has_unread)
            list_item.setSizeHint(mo.sizeHint())
            self.users_list_widget.addItem(list_item)
            self.users_list_widget.setItemWidget(list_item, mo)

    def get_other_users_info(self):
        latest_messages = self.local_database.get_latest_messages_per_user(self.get_aes_key())
        self.other_users_list.clear()
        temp_online_dict: Dict[str, OnlineUser] = self.other_online_users_list.copy()
        for message in latest_messages:
            # image profile, user display  name, online
            is_online = False
            profile_image_bytes = b''
            display_name = ""
            if message.recipient_username in temp_online_dict:
                profile_image_bytes = temp_online_dict[message.recipient_username].profile_picture
                display_name = temp_online_dict[message.recipient_username].name
                del temp_online_dict[message.recipient_username]
                is_online = True
            else:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect(('127.0.0.1', PORT))
                    s.send(CLIENT_GET_DISPLAY_NAME.encode())
                    s.recv(1024).decode() # server okay
                    s.send(message.recipient_username.encode())
                    display_name = s.recv(1024).decode()
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect(('127.0.0.1', PORT))
                    s.send(CLIENT_GET_PROFILE_PICTURE.encode())
                    s.recv(1024) # server okay
                    s.send(message.recipient_username.encode())
                    profile_image_bytes = receive_image_bytes_from_socket(s)
            has_unread: bool
            if message.is_income:
                has_unread = not message.is_read
            else:
                has_unread = True
            self.other_users_list[message.recipient_username] = OtherUsersBox(profile_image_bytes, display_name, message.message.decode(), message.timestamp, is_online, message.recipient_username, has_unread)

        for user in temp_online_dict.values():
            self.other_users_list[user.username] = OtherUsersBox(user.profile_picture, user.name, "", Timestamp.get_now(), True, user.username, False)

    def close_threads(self):
        """Clean up threads and connections"""
        self.isRunning = False
        self.peer_connection.stop()
        if hasattr(self, 'updater_thread'):
            self.updater_thread.join(timeout=1)

    def get_private_key(self):
        key: str
        with open(f"users/{self.online_user.username}/private_key.key", "r") as private_key_file:
            key = private_key_file.read()
        return key

    # extracts aes key of user
    def get_aes_key(self):
        with open(f"users/{self.online_user.username}/aes_key.key", "rb") as f:
            return f.read()
