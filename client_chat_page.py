import mimetypes
import os
import socket
import threading
import time
from typing import List, Dict

from PySide6.QtGui import QPixmap, QColor, QPainter, QDesktopServices, QIcon
from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QTextEdit, QListWidget, \
    QSizePolicy, QListWidgetItem, QMessageBox, QFileDialog, QStyle
from PySide6.QtCore import Qt, QSize, Signal, QUrl
from win10toast import ToastNotifier
import local_database
from log import Log
from message import LocalMessage
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

def show_new_message_notification(local_message: LocalMessage):
    content = "message"
    if local_message.message_type == local_database.MESSAGE_TYPE_TEXT:
        content = local_message.message.decode()
    elif local_message.message_type == local_database.MESSAGE_TYPE_IMAGE:
        content = "image"
    elif local_message.message_type == local_database.MESSAGE_TYPE_VIDEO:
        content = "video"
    elif local_message.message_type == local_database.MESSAGE_TYPE_AUDIO:
        content = "audio"
    else:
        content = "file"
    notifier = ToastNotifier()
    notifier.show_toast(f"New message from {local_message.recipient_username}", content)

class OtherUsersBox:
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
        elided_text = metrics.elidedText(subtitle, Qt.ElideRight, 200)
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

class MessageBubble(QWidget):
    def __init__(self, timestamp: str, is_income: bool):
        super().__init__()
        self.timestamp = timestamp
        self.is_income = is_income
        self.layout = QVBoxLayout()
        self.layout.setContentsMargins(10, 5, 10, 5)
        self.timestamp_label = QLabel(timestamp)
        self.timestamp_label.setStyleSheet("font-size: 10px; color: gray;")
        self.timestamp_label.setAlignment(Qt.AlignRight)
        self.setLayout(self.layout)

    def set_a_widget_style(self, widget: QWidget):
        widget.setStyleSheet(
            "background-color: #898989; border-radius: 10px; padding: 5px;" if self.is_income else
            "background-color: #C17D1D; color: white; border-radius: 10px; padding: 5px;"
        )

    def apply_tinted_effect(self):
        # Get original pixmap
        icon = self.style().standardIcon(QStyle.SP_MediaPlay)
        pixmap = icon.pixmap(32, 32)

        # Create tinted white pixmap
        tinted = QPixmap(pixmap.size())
        tinted.fill(Qt.transparent)

        painter = QPainter(tinted)
        painter.setCompositionMode(QPainter.CompositionMode_Source)
        painter.drawPixmap(0, 0, pixmap)
        painter.setCompositionMode(QPainter.CompositionMode_SourceIn)
        painter.fillRect(tinted.rect(), QColor("white"))
        painter.end()
        return tinted


class TextMessageBubble(MessageBubble):
    def __init__(self, text: str, timestamp: str, is_income: bool):
        super().__init__(timestamp, is_income)

        bubble = QLabel(text)
        bubble.setWordWrap(True)
        self.set_a_widget_style(bubble)

        self.layout.addWidget(bubble)
        self.layout.addWidget(self.timestamp_label)
        self.layout.setAlignment(Qt.AlignLeft if is_income else Qt.AlignRight)

class ImageMessageBubble(MessageBubble):
    def __init__(self, image_bytes, timestamp, is_income):
        super().__init__(timestamp, is_income)
        pixmap = QPixmap()
        pixmap.loadFromData(image_bytes)
        pixmap = pixmap.scaled(300, 300, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        label = QLabel()
        label.setPixmap(pixmap)
        label.setFixedSize(pixmap.size())
        label.setMinimumSize(100, 100)
        label.setMaximumSize(300, 300)

        self.layout.addWidget(label)
        self.layout.addWidget(self.timestamp_label)
        self.layout.setAlignment(Qt.AlignLeft if is_income else Qt.AlignRight)

class VideoMessageBubble(MessageBubble):
    def __init__(self, file_path, timestamp, is_income):
        super().__init__(timestamp, is_income)
        self.file_path = file_path
        self.play_button = QPushButton("play video")
        self.play_button.setIcon(QIcon(self.apply_tinted_effect()))
        self.play_button.clicked.connect(self.play_video)
        self.set_a_widget_style(self.play_button)
        self.layout.addWidget(self.play_button)
        self.layout.addWidget(self.timestamp_label)
        self.layout.setAlignment(Qt.AlignLeft if is_income else Qt.AlignRight)

    def play_video(self):
        QDesktopServices.openUrl(QUrl.fromLocalFile(self.file_path))

class AudioMessageBubble(MessageBubble):
    def __init__(self, file_path, timestamp, is_income):
        super().__init__(timestamp, is_income)
        self.file_path = file_path
        self.play_button = QPushButton("play audio")
        self.play_button.setIcon(QIcon(self.apply_tinted_effect()))
        self.play_button.clicked.connect(self.play_audio)
        self.set_a_widget_style(self.play_button)

        self.layout.addWidget(self.play_button)
        self.layout.addWidget(self.timestamp_label)
        self.layout.setAlignment(Qt.AlignLeft if is_income else Qt.AlignRight)

    def play_audio(self):
        QDesktopServices.openUrl(QUrl.fromLocalFile(self.file_path))

class FileMessageBubble(MessageBubble):
    def __init__(self, file_path, timestamp, is_income):
        super().__init__(timestamp, is_income)
        filename = os.path.basename(file_path)
        self.open_button = QPushButton(f"Open file")
        self.open_button.clicked.connect(self.open_file)
        self.open_button.setIcon(self.style().standardIcon(QStyle.SP_FileIcon))
        self.set_a_widget_style(self.open_button)

        self.layout.addWidget(self.open_button)
        self.layout.addWidget(self.timestamp_label)
        self.layout.setAlignment(Qt.AlignLeft if is_income else Qt.AlignRight)
        self.file_path = file_path

    def open_file(self):
        QDesktopServices.openUrl(QUrl.fromLocalFile(self.file_path))

class ClientChatMenu(QWidget):
    refresh_ui_signal = Signal()
    message_received_signal = Signal()
    def __init__(self, online_user: OnlineUser, receiver_socket, log: Log):
        super().__init__()
        self.online_user = online_user
        self.receiver_socket = receiver_socket
        self.log = log
        self.isRunning = True
        self.selected_user = None
        self.local_database = local_database.LocalDatabase(online_user.username)
        self.latest_messages = self.local_database.get_latest_messages_per_user(self.get_aes_key(), online_user.username)
        self.refresh_ui_signal.connect(self.refresh_user_list_ui)
        self.message_received_signal.connect(self.handle_text_message)
        self._suppress_selection_event = False
        self.attach_button = QPushButton("Send File")
        self.received_local_message: LocalMessage

        self.peer_connection = PeerConnection(
            username=online_user.username,
            private_key=self.get_private_key(),
            log=log,
            receiver_socket=self.receiver_socket,
            database=self.local_database,
            aes_key=self.get_aes_key(),
            menu=self
        )
        self.chat_list_widget = QListWidget()
        self.message_input = QTextEdit()
        self.send_button = QPushButton("Send Text")
        self.users_layout = QVBoxLayout()
        self.users_list_widget = QListWidget()

        self.setup_ui()
        self.other_users_list: Dict[str, OtherUsersBox] = {}
        self.other_online_users_list: Dict[str, OnlineUser] = {}
        self.updater_thread = threading.Thread(target=self.update_online_users_periodically)
        self.start_online_users_updater()

    def setup_ui(self):
        layout = QHBoxLayout()

        self.users_layout.addWidget(self.users_list_widget)
        self.users_list_widget.itemSelectionChanged.connect(self.on_user_selected)

        chat_layout = QVBoxLayout()
        self.chat_list_widget.setSpacing(5)
        self.chat_list_widget.setStyleSheet("border: none;")
        self.message_input.setMaximumHeight(100)
        self.message_input.setDisabled(True)

        h_layout = QHBoxLayout()
        self.send_button.clicked.connect(self.send_text_message)
        self.send_button.setIcon(self.style().standardIcon(QStyle.SP_ArrowForward))
        self.attach_button.setToolTip("Send text")
        self.send_button.setIconSize(QSize(24, 24))
        self.send_button.setDisabled(True)

        self.attach_button.setIcon(QIcon.fromTheme("document-open"))
        self.attach_button.setIconSize(QSize(24, 24))
        self.attach_button.setToolTip("Attach file")
        self.attach_button.clicked.connect(self.on_attach_file)
        self.attach_button.setDisabled(True)

        h_layout.addWidget(self.attach_button)
        h_layout.addWidget(self.send_button)

        chat_layout.addWidget(self.chat_list_widget)
        chat_layout.addWidget(self.message_input)
        chat_layout.addLayout(h_layout)

        layout.addLayout(self.users_layout, 1)
        layout.addLayout(chat_layout, 2)

        self.setLayout(layout)

    def on_user_selected(self):
        if getattr(self, '_suppress_selection_event', False):
            return  # Ignore selection if we're programmatically updating the list

        items = self.users_list_widget.selectedItems()
        if not items:
            return

        item = items[0]
        widget = self.users_list_widget.itemWidget(item)
        self.selected_user = widget.username

        self.message_input.setDisabled(not widget.is_online)
        self.send_button.setDisabled(not widget.is_online)
        self.attach_button.setDisabled(not widget.is_online)

        self.local_database.mark_messages_as_read_until_sent_or_read(widget.username)
        self.load_chat_history()

    def load_chat_history(self):
        scrollbar = self.chat_list_widget.verticalScrollBar()
        current_scroll = scrollbar.value()

        self.chat_list_widget.clear()
        if not self.selected_user:
            self.chat_list_widget.addItem(QListWidgetItem("Select a chat to start messaging."))
            self.message_input.setDisabled(True)
            self.send_button.setDisabled(True)
            self.attach_button.setDisabled(True)
            return

        messages = self.local_database.get_a_user_all_messages(self.selected_user, self.get_aes_key(), self.online_user.username)
        if not messages:
            item = QListWidgetItem()
            bubble = TextMessageBubble("Say hello to me!", "", True)
            item.setSizeHint(bubble.sizeHint())
            self.chat_list_widget.addItem(item)
            self.chat_list_widget.setItemWidget(item, bubble)
            return

        for msg in reversed(messages):  # reverse to show oldest first
            item = QListWidgetItem()
            time_pretty = msg.timestamp.get_time_pretty(False)
            bubble: MessageBubble
            if msg.message_type == local_database.MESSAGE_TYPE_TEXT:
                bubble = TextMessageBubble(msg.message.decode(), time_pretty, msg.is_income)
            elif msg.message_type == local_database.MESSAGE_TYPE_IMAGE:
                bubble = ImageMessageBubble(msg.message, time_pretty, msg.is_income)
            elif msg.message_type == local_database.MESSAGE_TYPE_VIDEO:
                bubble = VideoMessageBubble(msg.path, time_pretty, msg.is_income)
            elif msg.message_type == local_database.MESSAGE_TYPE_AUDIO:
                bubble = AudioMessageBubble(msg.path, time_pretty, msg.is_income)
            else:
                bubble = FileMessageBubble(msg.path, time_pretty, msg.is_income)

            item.setSizeHint(bubble.sizeHint())
            self.chat_list_widget.addItem(item)
            self.chat_list_widget.setItemWidget(item, bubble)

        max_scroll = scrollbar.maximum()
        distance_to_bottom = max_scroll - current_scroll

        if 0 == current_scroll or distance_to_bottom < 3:
            self.chat_list_widget.scrollToBottom()
        else:
            self.chat_list_widget.verticalScrollBar().setValue(current_scroll)

    def send_text_message(self):
        if not self.selected_user:
            return

        message = self.message_input.toPlainText().strip()
        if not message:
            error_dialog = QMessageBox(self)
            error_dialog.setIcon(QMessageBox.Critical)
            error_dialog.setWindowTitle("Message Error")
            error_dialog.setText("Input is empty")
            error_dialog.exec()

        success = self.peer_connection.send_message(self.selected_user, message.encode(), local_database.MESSAGE_TYPE_TEXT, "none")
        if success:
            self.message_input.clear()
            self.load_chat_history()
            self.chat_list_widget.scrollToBottom()
        else:
            error_dialog = QMessageBox(self)
            error_dialog.setIcon(QMessageBox.Critical)
            error_dialog.setWindowTitle("Message Error")
            error_dialog.setText("Failed to send the message.")
            error_dialog.exec()

    def on_attach_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Send")
        if not file_path:
            return  # user cancelled

        mime_type, _ = mimetypes.guess_type(file_path)
        file_type = local_database.MESSAGE_TYPE_FILE  # default

        if mime_type:
            if mime_type.startswith("image/"):
                file_type = local_database.MESSAGE_TYPE_IMAGE
            elif mime_type.startswith("video/"):
                file_type = local_database.MESSAGE_TYPE_VIDEO
            elif mime_type.startswith("audio/"):
                file_type = local_database.MESSAGE_TYPE_AUDIO

        # Read the file as bytes
        try:
            with open(file_path, "rb") as f:
                file_bytes = f.read()
            file_name = os.path.basename(file_path)
            suffix = os.path.splitext(file_name)[1].lstrip(".")
            self.send_file_message(file_bytes, file_type, suffix)
        except Exception as e:
            print(f"Failed to read file: {e}")

    def send_file_message(self, file_bytes: bytes, file_type: int, suffix):
        if not self.selected_user:
            return

        success = self.peer_connection.send_message(self.selected_user, file_bytes, file_type, suffix)
        if success:
            self.message_input.clear()
            self.load_chat_history()
            self.chat_list_widget.scrollToBottom()
        else:
            error_dialog = QMessageBox(self)
            error_dialog.setIcon(QMessageBox.Critical)
            error_dialog.setWindowTitle("Message Error")
            error_dialog.setText("Failed to send the message.")
            error_dialog.exec()

    def handle_text_message(self):
        if self.received_local_message.recipient_username == self.selected_user:
            self.load_chat_history()
        else:
            threading.Thread(target=show_new_message_notification, args=(self.received_local_message,)).start()


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
        self._suppress_selection_event = True  # 👈 suppress selection change handler temporarily

        self.users_list_widget.clear()
        sorted_boxes = sorted(
            self.other_users_list.values(),
            key=lambda box: box.latest_message_timestamp.timestamp,
            reverse=True
        )

        for box in sorted_boxes:
            list_item = QListWidgetItem()
            mo = Morph(box.image_bytes, box.display_name, box.subtitle, box.latest_message_timestamp, box.is_online,
                       box.username, box.has_unread)
            list_item.setSizeHint(mo.sizeHint())
            self.users_list_widget.addItem(list_item)
            self.users_list_widget.setItemWidget(list_item, mo)

        self._suppress_selection_event = False

        # Restore selection manually if user is already selected
        if self.selected_user:
            for i in range(self.users_list_widget.count()):
                widget = self.users_list_widget.itemWidget(self.users_list_widget.item(i))
                if widget.username == self.selected_user:
                    self.users_list_widget.setCurrentRow(i)
                    break

        if self.selected_user and self.selected_user in self.other_users_list:
            selected_box = self.other_users_list[self.selected_user]
            self.message_input.setDisabled(not selected_box.is_online)
            self.send_button.setDisabled(not selected_box.is_online)
            self.attach_button.setDisabled(not selected_box.is_online)

    def get_other_users_info(self):
        latest_messages = self.local_database.get_latest_messages_per_user(self.get_aes_key(), self.online_user.username)
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
                has_unread = False
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

    def emit_message_received_signal(self, message: LocalMessage):
        self.received_local_message = message
        self.message_received_signal.emit()