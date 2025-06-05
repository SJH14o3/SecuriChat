import socket
import threading
import random
import os
import json
import sys
from PIL import Image
from PySide6.QtCore import QRegularExpression, QTimer, Qt, QByteArray, QBuffer, QIODevice
from PySide6.QtGui import QRegularExpressionValidator, QPixmap, QIcon, QColor, QImage, QPainter
import client_chat_page
import timestamp
from statics import *
from server import PORT
from onlineuser import OnlineUser
from log import Log
from PySide6.QtWidgets import QApplication, QWidget, QPushButton, QVBoxLayout, QLabel, QLineEdit, QMessageBox, \
    QFileDialog, QColorDialog, QStackedWidget
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from client_chat_page import ClientChatMenu
import local_database

USERNAME_REGEX = r"^[a-zA-Z0-9_.-]{3,20}$"
PASSWORD_REGEX = r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@$!%*?&]{6,}$"

isRunning = True # useful to finish threads
ip_address = None # ip address of incoming messages socket for this client
port: int = 0 # port of incoming messages socket for this client
receiver_socket: socket.socket # this instance is sent for online client
log: Log # log file, it will be initialized after a successful login/sign in. name is socket of incoming messages

def store_key(private_key, username: str):
    os.makedirs("users", exist_ok=True)
    os.makedirs(f"users/{username}", exist_ok=True)
    with open(f"users/{username}/private_key.key", "w") as f:
        f.write(private_key)

# generates public and private keys using RSA-2048
def generate_public_and_private_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Get public key from it
    public_key = private_key.public_key()

    # Serialize public key to store in database (PEM format as string)
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    # Serialize private key (optional, for storing on client securely)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()  # You can use password-based encryption here
    ).decode('utf-8')

    return private_pem, public_pem

# generates and stores AES key for a new signed-in user
def generate_and_store_aes_key(username):
    aes_key = os.urandom(32)  # 256-bit key
    os.makedirs(f"users/{username}", exist_ok=True)
    with open(f"users/{username}/aes_key.key", "wb") as f:
        f.write(aes_key)

# trying to log in user
def log_in(username, password, main_window):
    socket_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket_connection.connect(('127.0.0.1', PORT))
    socket_connection.send(CLIENT_LOGIN_REQUEST.encode())
    result = socket_connection.recv(1024).decode()
    # first we send everything other than profile image in json format
    info = {
        "username": username,
        "password": password
    }
    socket_connection.send(json.dumps(info).encode())
    db_result = socket_connection.recv(1024).decode()
    if db_result == DATABASE_LOGIN_SUCCESS:
        global receiver_socket
        receiver_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        receiver_socket.bind(('127.0.0.1', 0))
        rx_ip_address, local_port = receiver_socket.getsockname()
        socket_connection.send(f"{rx_ip_address}:{local_port}".encode())
        global ip_address, port, log
        ip_address = rx_ip_address
        port = local_port
        log = Log(f"{port}")
        data = socket_connection.recv(4096).decode()
        online_user = OnlineUser.from_json(data)
        socket_connection.send(BUFFER.encode())
        profile_image = client_chat_page.receive_image_bytes_from_socket(socket_connection)
        online_user.profile_picture = profile_image
        main_window.switch_to_logged_in_client(online_user)
        return True, None
    else:
        invalid = "invalid"
        con = convert_to_request_name(db_result)
        socket_connection.close()
        return False, db_result if invalid == con else con

# trying to sign in user
def sign_up(username: str, password: str, email:str, profile_image: bytes, display_name:str, main_window):
    private_key_bytes , public_key_bytes = generate_public_and_private_keys()
    socket_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket_connection.connect(('127.0.0.1', PORT))
    socket_connection.send(CLIENT_SIGN_IN_REQUEST.encode())
    result = socket_connection.recv(1024).decode()
    if result != SERVER_OK:
        raise Exception("Server error")
    # first we send everything other than profile image in json format
    info = {
        "username": username,
        "password": password,
        "email": email,
        "public_key": public_key_bytes,
        "display_name": display_name
    }
    socket_connection.send(json.dumps(info).encode())
    result = socket_connection.recv(1024).decode()
    if result != SERVER_OK:
        raise Exception("Server error")
    # secondly we send the size of image to server
    socket_connection.sendall(len(profile_image).to_bytes(4, byteorder="big"))
    result = socket_connection.recv(1024).decode()
    if result != SERVER_OK:
        raise Exception("Server error")
    # lastly we send the image
    socket_connection.sendall(profile_image)
    result = socket_connection.recv(1024).decode()
    if result != SERVER_OK:
        raise Exception("Server error")
    socket_connection.send(BUFFER.encode())
    db_result = socket_connection.recv(1024).decode()
    if db_result != DATABASE_SIGNIN_SUCCESS:
        return False, db_result
    else:
        global receiver_socket
        receiver_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        receiver_socket.bind(('127.0.0.1', 0))
        rx_ip_address, local_port = receiver_socket.getsockname()
        socket_connection.send(f"{rx_ip_address}:{local_port}".encode())
        global ip_address, port, log
        ip_address = rx_ip_address
        port = local_port
        log = Log(f"{port}")
        store_key(private_key_bytes, username)
        generate_and_store_aes_key(username)
        local_database.create_database(username)
        online_user = OnlineUser(ip_address, port, display_name, username,public_key_bytes, profile_image, timestamp.Timestamp.get_now())
        main_window.switch_to_logged_in_client(online_user)
    socket_connection.close()
    return True, None

# first make sure that server is online, then sign-in/login process
def connect_to_server():
    try:
        socket_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # TCP connection
        socket_connection.bind(('127.0.0.1', 0))  # 0 for port means that an available port will be assigned
        socket_connection.connect(('127.0.0.1', PORT))
        socket_connection.send(CLIENT_CHECK_SERVER_AVAILABILITY.encode())
        response = socket_connection.recv(1024).decode()
        if response != SERVER_CONNECT_OK:
            raise Exception("Server response was invalid")

    except ConnectionRefusedError:
        print("Connection refused: make sure server is running.")
    except socket.gaierror as e:
        print(f"Invalid address: {e}")
    except TimeoutError:
        print("Connection timed out: Server took too long to respond.")
    except socket.error as e:
        print(f"Socket error: {e}.")
    except Exception as e:
        print(e)

# UI class for logging in scene
class LoginPage(QWidget):
    def __init__(self, switch_to_signin_callback, main_window: QStackedWidget):
        super().__init__()
        self.connected = False
        self.error_message = None
        self.connect_to_server()
        self.window = main_window
        # if connection to server was successful, then we will show the login scene
        if self.connected:
            self.switch_to_signin_callback = switch_to_signin_callback
            self.pixmap = QPixmap("icon.png").scaled(150, 150)
            self.label = QLabel(self)
            self.switch_button = QPushButton("Switch to Sign Up")
            self.login_button = QPushButton("Log In")
            self.password_input = QLineEdit()
            self.password_label = QLabel("Password:")
            self.username_input = QLineEdit()
            self.username_label = QLabel("Username:")
            self.setup_ui()
            main_window.show()
        else:
            # if it wasn't then an error is shown and program will exit
            QTimer.singleShot(0, self.show_connection_failed_dialog)

    # show the error dialog when connection to server failed
    def show_connection_failed_dialog(self):
        QMessageBox.critical(self, "Critical Error", self.error_message)
        QApplication.quit()

    # first we need to try to connect to the server and make sure it's running
    def connect_to_server(self):
        try:
            socket_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket_connection.bind(('127.0.0.1', 0))
            socket_connection.connect(('127.0.0.1', PORT))
            socket_connection.send(CLIENT_CHECK_SERVER_AVAILABILITY.encode())
            response = socket_connection.recv(1024).decode()
            if response != SERVER_CONNECT_OK:
                self.error_message = "Server response was invalid"
            else:
                self.connected = True
        except ConnectionRefusedError:
            self.error_message = "Server did not respond\nMake sure server is running."
        except socket.gaierror:
            self.error_message = "Invalid address: Could not resolve hostname."
        except TimeoutError:
            self.error_message = "Connection timed out: Server took too long to respond."
        except socket.error as e:
            self.error_message = f"Socket error: {e}."
        except Exception as e:
            self.error_message = f"Unknown error: {e}."

    # we validate user input
    def validate_inputs(self):
        if not self.username_input.hasAcceptableInput():
            QMessageBox.critical(self, "Error", "Invalid username format\nusername must contain only letters, numbers and underscores,\n with 3 to 20 characters")
        elif not self.password_input.hasAcceptableInput():
            QMessageBox.critical(self, "Error", "Invalid password format\npassword must contain only letters, numbers and punctuations,\n with at one digit and one letter and at least 6 characters")
        else:
            result, error = log_in(self.username_input.text(), self.password_input.text(), self.window)
            if result:
                print("login successful")
            else:
                QMessageBox.critical(self, "Error", f"login failed: {error}")

    # setting up log in scene
    def setup_ui(self):

        username_regex = QRegularExpression(USERNAME_REGEX)
        self.username_input.setValidator(QRegularExpressionValidator(username_regex))

        self.password_input.setEchoMode(QLineEdit.Password)
        password_regex = QRegularExpression(PASSWORD_REGEX)
        self.password_input.setValidator(QRegularExpressionValidator(password_regex))

        self.login_button.clicked.connect(self.validate_inputs)
        self.switch_button.clicked.connect(self.switch_to_signin_callback)

        self.label.setPixmap(self.pixmap)
        self.label.setAlignment(Qt.AlignCenter)

        layout = QVBoxLayout()
        layout.addWidget(self.label)
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_input)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.login_button)
        layout.addWidget(self.switch_button)

        self.setLayout(layout)

# sign in page handler
class SigninPage(QWidget):
    def __init__(self, switch_to_login_callback, main_window: QStackedWidget):
        super().__init__()
        self.setWindowTitle("Sign Up")
        self.pixmap = QPixmap("icon.png").scaled(150, 150)
        self.main_window = main_window
        self.label = QLabel(self)
        self.username_input = QLineEdit()
        self.password_input = QLineEdit()
        self.email_input = QLineEdit()
        self.display_name_input = QLineEdit()

        self.image_label = QLabel()
        self.image_label.setFixedSize(300, 300)
        self.image_label.setAlignment(Qt.AlignCenter)

        self.profile_image_path = "user_profile.png"  # initial image
        self.load_initial_profile_image()

        self.pick_image_button = QPushButton("Select Image from your device")
        self.pick_image_button.clicked.connect(self.select_image)

        self.color_button = QPushButton("Pick Background Color")
        self.color_button.clicked.connect(self.select_color)

        self.confirm_button = QPushButton("Confirm")
        self.confirm_button.clicked.connect(self.validate_inputs)

        self.switch_button = QPushButton("Switch to Login")
        self.switch_button.clicked.connect(switch_to_login_callback)

        self.init_validators()
        self.setup_ui()

    def setup_ui(self):
        self.label.setPixmap(self.pixmap)
        self.label.setAlignment(Qt.AlignCenter)

        layout = QVBoxLayout()
        layout.addWidget(self.label)
        layout.addWidget(QLabel("Username:"))
        layout.addWidget(self.username_input)

        layout.addWidget(QLabel("Password:"))
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_input)

        layout.addWidget(QLabel("Email:"))
        layout.addWidget(self.email_input)

        layout.addWidget(QLabel("Display Name:"))
        layout.addWidget(self.display_name_input)

        layout.addWidget(self.image_label)
        layout.addWidget(self.color_button)
        layout.addWidget(self.pick_image_button)

        layout.addWidget(self.confirm_button)
        layout.addWidget(self.switch_button)

        self.setLayout(layout)

    def init_validators(self):
        self.username_input.setValidator(QRegularExpressionValidator(QRegularExpression(USERNAME_REGEX)))
        self.password_input.setValidator(QRegularExpressionValidator(QRegularExpression(PASSWORD_REGEX)))
        self.email_input.setValidator(QRegularExpressionValidator(QRegularExpression(r"^[\w\.-]+@[\w\.-]+\.\w+$")))

    def load_initial_profile_image(self):
        color = QColor(random.randint(0,255), random.randint(0,255), random.randint(0,255))
        self.update_profile_image_with_color(color)

    def update_profile_image_with_color(self, color):
        pixmap = QPixmap(self.profile_image_path).scaled(300, 300, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        image = QImage(300, 300, QImage.Format_ARGB32)
        image.fill(color)

        painter = QPainter(image)
        painter.drawPixmap(0, 0, pixmap)
        painter.end()

        self.image_label.setPixmap(QPixmap.fromImage(image))
        self.final_image = image

    def select_color(self):
        color = QColorDialog.getColor()
        if color.isValid():
            self.update_profile_image_with_color(color)

    def select_image(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Image", "", "Images (*.png *.jpg *.jpeg)")
        if path:
            img = Image.open(path)
            size = min(img.size)
            img = img.crop(((img.width - size) // 2, (img.height - size) // 2,
                            (img.width + size) // 2, (img.height + size) // 2))
            img = img.resize((300, 300))
            img.save("temp_profile.png")
            self.profile_image_path = "temp_profile.png"
            self.update_profile_image_with_color(QColor(255, 255, 255))  # default white

    def validate_inputs(self):
        if not self.username_input.hasAcceptableInput():
            self.show_error("Invalid username format\nusername must contain only letters, numbers and underscores,\n with 3 to 20 characters")
            return
        if not self.password_input.hasAcceptableInput():
            self.show_error("Invalid password format\npassword must contain only letters, numbers and punctuations,\n with at one digit and one letter and at least 6 characters")
            return
        if not self.email_input.hasAcceptableInput():
            self.show_error("Invalid email format.")
            return
        if self.display_name_input.text().strip() == "":
            self.show_error("Display name cannot be empty.")
            return

        byte_image = convert_q_image_to_bytes(self.final_image)

        # Call backend function
        result, error_message = sign_up(self.username_input.text(), self.password_input.text(), self.email_input.text(), byte_image, self.display_name_input.text(), self.main_window)
        if result:
            QMessageBox.information(self, "Success", "Signed up successfully!")
        else:
            print(error_message)
            QMessageBox.critical(self, "Error", f"Sign up failed: {convert_to_request_name(error_message)}")

    def show_error(self, message):
        QMessageBox.critical(self, "Validation Error", message)

# a main window for switching fast between login and sign in pages
class MainWindow(QStackedWidget):
    def __init__(self):
        super().__init__()
        self.login_page= LoginPage(self.show_signin, self)
        self.signin_page = SigninPage(self.show_login, self)
        self.addWidget(self.login_page)
        self.addWidget(self.signin_page)
        self.setCurrentIndex(0)
        self.setFixedSize(300, 350)
        self.setWindowTitle("SecuriChat")
        self.logged_in = False

    def show_signin(self):
        self.setFixedSize(300, 800)
        self.setCurrentIndex(1)

    def show_login(self):
        self.setFixedSize(300, 350)
        self.setCurrentIndex(0)

    def switch_to_logged_in_client(self, online_user: OnlineUser):
        global receiver_socket, log
        self.logged_in = True
        self.setWindowTitle(f"SecuriChat - {online_user.username}")
        self.setFixedSize(1000, 800)
        self.chat_page = ClientChatMenu(online_user, receiver_socket, log)
        self.addWidget(self.chat_page)
        self.setCurrentWidget(self.chat_page)

    def closeEvent(self, event):
        if self.logged_in:
            self.chat_page.isRunning = False
            self.chat_page.close_threads()

def main():
    app = QApplication(sys.argv)
    app.setWindowIcon(QIcon("icon.png"))
    global window
    window = MainWindow()
    sys.exit(app.exec())

if __name__ == '__main__':
    main()