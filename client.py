import socket
import threading
import random
import time
import json
import sys

from PySide6.QtCore import QRegularExpression, QTimer
from PySide6.QtGui import QRegularExpressionValidator

from statics import *
from server import PORT
from user import User
from log import Log
from PySide6.QtWidgets import QApplication, QWidget, QPushButton, QVBoxLayout, QLabel, QLineEdit, QMessageBox

isRunning = True # useful to finish threads
ip_address = None # ip address of incoming messages socket for this client
port: int = 0 # port of incoming messages socket for this client
log: Log # log file, it will be initialized after a successful login/sign in. name is socket of incoming messages
window: QWidget # window of UI


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
            socket_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket_connection.connect(('127.0.0.1', PORT))
            socket_connection.send(CLIENT_FETCH_ONLINE_USERS_REQUEST.encode())
            data = socket_connection.recv(4096).decode()
            user_dicts = json.loads(data)
            users = [User(**d) for d in user_dicts]
            global ip_address, port
            for user in users:
                if user.address_is_equal(port, ip_address):
                    users.remove(user)
                    break
            log.append_users_logs("other online users fetched" ,users)
            time.sleep(5)
        except:
            print("something went wrong")

# temporarily and will be removed later on
def temporary_signin(conn: socket):
    conn.send(CLIENT_TEMPORARILY_LOGIN_REQUEST.encode())
    response = conn.recv(1024).decode()
    if response != SERVER_OK:
        raise Exception("Server login failed")
    receiver_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    receiver_socket.bind(('127.0.0.1', 0))
    local_port = receiver_socket.getsockname()[1]
    global log
    log = Log(f"{local_port}")
    username = f"client#{random.randint(0,1000)}?{local_port}"
    # making client ready to response before telling server that we are online
    income_connection = threading.Thread(target=receive_connection, args=(receiver_socket, local_port, receiver_socket.getsockname()[0]))
    income_connection.start()
    conn.send(f"{username}".encode())
    response = conn.recv(1024).decode()
    if response != SERVER_LOGIN_OK:
        raise Exception("Server login failed")

    fetch_users_thread = threading.Thread(target=fetch_online_users)
    fetch_users_thread.start()
    conn.send(CLIENT_LOG_OFF.encode())
    response = conn.recv(1024).decode()
    if response != SERVER_LOG_OFF_OK:
        raise Exception("Server logoff failed")
    conn.close()
    while isRunning:
        time.sleep(1)

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
        # server is online
        temporary_signin(socket_connection)

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

# handling messages that are sent to client in a thread
def handle_income_connection(conn: socket, addr):
    global ip_address, port
    while isRunning:
        request = conn.recv(1024).decode()
        if request == SERVER_PING: # responding to server ping which happens every 3 seconds
            conn.send(CLIENT_IS_ONLINE.encode())
            log.append_log("responded to server ping")


# client will wait for connections and creates a thread for each thread
def receive_connection(conn, conn_port: int, conn_addr):
    global ip_address, port
    port = conn_port
    ip_address = conn_addr
    conn.listen(10)
    while isRunning:
        transmitter, address = conn.accept()
        thread = threading.Thread(target=handle_income_connection, args=(transmitter, conn))
        thread.start()

# UI class for logging in scene
class UI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SecuriChat")
        self.setFixedSize(300, 200)
        self.connected = False
        self.error_message = None
        self.connect_to_server()
        # if connection to server was successful, then we will show the login scene
        if self.connected:
            self.switch_button = QPushButton("Switch to Sign Up")
            self.login_button = QPushButton("Log In")
            self.password_input = QLineEdit()
            self.password_label = QLabel("Password:")
            self.username_input = QLineEdit()
            self.username_label = QLabel("Username:")
            self.setup_ui()
            self.show()
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
        # TODO: complete implementation
        if self.username_input.hasAcceptableInput() and self.password_input.hasAcceptableInput():
            QMessageBox.information(self, "Success", "Inputs are valid!")
        else:
            QMessageBox.warning(self, "Error", "Invalid username or password format.")

    # setting up log in scene
    def setup_ui(self):

        username_regex = QRegularExpression(r"^[a-zA-Z0-9_.-]{3,20}$")
        self.username_input.setValidator(QRegularExpressionValidator(username_regex))

        self.password_input.setEchoMode(QLineEdit.Password)
        password_regex = QRegularExpression(r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@$!%*?&]{6,}$")
        self.password_input.setValidator(QRegularExpressionValidator(password_regex))

        self.login_button.clicked.connect(self.validate_inputs)

        layout = QVBoxLayout()
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_input)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.login_button)
        layout.addWidget(self.switch_button)

        self.setLayout(layout)
        self.show()


def main():
    app = QApplication(sys.argv)
    window = UI()
    sys.exit(app.exec())

if __name__ == '__main__':
    main()