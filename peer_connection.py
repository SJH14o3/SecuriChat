import socket
import threading
import json
from typing import Dict, Callable
from local_database import LocalDatabase, MESSAGE_TYPE_TEXT
from message import OnionMessage, create_onion_message, receive_final_message, LocalMessage
from message import create_message_ack
from log import Log
from statics import *
from timestamp import Timestamp

CHUNK_SIZE = 8192

def get_message_database_type(type_: str) -> int:
    if type_ == "text":
        return MESSAGE_TYPE_TEXT
    else:
        return 0

class PeerConnection:
    def __init__(self, username: str, private_key: str, log: Log, receiver_socket: socket.socket, database: LocalDatabase, aes_key, menu):
        self.username = username
        self.private_key = private_key
        self.log = log
        self.peers: Dict[str, tuple] = {}  # username -> (ip, port, public_key)
        self.message_handlers: Dict[str, Callable] = {}
        self.is_running = True
        self.aes_key = aes_key
        
        # Create listening socket
        self.listener_socket = receiver_socket
        self.ip, self.port = self.listener_socket.getsockname()
        self.database = database
        
        # Start listening thread
        self.listener_socket.listen(10)
        self.listen_thread = threading.Thread(target=self._listen_for_connections)
        self.listen_thread.daemon = True
        self.listen_thread.start()

        self.menu = menu
        
        self.log.append_log(f"P2P Connection initialized for {username} on {self.ip}:{self.port}")

    def _listen_for_connections(self):
        """Listen for incoming peer connections"""
        while self.is_running:
            try:
                client_socket, address = self.listener_socket.accept()
                thread = threading.Thread(target=self._handle_peer_connection, args=(client_socket, address))
                thread.daemon = True
                thread.start()
            except Exception as e:
                if self.is_running:
                    self.log.append_log(f"Error in listener: {str(e)}")

    def handle_server_ping_response(self, peer_socket: socket.socket):
        self.log.append_log(f"responded to server ping")
        peer_socket.send(CLIENT_IS_ONLINE.encode())

    def handle_peer_message(self, peer_socket: socket.socket, address: tuple):
        self.log.append_log(f"Handling peer message from {address}")
        peer_socket.send(BUFFER.encode())
        message_type_ = int(peer_socket.recv(1024).decode())
        peer_socket.send(BUFFER.encode())
        suffix = peer_socket.recv(1024).decode()
        peer_socket.sendall(BUFFER.encode())
        # Step 3: Receive message with improved chunking
        message_data = b""
        chunks_count = int(peer_socket.recv(1024).decode())
        peer_socket.send(BUFFER.encode())
        for _ in range(chunks_count):
            message_data += peer_socket.recv(CHUNK_SIZE)
            peer_socket.send(BUFFER.encode())
        peer_socket.recv(1024) # sender okay
        if b"END_OF_MESSAGE" in message_data:
            message_data = message_data[:message_data.index(b"END_OF_MESSAGE")]

        if not message_data:
            self.log.append_log(f"No message data received from {address}")
            return

        # Step 4: Process message and send acknowledgment
        message_dict = receive_final_message(message_data, self.private_key)
        self.log.append_log(f"Successfully processed message from {message_dict.get('sender_id')}")

        # Send ready for ack signal
        peer_socket.sendall(CLIENT_ACK_OK.encode())
        peer_socket.recv(1024) # sender okay
        self.log.append_log(f"Sent ready for ack signal to {address}")

        # Send acknowledgment
        ack = create_message_ack(message_dict['message_id'], message_dict['sender_id'])
        ack_json = json.dumps(ack)
        ack_msg = ack_json + "END_OF_ACK"
        chunks = [ack_msg[i:i+CHUNK_SIZE] for i in range(0, len(ack_msg), CHUNK_SIZE)]
        chunks_count = len(chunks)
        peer_socket.send(f"{chunks_count}".encode())
        peer_socket.recv(1024) # sender okay
        for chunk in chunks:
            peer_socket.sendall(chunk.encode())
            peer_socket.recv(1024) # sender okay

        self.log.append_log(f"Sent acknowledgment to {address}")
        # Handle message type
        message_type = message_dict.get('message_type', 'text')
        local_message = LocalMessage(0, message_dict['sender_id'], message_type_, True, message_dict['content'], Timestamp.get_now(), False, suffix, self.username)
        self.database.store_message(local_message, self.aes_key, self.log)
        self.menu.emit_message_received_signal(local_message)
        self.log.append_log(f"Handled message of type {message_type} from {address}")

    def _handle_peer_connection(self, peer_socket: socket.socket, address: tuple):
        """Handle incoming peer connection"""
        try:
            peer_socket.settimeout(10)  # 10 second timeout
            request = peer_socket.recv(1024).decode().strip()
            self.log.append_log(f"Received request '{convert_to_request_name(request)}' from {address}")
            # Handle server ping
            if request == SERVER_PING:
                self.handle_server_ping_response(peer_socket)
            # Handle peer message
            elif request == CLIENT_PEER_MESSAGE:
                self.handle_peer_message(peer_socket, address)
            else:
                self.log.append_log(f"Unknown request type from {address}: {request}")

        except Exception as e:
            print(f"[RECEIVE] Error in connection handler for {address}: {str(e)}")
            self.log.append_log(f"Error in connection handler for {address}: {str(e)}")
        finally:
            try:
                peer_socket.close()
            except Exception as e:
                self.log.append_log(f"Error in final clause for _handle_peer_connection: {str(e)}")

    def send_message(self, recipient_username: str, message_content: bytes, message_type: int, suffix: str = 'text') -> bool:
        """Send a message to a peer"""
        if recipient_username not in self.peers:
            self.log.append_log(f"Unknown recipient: {recipient_username}")
            print(f"[SEND] Recipient username '{recipient_username}' not in peers")
            return False

        try:
            # Get recipient info first
            recipient_ip, recipient_port, recipient_public_key = self.peers[recipient_username]

            # Create message object
            message = OnionMessage(
                content=message_content,
                sender_id=self.username,
                recipient_id=recipient_username,
                message_type=message_type
            )
            # Add encryption layer
            try:
                message.add_layer(
                    node_public_key=recipient_public_key,
                    next_address=(recipient_ip, str(recipient_port))
                )
            except Exception as e:
                print(f"[SEND] Failed to add encryption for {recipient_username}: {str(e)}")
                return False
            
            # Create encrypted message
            try:
                encrypted_message = create_onion_message(message, self.private_key)
            except Exception as e:
                print(f"[SEND] Failed to create encrypted message for {recipient_username}: {str(e)}")
                return False

            # Send message
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(15)  # 15 second timeout
                
                with s:
                    s.connect((recipient_ip, int(recipient_port)))
                    s.sendall(CLIENT_PEER_MESSAGE.encode())
                    try:
                        ready_signal = s.recv(1024).decode().strip()
                        if ready_signal != BUFFER:
                            raise Exception(f"Expected {BUFFER}, got: '{ready_signal}'")
                    except Exception as e:
                        print(f"[SEND] Failed to get valid ready signal from {recipient_username}: {str(e)}")
                        return False
                    s.send(f"{message_type}".encode())
                    s.recv(1024) # other user OK
                    s.send(f"{suffix}".encode())
                    s.recv(1024) # other user OK
                    # Send encrypted message in chunks
                    msg_with_end = encrypted_message + b"END_OF_MESSAGE"
                    chunks = [msg_with_end[i:i + CHUNK_SIZE] for i in range(0, len(msg_with_end), CHUNK_SIZE)]
                    chunks_count = len(chunks)
                    s.send(f"{chunks_count}".encode())
                    s.recv(1024) # receiver okay
                    for i in range(chunks_count):
                        s.sendall(chunks[i])
                        s.recv(1024) # receiver okay
                    s.send(BUFFER.encode())
                    # Wait for ready for ack signal
                    ack_ready = s.recv(1024).decode()
                    if ack_ready != CLIENT_ACK_OK:
                        raise Exception(f"Expected READY_FOR_ACK, got: '{ack_ready}'")
                    s.send(BUFFER.encode())
                    chunks_count = int(s.recv(1024).decode())
                    ack_data = b""
                    s.send(BUFFER.encode())
                    for i in range(chunks_count):
                        ack_data += s.recv(CHUNK_SIZE)
                        s.send(BUFFER.encode())
                    if b"END_OF_ACK" in ack_data:
                        ack_data = ack_data[:ack_data.index(b"END_OF_ACK")]
                    # Process acknowledgment
                    ack_json = ack_data.decode()

                    ack = json.loads(ack_json)
                    if ack.get('type') == 'ack' and ack.get('message_id') == message.message_id:
                        local_message = LocalMessage(0, recipient_username, message_type, False, message_content, Timestamp.get_now(), True, suffix, self.username)
                        self.database.store_message(local_message, self.aes_key, self.log)
                        return True

                    print(f"[SEND] Invalid ack from {recipient_username} - Type: {ack.get('type')}, Expected ID: {message.message_id}, Got ID: {ack.get('message_id')}")
                    return False

            except Exception as e:
                print(f"[SEND] Error in message sending to {recipient_username}: {str(e)}")
                return False

        except Exception as e:
            print(f"[SEND] Unexpected error sending to {recipient_username}: {str(e)}")
            return False

    def update_peer(self, username: str, ip: str, port: int, public_key: str):
        """Update or add a peer's connection information"""
        self.peers[username] = (ip, str(port), public_key)
        self.log.append_log(f"Updated peer information for {username}: {ip}:{port}")

    def remove_peer(self, username: str):
        """Remove a peer from the connection list"""
        if username in self.peers:
            del self.peers[username]
            self.log.append_log(f"Removed peer: {username}")

    def stop(self):
        """Stop the peer connection"""
        self.is_running = False
        self.listener_socket.close()
        self.log.append_log("P2P Connection stopped") 