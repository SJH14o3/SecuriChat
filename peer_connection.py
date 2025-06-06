import socket
import threading
import json
import time
from typing import Dict, Optional, Callable

from local_database import LocalDatabase, MESSAGE_TYPE_TEXT, MESSAGE_TYPE_FILE
from message import OnionMessage, create_onion_message, create_onion_message_encrypted, process_onion_message, receive_final_message
from message import MessageError, create_message_ack
from local_message import LocalMessage
from log import Log
from statics import *
from timestamp import Timestamp

CHUNK_SIZE = 8192

def get_message_database_type(type_: str) -> int:
    if type_ == MESSAGE_TYPE_TEXT:
        return 0
    elif type_ == MESSAGE_TYPE_FILE:
        return 4
    else:
        return 0

class PeerConnection:
    def __init__(self, username: str, private_key: str, log: Log, receiver_socket: socket.socket, database: LocalDatabase, aes_key):
        self.username = username
        self.private_key = private_key
        self.log = log
        self.peers: Dict[str, tuple] = {}
        self.message_handlers: Dict[str, Callable] = {}
        self.is_running = True
        self.aes_key = aes_key
        self.listener_socket = receiver_socket
        self.ip, self.port = self.listener_socket.getsockname()
        self.database = database
        self.listener_socket.listen(10)
        self.listen_thread = threading.Thread(target=self._listen_for_connections)
        self.listen_thread.daemon = True
        self.listen_thread.start()
        self.log.append_log(f"P2P Connection initialized for {username} on {self.ip}:{self.port}")

    def register_message_handler(self, message_type: str, handler: Callable):
        self.message_handlers[message_type] = handler

    def _listen_for_connections(self):
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
        try:
            peer_socket.send(SERVER_OK.encode())  # Send OK response first
            
            # Receive message length first
            try:
                length_bytes = peer_socket.recv(4)
                if not length_bytes:
                    raise MessageError("Empty length received")
                message_length = int.from_bytes(length_bytes, byteorder='big')
                self.log.append_log(f"Received message length: {message_length} from {address}")
            except Exception as e:
                raise MessageError(f"Failed to receive message length: {str(e)}")

            peer_socket.send(SERVER_OK.encode())  # Acknowledge length receipt
            
            # Receive the full message
            try:
                encrypted_data = b''
                while len(encrypted_data) < message_length:
                    chunk = peer_socket.recv(min(8192, message_length - len(encrypted_data)))
                    if not chunk:
                        raise MessageError("Connection closed while receiving message")
                    encrypted_data += chunk
                self.log.append_log(f"Received full encrypted data of length {len(encrypted_data)} from {address}")
            except Exception as e:
                raise MessageError(f"Failed to receive message data: {str(e)}")
            
            # Decrypt and process message
            try:
                message_dict = receive_final_message(encrypted_data, self.private_key)
                message_type = message_dict.get('message_type', 'text')
                self.log.append_log(f"Successfully decrypted message of type {message_type} from {address}")
            except Exception as e:
                self.log.append_log(f"Decryption error details - Length: {len(encrypted_data)}, First 32 bytes: {encrypted_data[:32].hex()}")
                raise MessageError(f"Failed to decrypt message: {str(e)}")

            # Create and store local message
            try:
                local_message = LocalMessage(
                    message_id=0,
                    recipient_username=message_dict['sender_id'],
                    message_type=get_message_database_type(message_dict['message_type']),
                    is_income=True,
                    message=message_dict['content'].encode() if isinstance(message_dict['content'], str) else message_dict['content'],
                    timestamp=Timestamp.get_now(),
                    is_read=False,
                    file_name=message_dict.get('file_name'),
                    file_size=message_dict.get('file_size')
                )
                self.database.store_message(local_message, self.aes_key, self.log)
                self.log.append_log(f"Stored message from {message_dict['sender_id']} in database")
            except Exception as e:
                raise MessageError(f"Failed to store message: {str(e)}")

            # Handle message based on type
            if message_type in self.message_handlers:
                try:
                    self.message_handlers[message_type](message_dict)
                    self.log.append_log(f"Successfully handled message of type {message_type} from {address}")
                except Exception as e:
                    raise MessageError(f"Failed to handle message: {str(e)}")
            else:
                print(f"[RECEIVE] No handler for message type {message_type} from {address}")
                self.log.append_log(f"No handler for message type {message_type} from {address}")

            # Send acknowledgment
            try:
                ack = create_message_ack(message_dict['message_id'], message_dict['sender_id'])
                ack_json = json.dumps(ack)
                ack_bytes = ack_json.encode()
                peer_socket.send(len(ack_bytes).to_bytes(4, byteorder='big'))  # Send length first
                peer_socket.recv(1024)  # Wait for length acknowledgment
                peer_socket.send(ack_bytes)  # Send actual data
                peer_socket.recv(1024)  # Wait for final confirmation
                self.log.append_log(f"Sent acknowledgment for message {message_dict['message_id']}")
            except Exception as e:
                raise MessageError(f"Failed to send acknowledgment: {str(e)}")

        except Exception as e:
            print(f"[RECEIVE] Error in connection handler for {address}: {str(e)}")
            self.log.append_log(f"Error in connection handler for {address}: {str(e)}")
        finally:
            try:
                peer_socket.close()
            except Exception as e:
                self.log.append_log(f"Error in final clause for _handle_peer_connection: {str(e)}")

    def _handle_peer_connection(self, peer_socket: socket.socket, address: tuple):
        try:
            peer_socket.settimeout(10)
            request = peer_socket.recv(1024).decode().strip()
            self.log.append_log(f"Received request '{convert_to_request_name(request)}' from {address}")
            if request == SERVER_PING:
                self.handle_server_ping_response(peer_socket)
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

    def send_message(self, recipient_username: str, message_content: str, message_type: str = 'text', file_name: str = None, file_size: int = None) -> bool:
        try:
            if recipient_username not in self.peers:
                print(f"[SEND] Unknown recipient: {recipient_username}")
                return False

            recipient_address = self.peers[recipient_username]
            self.log.append_log(f"Creating message for {recipient_username} of type {message_type}")

            try:
                message = create_onion_message(
                    message_content,
                    self.username,
                    recipient_username,
                    message_type,
                    file_name,
                    file_size
                )
                self.log.append_log(f"Created onion message with ID {message.message_id}")
            except Exception as e:
                raise MessageError(f"Failed to create message: {str(e)}")

            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(10)
                    s.connect((recipient_address[0], int(recipient_address[1])))
                    s.send(CLIENT_PEER_MESSAGE.encode())
                    response = s.recv(1024).decode().strip()
                    if response != SERVER_OK:
                        raise MessageError(f"Server rejected connection: {response}")

                    # Send encrypted message with length prefix
                    try:
                        encrypted_message = create_onion_message_encrypted(message, recipient_address[2])
                        self.log.append_log(f"Created encrypted message of length {len(encrypted_message)}")
                    except Exception as e:
                        raise MessageError(f"Failed to encrypt message: {str(e)}")

                    try:
                        s.send(len(encrypted_message).to_bytes(4, byteorder='big'))  # Send length first
                        response = s.recv(1024).decode().strip()
                        if response != SERVER_OK:
                            raise MessageError(f"Server rejected message length: {response}")
                        s.send(encrypted_message)  # Send actual data
                        self.log.append_log(f"Sent encrypted message to {recipient_username}")
                    except Exception as e:
                        raise MessageError(f"Failed to send encrypted message: {str(e)}")
                    
                    # Wait for and parse acknowledgment
                    try:
                        length_bytes = s.recv(4)
                        if not length_bytes:
                            raise MessageError("Empty acknowledgment length received")
                        ack_length = int.from_bytes(length_bytes, byteorder='big')
                        s.send(SERVER_OK.encode())  # Acknowledge length receipt
                        
                        ack_json = s.recv(ack_length).decode()
                        if not ack_json:
                            raise MessageError("Empty acknowledgment received")
                        ack = json.loads(ack_json)
                        s.send(SERVER_OK.encode())  # Send final confirmation
                        self.log.append_log(f"Received acknowledgment for message {message.message_id}")
                    except json.JSONDecodeError as e:
                        raise MessageError(f"Invalid acknowledgment format: {ack_json}")
                    except Exception as e:
                        raise MessageError(f"Failed to receive acknowledgment: {str(e)}")

                    if ack.get('type') == 'ack' and ack.get('message_id') == message.message_id:
                        try:
                            local_message = LocalMessage(
                                message_id=0,
                                recipient_username=recipient_username,
                                message_type=get_message_database_type(message_type),
                                is_income=False,
                                message=message_content.encode() if isinstance(message_content, str) else message_content,
                                timestamp=Timestamp.get_now(),
                                is_read=True,
                                file_name=file_name,
                                file_size=file_size
                            )
                            self.database.store_message(local_message, self.aes_key, self.log)
                            self.log.append_log(f"Stored sent message in database")
                            return True
                        except Exception as e:
                            raise MessageError(f"Failed to store sent message: {str(e)}")
                    
                    raise MessageError(f"Invalid acknowledgment - Type: {ack.get('type')}, Expected ID: {message.message_id}, Got ID: {ack.get('message_id')}")
            except MessageError:
                raise
            except Exception as e:
                raise MessageError(f"Connection error: {str(e)}")
        except Exception as e:
            print(f"[SEND] Error sending to {recipient_username}: {str(e)}")
            self.log.append_log(f"Error sending to {recipient_username}: {str(e)}")
            return False

    def update_peer(self, username: str, ip: str, port: int, public_key: str):
        self.peers[username] = (ip, str(port), public_key)
        self.log.append_log(f"Updated peer information for {username}: {ip}:{port}")

    def remove_peer(self, username: str):
        if username in self.peers:
            del self.peers[username]
            self.log.append_log(f"Removed peer: {username}")

    def stop(self):
        self.is_running = False
        self.listener_socket.close()
        self.log.append_log("P2P Connection stopped")