import socket
import threading
import json
import time
from typing import Dict, Optional, Callable
from message import OnionMessage, create_onion_message, process_onion_message, receive_final_message
from message import MessageError, create_message_ack
from log import Log
from statics import *

class PeerConnection:
    def __init__(self, username: str, private_key: str, log: Log, receiver_socket: socket.socket):
        self.username = username
        self.private_key = private_key
        self.log = log
        self.peers: Dict[str, tuple] = {}  # username -> (ip, port)
        self.message_handlers: Dict[str, Callable] = {}
        self.is_running = True
        
        # Create listening socket
        self.listener_socket = receiver_socket
        self.ip, self.port = self.listener_socket.getsockname()
        
        # Start listening thread
        self.listener_socket.listen(10)
        self.listen_thread = threading.Thread(target=self._listen_for_connections)
        self.listen_thread.daemon = True
        self.listen_thread.start()
        
        self.log.append_log(f"P2P Connection initialized for {username} on {self.ip}:{self.port}")

    def register_message_handler(self, message_type: str, handler: Callable):
        """Register a handler for a specific message type"""
        self.message_handlers[message_type] = handler

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

    def _handle_peer_connection(self, peer_socket: socket.socket, address: tuple):
        """Handle incoming peer connection"""
        try:
            request  = peer_socket.recv(1024).decode()
            if request == SERVER_PING:
                self.log.append_log(f"answered to server ping")
                peer_socket.send(CLIENT_IS_ONLINE.encode())
            elif request == CLIENT_PEER_MESSAGE:
                # Receive the encrypted message
                peer_socket.send(BUFFER.encode())
                message_data = peer_socket.recv(4096)
                if not message_data:
                    return

                # Process the message
                try:
                    message_dict = receive_final_message(message_data, self.private_key)

                    # Send acknowledgment
                    ack = create_message_ack(message_dict['message_id'], message_dict['sender_id'])
                    peer_socket.send(json.dumps(ack).encode())

                    # Handle different message types
                    message_type = message_dict.get('type', 'text')
                    if message_type in self.message_handlers:
                        self.message_handlers[message_type](message_dict)
                    else:
                        self.log.append_log(f"Received unknown message type: {message_type}")

                except MessageError as e:
                    self.log.append_log(f"Error processing message: {str(e)}")

        except Exception as e:
            self.log.append_log(f"Error handling peer connection: {str(e)}")
        finally:
            peer_socket.close()

    def send_message(self, recipient_username: str, message_content: str, message_type: str = 'text') -> bool:
        """Send a message to a peer"""
        if recipient_username not in self.peers:
            self.log.append_log(f"Unknown recipient: {recipient_username}")
            return False

        try:
            # Create the message
            message = OnionMessage(
                content=message_content,
                sender_id=self.username,
                recipient_id=recipient_username
            )
            message.add_layer(self.peers[recipient_username][0], self.peers[recipient_username][1])
            
            # Create encrypted message
            encrypted_message = create_onion_message(message, self.private_key)
            
            # Send the message
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(self.peers[recipient_username])
                s.send(CLIENT_PEER_MESSAGE.encode())
                s.recv(1024) # client OK
                s.send(encrypted_message)
                
                # Wait for acknowledgment
                try:
                    ack_data = s.recv(1024).decode()
                    ack = json.loads(ack_data)
                    if ack.get('type') == 'ack' and ack.get('message_id') == message.message_id:
                        self.log.append_log(f"Message {message.message_id} acknowledged by {recipient_username}")
                        return True
                    return False
                except Exception as e:
                    self.log.append_log(f"Failed to receive acknowledgment: {str(e)}")
                    return False

        except Exception as e:
            print("exception: ", e)
            self.log.append_log(f"Error sending message to {recipient_username}: {str(e)}")
            return False

    def update_peer(self, username: str, ip: str, port: int):
        """Update or add a peer's connection information"""
        self.peers[username] = (ip, port)
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