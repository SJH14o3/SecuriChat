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
        self.peers: Dict[str, tuple] = {}  # username -> (ip, port, public_key)
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
            peer_socket.settimeout(10)  # 10 second timeout
            
            # Step 1: Get initial request
            try:
                request = peer_socket.recv(1024).decode().strip()
                print(f"[RECEIVE] Got initial request: '{request}'")
            except Exception as e:
                print(f"[RECEIVE] Error receiving initial request: {str(e)}")
                return
            
            if request == SERVER_PING:
                try:
                    self.log.append_log(f"answered to server ping")
                    peer_socket.sendall(CLIENT_IS_ONLINE.encode())
                    print(f"[RECEIVE] Sent CLIENT_IS_ONLINE: '{CLIENT_IS_ONLINE}'")
                except Exception as e:
                    print(f"[RECEIVE] Error sending ping response: {str(e)}")
                return
                
            if request != CLIENT_PEER_MESSAGE:  # Use CLIENT_PEER_MESSAGE instead of "900"
                print(f"[RECEIVE] Unknown request type: '{request}'")
                return
                
            print("[RECEIVE] Handling peer message...")
            
            # Step 2: Send ready signal
            try:
                ready_msg = BUFFER  # Use BUFFER instead of "READY_FOR_MESSAGE"
                peer_socket.sendall(ready_msg.encode())
                print(f"[RECEIVE] Sent ready signal: '{ready_msg}'")
            except Exception as e:
                print(f"[RECEIVE] Failed to send ready signal: {str(e)}")
                return
            
            # Step 3: Receive message
            try:
                message_data = b""
                while True:
                    try:
                        chunk = peer_socket.recv(8192)
                        if not chunk:
                            print("[RECEIVE] Connection closed while receiving message")
                            return
                        message_data += chunk
                        if b"END_OF_MESSAGE" in message_data:
                            message_data = message_data[:message_data.index(b"END_OF_MESSAGE")]
                            break
                    except socket.timeout:
                        print("[RECEIVE] Timeout while receiving message")
                        return
                
                if not message_data:
                    print("[RECEIVE] No message data received")
                    return
                
                print(f"[RECEIVE] Got message data of length: {len(message_data)}")
            except Exception as e:
                print(f"[RECEIVE] Error receiving message data: {str(e)}")
                return
            
            # Step 4: Process message and send acknowledgment
            try:
                # Process the message
                message_dict = receive_final_message(message_data, self.private_key)
                print(f"[RECEIVE] Processed message from: {message_dict.get('sender_id')}")
                
                # Send ready for ack signal
                try:
                    ready_ack = "READY_FOR_ACK"
                    peer_socket.sendall(ready_ack.encode())
                    print(f"[RECEIVE] Sent ready for ack signal: '{ready_ack}'")
                except Exception as e:
                    print(f"[RECEIVE] Failed to send ready for ack: {str(e)}")
                    return
                
                # Send acknowledgment
                try:
                    ack = create_message_ack(message_dict['message_id'], message_dict['sender_id'])
                    ack_json = json.dumps(ack)
                    ack_msg = ack_json + "END_OF_ACK"
                    peer_socket.sendall(ack_msg.encode())
                    print(f"[RECEIVE] Sent acknowledgment: '{ack_json}'")
                except Exception as e:
                    print(f"[RECEIVE] Failed to send acknowledgment: {str(e)}")
                    return
                
                # Handle message type
                try:
                    message_type = message_dict.get('type', 'text')
                    if message_type in self.message_handlers:
                        self.message_handlers[message_type](message_dict)
                    else:
                        self.log.append_log(f"Received unknown message type: {message_type}")
                except Exception as e:
                    print(f"[RECEIVE] Error handling message type: {str(e)}")
                    
            except Exception as e:
                print(f"[RECEIVE] Error processing message: {str(e)}")
                self.log.append_log(f"Error processing message: {str(e)}")
                
        except Exception as e:
            print(f"[RECEIVE] Error in connection handler: {str(e)}")
            self.log.append_log(f"Error handling peer connection: {str(e)}")
        finally:
            try:
                peer_socket.close()
                print("[RECEIVE] Connection closed")
            except:
                pass

    def send_message(self, recipient_username: str, message_content: str, message_type: str = 'text') -> bool:
        """Send a message to a peer"""
        if recipient_username not in self.peers:
            self.log.append_log(f"Unknown recipient: {recipient_username}")
            print("[SEND] Recipient username not in peers")
            return False

        try:
            # Create message object
            try:
                message = OnionMessage(
                    content=message_content,
                    sender_id=self.username,
                    recipient_id=recipient_username
                )
                print("[SEND] Created message object")
            except Exception as e:
                print(f"[SEND] Failed to create message: {str(e)}")
                return False

            # Get recipient info
            try:
                recipient_ip, recipient_port, recipient_public_key = self.peers[recipient_username]
                print(f"[SEND] Got recipient info - IP: {recipient_ip}, Port: {recipient_port}")
            except Exception as e:
                print(f"[SEND] Failed to get recipient info: {str(e)}")
                return False

            # Add encryption layer
            try:
                message.add_layer(
                    node_public_key=recipient_public_key,
                    next_address=(recipient_ip, str(recipient_port))
                )
                print("[SEND] Added encryption layer")
            except Exception as e:
                print(f"[SEND] Failed to add encryption: {str(e)}")
                return False

            # Create encrypted message
            try:
                encrypted_message = create_onion_message(message, self.private_key)
                print("[SEND] Created encrypted message")
            except Exception as e:
                print(f"[SEND] Failed to create encrypted message: {str(e)}")
                return False

            # Send message
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(15)  # 15 second timeout
                
                with s:
                    # Connect
                    s.connect((recipient_ip, int(recipient_port)))
                    print(f"[SEND] Connected to {recipient_ip}:{recipient_port}")
                    
                    # Send initial request
                    s.sendall(CLIENT_PEER_MESSAGE.encode())
                    print(f"[SEND] Sent initial request: '{CLIENT_PEER_MESSAGE}'")
                    
                    # Wait for ready signal
                    ready_signal = s.recv(1024).decode().strip()
                    if ready_signal != BUFFER:
                        raise Exception(f"Expected {BUFFER}, got: '{ready_signal}'")
                    print(f"[SEND] Got ready signal: '{ready_signal}'")
                    
                    # Send encrypted message
                    msg_with_end = encrypted_message + b"END_OF_MESSAGE"
                    s.sendall(msg_with_end)
                    print("[SEND] Sent encrypted message")
                    
                    # Wait for ready for ack signal
                    ack_ready = s.recv(1024).decode().strip()
                    if ack_ready != "READY_FOR_ACK":
                        raise Exception(f"Expected READY_FOR_ACK, got: '{ack_ready}'")
                    print(f"[SEND] Got ready for ack signal: '{ack_ready}'")
                    
                    # Receive acknowledgment
                    print("[SEND] Waiting for acknowledgment...")
                    ack_data = b""
                    while True:
                        try:
                            chunk = s.recv(1024)
                            if not chunk:
                                print("[SEND] Connection closed while receiving ack")
                                return False
                            ack_data += chunk
                            if b"END_OF_ACK" in ack_data:
                                ack_data = ack_data[:ack_data.index(b"END_OF_ACK")]
                                break
                        except socket.timeout:
                            print("[SEND] Timeout while receiving acknowledgment")
                            return False
                    
                    if not ack_data:
                        print("[SEND] Received empty acknowledgment")
                        return False
                    
                    # Process acknowledgment
                    try:
                        ack_json = ack_data.decode()
                        print(f"[SEND] Received ack data: '{ack_json}'")
                        
                        ack = json.loads(ack_json)
                        if ack.get('type') == 'ack' and ack.get('message_id') == message.message_id:
                            print("[SEND] Valid acknowledgment received")
                            return True
                        
                        print(f"[SEND] Invalid ack - Type: {ack.get('type')}, Expected ID: {message.message_id}, Got ID: {ack.get('message_id')}")
                        return False
                        
                    except json.JSONDecodeError as e:
                        print(f"[SEND] Failed to parse ack JSON: {str(e)}")
                        return False
                    except Exception as e:
                        print(f"[SEND] Error processing ack: {str(e)}")
                        return False
                    
            except Exception as e:
                print(f"[SEND] Error in message sending: {str(e)}")
                return False

        except Exception as e:
            print(f"[SEND] Unexpected error: {str(e)}")
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