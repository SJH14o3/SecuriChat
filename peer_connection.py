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
                print(f"[RECEIVE] Got initial request: '{request}' from {address}")
                self.log.append_log(f"Received request '{request}' from {address}")
            except Exception as e:
                print(f"[RECEIVE] Error receiving initial request from {address}: {str(e)}")
                self.log.append_log(f"Error receiving request from {address}: {str(e)}")
                return

            # Handle server ping
            if request == SERVER_PING:
                try:
                    self.log.append_log(f"Answered to server ping from {address}")
                    peer_socket.sendall(CLIENT_IS_ONLINE.encode())
                    time.sleep(0.2)  # Wait for ping response to be sent
                    print(f"[RECEIVE] Sent CLIENT_IS_ONLINE to {address}")
                    return
                except Exception as e:
                    print(f"[RECEIVE] Error sending ping response to {address}: {str(e)}")
                    self.log.append_log(f"Error sending ping response to {address}: {str(e)}")
                    return
            
            # Handle peer message
            if request == CLIENT_PEER_MESSAGE:
                print(f"[RECEIVE] Handling peer message from {address}...")
                self.log.append_log(f"Handling peer message from {address}")
                
                # Step 2: Send ready signal
                try:
                    ready_msg = BUFFER
                    peer_socket.sendall(ready_msg.encode())
                    time.sleep(0.2)  # Wait for ready signal to be sent
                    print(f"[RECEIVE] Sent ready signal '{ready_msg}' to {address}")
                    self.log.append_log(f"Sent ready signal to {address}")
                except Exception as e:
                    print(f"[RECEIVE] Failed to send ready signal to {address}: {str(e)}")
                    self.log.append_log(f"Failed to send ready signal to {address}: {str(e)}")
                    return
                
                # Step 3: Receive message with improved chunking
                try:
                    message_data = b""
                    start_time = time.time()
                    while True:
                        if time.time() - start_time > 30:  # 30 second total timeout
                            print(f"[RECEIVE] Total receive timeout from {address}")
                            self.log.append_log(f"Timeout receiving message from {address}")
                            return
                            
                        try:
                            chunk = peer_socket.recv(8192)
                            if not chunk:
                                if message_data:  # If we have some data, wait a bit more
                                    time.sleep(0.5)
                                    continue
                                print(f"[RECEIVE] Connection closed by {address} while receiving message")
                                self.log.append_log(f"Connection closed by {address} during message receive")
                                return
                            
                            message_data += chunk
                            print(f"[RECEIVE] Got chunk of size {len(chunk)} from {address}")
                            
                            if b"END_OF_MESSAGE" in message_data:
                                message_data = message_data[:message_data.index(b"END_OF_MESSAGE")]
                                time.sleep(0.2)  # Wait a bit after receiving complete message
                                break
                        except socket.timeout:
                            if message_data:  # If we have some data, wait a bit more
                                time.sleep(0.5)
                            continue  # Keep trying until total timeout
                    
                    if not message_data:
                        print(f"[RECEIVE] No message data received from {address}")
                        self.log.append_log(f"No message data received from {address}")
                        return
                    
                    print(f"[RECEIVE] Got complete message data of length: {len(message_data)} from {address}")
                    self.log.append_log(f"Received complete message ({len(message_data)} bytes) from {address}")
                except Exception as e:
                    print(f"[RECEIVE] Error receiving message data from {address}: {str(e)}")
                    self.log.append_log(f"Error receiving message data from {address}: {str(e)}")
                    return
                
                # Step 4: Process message and send acknowledgment
                try:
                    # Process the message
                    print(f"[RECEIVE] Attempting to process message from {address}")
                    self.log.append_log(f"Processing message from {address}")
                    
                    message_dict = receive_final_message(message_data, self.private_key)
                    print(f"[RECEIVE] Successfully processed message from: {message_dict.get('sender_id')}")
                    self.log.append_log(f"Successfully processed message from {message_dict.get('sender_id')}")
                    time.sleep(0.2)  # Wait after processing
                    
                    # Send ready for ack signal
                    ready_ack = "READY_FOR_ACK"
                    peer_socket.sendall(ready_ack.encode())
                    time.sleep(0.2)  # Wait for ready for ack to be sent
                    print(f"[RECEIVE] Sent ready for ack signal to {address}")
                    self.log.append_log(f"Sent ready for ack signal to {address}")
                    
                    # Send acknowledgment
                    ack = create_message_ack(message_dict['message_id'], message_dict['sender_id'])
                    ack_json = json.dumps(ack)
                    ack_msg = ack_json + "END_OF_ACK"
                    peer_socket.sendall(ack_msg.encode())
                    time.sleep(0.5)  # Longer wait after sending ack
                    print(f"[RECEIVE] Sent acknowledgment to {address}: {ack_json}")
                    self.log.append_log(f"Sent acknowledgment to {address}")
                    
                    # Handle message type
                    message_type = message_dict.get('message_type', 'text')
                    if message_type in self.message_handlers:
                        self.message_handlers[message_type](message_dict)
                        print(f"[RECEIVE] Successfully handled message of type {message_type} from {address}")
                        self.log.append_log(f"Handled message of type {message_type} from {address}")
                    else:
                        print(f"[RECEIVE] No handler for message type {message_type} from {address}")
                        self.log.append_log(f"No handler for message type {message_type} from {address}")
                except Exception as e:
                    print(f"[RECEIVE] Error processing message from {address}: {str(e)}")
                    self.log.append_log(f"Error processing message from {address}: {str(e)}")
                    return
            else:
                print(f"[RECEIVE] Unknown request type from {address}: '{request}'")
                self.log.append_log(f"Unknown request type from {address}: '{request}'")

        except Exception as e:
            print(f"[RECEIVE] Error in connection handler for {address}: {str(e)}")
            self.log.append_log(f"Error in connection handler for {address}: {str(e)}")
        finally:
            try:
                time.sleep(1.0)  # Longer delay before closing to ensure all data is sent
                peer_socket.close()
                print(f"[RECEIVE] Connection closed with {address}")
                self.log.append_log(f"Connection closed with {address}")
            except:
                pass

    def send_message(self, recipient_username: str, message_content: str, message_type: str = 'text') -> bool:
        """Send a message to a peer"""
        if recipient_username not in self.peers:
            self.log.append_log(f"Unknown recipient: {recipient_username}")
            print(f"[SEND] Recipient username '{recipient_username}' not in peers")
            return False

        try:
            # Get recipient info first
            recipient_ip, recipient_port, recipient_public_key = self.peers[recipient_username]
            print(f"[SEND] Got recipient info for {recipient_username} - IP: {recipient_ip}, Port: {recipient_port}")

            # Create message object
            message = OnionMessage(
                content=message_content,
                sender_id=self.username,
                recipient_id=recipient_username,
                message_type=message_type
            )
            print(f"[SEND] Created message object for {recipient_username}")

            # Add encryption layer
            try:
                print(f"[SEND] Adding encryption layer for {recipient_username} using their public key")
                message.add_layer(
                    node_public_key=recipient_public_key,
                    next_address=(recipient_ip, str(recipient_port))
                )
                print(f"[SEND] Successfully added encryption layer for {recipient_username}")
            except Exception as e:
                print(f"[SEND] Failed to add encryption for {recipient_username}: {str(e)}")
                return False
            
            # Create encrypted message
            try:
                print(f"[SEND] Creating final encrypted message for {recipient_username}")
                encrypted_message = create_onion_message(message, self.private_key)
                print(f"[SEND] Successfully created encrypted message of length {len(encrypted_message)}")
            except Exception as e:
                print(f"[SEND] Failed to create encrypted message for {recipient_username}: {str(e)}")
                return False

            # Send message
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(15)  # 15 second timeout
                
                with s:
                    # Connect
                    print(f"[SEND] Attempting to connect to {recipient_username} at {recipient_ip}:{recipient_port}")
                    s.connect((recipient_ip, int(recipient_port)))
                    time.sleep(0.2)  # Wait after connection
                    print(f"[SEND] Successfully connected to {recipient_username}")
                    
                    # Send initial request
                    print(f"[SEND] Sending initial request to {recipient_username}")
                    s.sendall(CLIENT_PEER_MESSAGE.encode())
                    time.sleep(0.2)  # Wait after sending request
                    print(f"[SEND] Sent initial request '{CLIENT_PEER_MESSAGE}' to {recipient_username}")
                    
                    # Wait for ready signal with timeout
                    try:
                        ready_signal = s.recv(1024).decode().strip()
                        if ready_signal != BUFFER:
                            raise Exception(f"Expected {BUFFER}, got: '{ready_signal}'")
                        time.sleep(0.2)  # Wait after receiving ready signal
                        print(f"[SEND] Got correct ready signal from {recipient_username}: '{ready_signal}'")
                    except Exception as e:
                        print(f"[SEND] Failed to get valid ready signal from {recipient_username}: {str(e)}")
                        return False
                    
                    # Send encrypted message in chunks
                    try:
                        msg_with_end = encrypted_message + b"END_OF_MESSAGE"
                        chunk_size = 8192
                        for i in range(0, len(msg_with_end), chunk_size):
                            chunk = msg_with_end[i:i + chunk_size]
                            s.sendall(chunk)
                            time.sleep(0.2)  # Wait between chunks
                            print(f"[SEND] Sent chunk {i//chunk_size + 1} of size {len(chunk)} to {recipient_username}")
                        time.sleep(0.5)  # Longer wait after sending all chunks
                        print(f"[SEND] Completed sending message to {recipient_username}")
                    except Exception as e:
                        print(f"[SEND] Failed to send message chunks to {recipient_username}: {str(e)}")
                        return False
                    
                    # Wait for ready for ack signal
                    try:
                        ack_ready = s.recv(1024).decode().strip()
                        if ack_ready != "READY_FOR_ACK":
                            raise Exception(f"Expected READY_FOR_ACK, got: '{ack_ready}'")
                        time.sleep(0.2)  # Wait after receiving ready for ack
                        print(f"[SEND] Got ready for ack signal from {recipient_username}")
                    except Exception as e:
                        print(f"[SEND] Failed to get ready for ack from {recipient_username}: {str(e)}")
                        return False
                    
                    # Receive acknowledgment with timeout
                    print(f"[SEND] Waiting for acknowledgment from {recipient_username}...")
                    try:
                        ack_data = b""
                        start_time = time.time()
                        while True:
                            if time.time() - start_time > 30:  # 30 second total timeout
                                print(f"[SEND] Total timeout waiting for ack from {recipient_username}")
                                return False
                                
                            try:
                                chunk = s.recv(1024)
                                if not chunk:
                                    if ack_data:  # If we have some data, wait a bit more
                                        time.sleep(0.5)
                                        continue
                                    print(f"[SEND] Connection closed by {recipient_username} while receiving ack")
                                    return False
                                ack_data += chunk
                                if b"END_OF_ACK" in ack_data:
                                    ack_data = ack_data[:ack_data.index(b"END_OF_ACK")]
                                    time.sleep(0.2)  # Wait after receiving complete ack
                                    break
                            except socket.timeout:
                                if ack_data:  # If we have some data, wait a bit more
                                    time.sleep(0.5)
                                continue  # Keep trying until total timeout
                        
                        if not ack_data:
                            print(f"[SEND] Received empty acknowledgment from {recipient_username}")
                            return False
                        
                        # Process acknowledgment
                        try:
                            ack_json = ack_data.decode()
                            print(f"[SEND] Received ack data from {recipient_username}: '{ack_json}'")
                            
                            ack = json.loads(ack_json)
                            if ack.get('type') == 'ack' and ack.get('message_id') == message.message_id:
                                print(f"[SEND] Valid acknowledgment received from {recipient_username}")
                                time.sleep(0.5)  # Wait after successful ack
                                return True
                            
                            print(f"[SEND] Invalid ack from {recipient_username} - Type: {ack.get('type')}, Expected ID: {message.message_id}, Got ID: {ack.get('message_id')}")
                            return False
                        except json.JSONDecodeError as e:
                            print(f"[SEND] Failed to parse ack JSON from {recipient_username}: {str(e)}")
                            return False
                    except Exception as e:
                        print(f"[SEND] Error receiving ack from {recipient_username}: {str(e)}")
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