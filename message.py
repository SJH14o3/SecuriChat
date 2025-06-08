import json
import random
import time
import uuid
from typing import List, Dict, Tuple, Optional
from cryptography.hazmat.primitives import hashes, padding, serialization, hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asymmetric_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
from timestamp import Timestamp

# Constants
MAX_MESSAGE_AGE = 300  # 5 minutes in seconds
MAX_RETRIES = 3
CHUNK_SIZE = 1024 * 64  # 64KB chunks for large messages

class MessageError(Exception):
    pass

class MessageValidationError(MessageError):
    pass

class MessageCorruptionError(MessageError):
    pass

class OnionLayer:
    def __init__(self, node_public_key: str, next_address: Tuple[str, str]):
        self.node_public_key = node_public_key
        self.next_address = next_address
        self.layer_id = str(uuid.uuid4())

class OnionMessage:
    def __init__(self, content: str, sender_id: str, recipient_id: str, message_type: str = 'text'):
        self.content = content
        self.sender_id = sender_id
        self.recipient_id = recipient_id
        self.message_type = message_type
        self.layers: List[OnionLayer] = []
        self.message_id = str(uuid.uuid4())
        self.sequence_number = 0  # Will be set during message creation
        self.timestamp = time.time()
        self.chunks: List[str] = []  # For large messages
        self.total_chunks = 0
        
    def add_layer(self, node_public_key: str, next_address: Tuple[str, str]):
        """Add a new layer to the onion routing path"""
        self.layers.append(OnionLayer(node_public_key, next_address))

def add_checksum(message_data: bytes) -> bytes:
    """Add SHA-256 checksum to message data"""
    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(message_data)
    checksum = hasher.finalize()
    # Format: [checksum(32 bytes)][message_data]
    return checksum + message_data

def verify_checksum(message_with_checksum: bytes) -> Tuple[bool, bytes]:
    """Verify message integrity using checksum"""
    if len(message_with_checksum) < 32:
        return False, b""
        
    checksum = message_with_checksum[:32]  # SHA-256 is 32 bytes
    message = message_with_checksum[32:]
    
    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(message)
    calculated_checksum = hasher.finalize()
    
    return checksum == calculated_checksum, message

def validate_message(message_dict: Dict) -> bool:
    required_fields = ['content', 'sender_id', 'recipient_id',
                      'sequence_number', 'timestamp', 'message_id',
                      'message_type']
    
    # Check all required fields exist
    if not all(field in message_dict for field in required_fields):
        return False
        
    # Check timestamp is not too old
    if time.time() - message_dict['timestamp'] > MAX_MESSAGE_AGE:
        return False
        
    # Check message format
    if not isinstance(message_dict['content'], str):
        return False
        
    return True

def create_onion_route(online_users: List[Dict], recipient_address: Tuple[str, str], 
                      num_hops: int = 3) -> List[OnionLayer]:
    available_nodes = [user for user in online_users
                      if (user['ip_address'], str(user['port'])) != recipient_address]
    
    if len(available_nodes) < num_hops - 1:
        num_hops = len(available_nodes) + 1
    
    route_nodes = random.sample(available_nodes, num_hops - 1)
    route = []
    
    # Build the route from exit node back to entry node
    next_address = recipient_address
    for node in reversed(route_nodes):
        route.append(OnionLayer(
            node_public_key=node['public_key'],
            next_address=next_address
        ))
        next_address = (node['ip_address'], str(node['port']))
    
    return route

def encrypt_layer(data: bytes, public_key_pem: str) -> bytes:
    try:
        # Step 1: Load the public key
        try:
            print(f"Loading public key...")
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode(),
                backend=default_backend()
            )
            print(f"Successfully loaded public key")
        except Exception as e:
            raise MessageError(f"Failed to load public key: {str(e)}")

        # Step 2: Generate AES key and IV
        try:
            aes_key = os.urandom(32)
            iv = os.urandom(16)
            print(f"Generated AES key and IV")
        except Exception as e:
            raise MessageError(f"Failed to generate AES key or IV: {str(e)}")

        # Step 3: Encrypt AES key with RSA
        try:
            encrypted_key = public_key.encrypt(
                aes_key,
                asymmetric_padding.OAEP(
                    mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print(f"Successfully encrypted AES key with RSA")
        except Exception as e:
            raise MessageError(f"Failed to encrypt AES key with RSA: {str(e)}")

        # Step 4: Create AES cipher
        try:
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            print(f"Created AES cipher")
        except Exception as e:
            raise MessageError(f"Failed to create AES cipher: {str(e)}")

        # Step 5: Add padding
        try:
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(data) + padder.finalize()
            print(f"Successfully added padding")
        except Exception as e:
            raise MessageError(f"Failed to add padding: {str(e)}")

        # Step 6: Encrypt data with AES
        try:
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            print(f"Successfully encrypted data with AES")
        except Exception as e:
            raise MessageError(f"Failed to encrypt data with AES: {str(e)}")

        # Step 7: Generate HMAC
        try:
            h = hmac.HMAC(aes_key, hashes.SHA256())
            h.update(encrypted_data)
            mac = h.finalize()
            print(f"Successfully generated HMAC")
        except Exception as e:
            raise MessageError(f"Failed to generate HMAC: {str(e)}")

        # Step 8: Format final output with clear separation between metadata and encrypted data
        try:
            metadata = {
                'encrypted_key': encrypted_key.hex(),
                'iv': iv.hex(),
                'mac': mac.hex(),
                'data_length': len(encrypted_data)
            }
            metadata_json = json.dumps(metadata).encode('utf-8')
            metadata_length = len(metadata_json).to_bytes(4, byteorder='big')
            
            # Format: [metadata_length(4 bytes)][metadata_json][encrypted_data]
            payload = metadata_length + metadata_json + encrypted_data
            
            # Add checksum for the entire payload
            hasher = hashes.Hash(hashes.SHA256())
            hasher.update(payload)
            checksum = hasher.finalize()
            
            # Final format: [checksum(32 bytes)][metadata_length(4 bytes)][metadata_json][encrypted_data]
            result = checksum + payload
            print(f"Successfully formatted encrypted data")
            return result
        except Exception as e:
            raise MessageError(f"Failed to format encrypted data: {str(e)}")

    except MessageError as e:
        # Re-raise MessageError with original message
        raise
    except Exception as e:
        # Catch any other unexpected errors
        raise MessageError(f"Unexpected encryption error: {str(e)}")

def decrypt_layer(encrypted_data: bytes, private_key_pem: str) -> Tuple[bytes, Tuple[str, str]]:
    """Decrypt a layer using the node's private key"""
    try:
        # Load private key
        try:
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode(),
                password=None,
                backend=default_backend()
            )
            print(f"Successfully loaded private key")
        except Exception as e:
            raise MessageError(f"Failed to load private key: {str(e)}")
        
        # Parse the encrypted data format: [metadata_length(4 bytes)][metadata_json][encrypted_data]
        try:
            # First 32 bytes are checksum for the entire payload
            checksum = encrypted_data[:32]
            payload = encrypted_data[32:]
            
            # Verify checksum
            hasher = hashes.Hash(hashes.SHA256())
            hasher.update(payload)
            calculated_checksum = hasher.finalize()
            if checksum != calculated_checksum:
                raise MessageCorruptionError("Checksum verification failed")
            
            # Get metadata length and JSON
            metadata_length = int.from_bytes(payload[:4], byteorder='big')
            metadata_json = payload[4:4+metadata_length]
            data_dict = json.loads(metadata_json.decode('utf-8'))
            encrypted_data_bytes = payload[4+metadata_length:]
            print(f"Successfully parsed encrypted data format")
        except MessageCorruptionError as e:
            raise
        except Exception as e:
            print(f"Raw encrypted data (first 50 bytes): {encrypted_data[:50]}")
            raise MessageError(f"Failed to parse encrypted data format: {str(e)}")
        
        try:
            encrypted_key = bytes.fromhex(data_dict['encrypted_key'])
            iv = bytes.fromhex(data_dict['iv'])
            mac = bytes.fromhex(data_dict['mac'])
            ciphertext = encrypted_data_bytes[:data_dict['data_length']]
            print(f"Successfully extracted encryption components")
        except Exception as e:
            raise MessageError(f"Failed to extract encryption components: {str(e)}")
        
        # Decrypt the AES key
        try:
            aes_key = private_key.decrypt(
                encrypted_key,
                asymmetric_padding.OAEP(
                    mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print(f"Successfully decrypted AES key")
        except Exception as e:
            raise MessageError(f"Failed to decrypt AES key: {str(e)}")
        
        # Verify HMAC
        try:
            h = hmac.HMAC(aes_key, hashes.SHA256())
            h.update(ciphertext)
            h.verify(mac)
            print(f"Successfully verified HMAC")
        except Exception as e:
            raise MessageCorruptionError(f"Message integrity check failed: {str(e)}")
        
        # Decrypt the data with AES
        try:
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(ciphertext) + decryptor.finalize()
            print(f"Successfully decrypted data with AES")
        except Exception as e:
            raise MessageError(f"Failed to decrypt data with AES: {str(e)}")
        
        # Remove padding
        try:
            unpadder = padding.PKCS7(128).unpadder()
            data = unpadder.update(padded_data) + unpadder.finalize()
            print(f"Successfully removed padding")
        except Exception as e:
            raise MessageError(f"Failed to remove padding: {str(e)}")
        
        # Parse the decrypted data
        try:
            decrypted_dict = json.loads(data.decode('utf-8'))
            print(f"Successfully parsed decrypted data JSON")
        except Exception as e:
            print(f"Raw decrypted data (first 50 bytes): {data[:50]}")
            raise MessageError(f"Failed to parse decrypted data JSON: {str(e)}")
        
        try:
            next_address = (str(decrypted_dict['next_ip']), str(decrypted_dict['next_port']))
            payload = bytes.fromhex(decrypted_dict['payload'])
            print(f"Successfully extracted next hop information")
        except Exception as e:
            raise MessageError(f"Failed to extract next hop information: {str(e)}")
        
        # Verify checksum if present
        if 'checksum' in decrypted_dict:
            try:
                is_valid, payload = verify_checksum(payload)
                if not is_valid:
                    raise MessageCorruptionError("Checksum verification failed")
                print(f"Successfully verified checksum")
            except Exception as e:
                raise MessageCorruptionError(f"Checksum verification failed: {str(e)}")
        
        return payload, next_address
    except MessageError:
        raise
    except Exception as e:
        raise MessageError(f"Decryption failed: {str(e)}")

def create_onion_message(message: OnionMessage, sender_private_key: str) -> bytes:
    """Create an onion-encrypted message with integrity checks"""
    try:
        print("[ONION] Creating onion message...")
        
        # Split large messages into chunks
        if len(message.content.encode()) > CHUNK_SIZE:
            chunks = [message.content[i:i+CHUNK_SIZE] for i in range(0, len(message.content), CHUNK_SIZE)]
            message.chunks = chunks
            message.total_chunks = len(chunks)
            print(f"[ONION] Split message into {len(chunks)} chunks")
            
        # Create the base message
        message_data = {
            'content': message.content if not message.chunks else message.chunks[0],
            'sender_id': message.sender_id,
            'recipient_id': message.recipient_id,
            'message_id': message.message_id,
            'sequence_number': message.sequence_number,
            'timestamp': message.timestamp,
            'total_chunks': message.total_chunks,
            'chunk_index': 0 if not message.chunks else 1,
            'message_type': message.message_type
        }
        
        print(f"[ONION] Created base message data with ID {message.message_id}")
        
        # Validate the message data
        if not validate_message(message_data):
            raise MessageValidationError("Invalid message data")
        
        print("[ONION] Message data validated successfully")
        
        # Convert to bytes and add checksum
        try:
            payload = json.dumps(message_data).encode('utf-8')
            print(f"[ONION] Converted message to bytes, length: {len(payload)}")
            
            payload_with_checksum = add_checksum(payload)
            print(f"[ONION] Added checksum, new length: {len(payload_with_checksum)}")
        except Exception as e:
            raise MessageError(f"Failed to prepare message payload: {str(e)}")
        
        # Build the onion layers
        print(f"[ONION] Building {len(message.layers)} encryption layers...")
        
        for i, layer in enumerate(reversed(message.layers), 1):
            try:
                next_ip, next_port = layer.next_address
                layer_data = json.dumps({
                    'next_ip': str(next_ip),
                    'next_port': next_port,
                    'layer_id': layer.layer_id,
                    'payload': payload_with_checksum.hex(),
                    'checksum': True
                }).encode('utf-8')
                
                print(f"[ONION] Created layer {i} data for next hop {next_ip}:{next_port}")
                
                # Don't add checksum here since encrypt_layer now handles it
                payload_with_checksum = encrypt_layer(layer_data, layer.node_public_key)
                print(f"[ONION] Encrypted layer {i}, new payload length: {len(payload_with_checksum)}")
                
            except Exception as e:
                raise MessageError(f"Failed to build layer {i}: {str(e)}")
        
        print("[ONION] Successfully created complete onion message")
        return payload_with_checksum
        
    except MessageValidationError as e:
        print(f"[ONION] Message validation failed: {str(e)}")
        raise
    except MessageError as e:
        print(f"[ONION] Failed to create onion message: {str(e)}")
        raise
    except Exception as e:
        print(f"[ONION] Unexpected error creating onion message: {str(e)}")
        raise MessageError(f"Failed to create onion message: {str(e)}")

def process_onion_message(encrypted_data: bytes, node_private_key: str) -> Optional[Tuple[bytes, Tuple[str, str]]]:
    """Process an onion-encrypted message at a relay node with error handling"""
    retries = 0
    while retries < MAX_RETRIES:
        try:
            print(f"[PROCESS] Attempt {retries + 1} to process onion message")
            
            # Validate input data
            if not encrypted_data:
                raise MessageError("Empty encrypted data received")
            print(f"[PROCESS] Received encrypted data of length: {len(encrypted_data)}")
            
            try:
                # First try to decrypt the layer
                result = decrypt_layer(encrypted_data, node_private_key)
                print("[PROCESS] Successfully decrypted layer")
                
                # Validate the decrypted result
                if not result or len(result) != 2:
                    raise MessageError("Invalid decryption result format")
                    
                payload, next_address = result
                
                # Validate payload and next_address
                if not payload:
                    raise MessageError("Empty payload after decryption")
                if not next_address or len(next_address) != 2:
                    raise MessageError(f"Invalid next_address format: {next_address}")
                    
                print(f"[PROCESS] Successfully processed message. Next hop: {next_address}")
                return payload, next_address
                
            except MessageCorruptionError as e:
                print(f"[PROCESS] Message corruption detected: {str(e)}")
                raise
            except MessageError as e:
                print(f"[PROCESS] Message processing error: {str(e)}")
                raise
            except Exception as e:
                print(f"[PROCESS] Unexpected error during processing: {str(e)}")
                raise MessageError(f"Unexpected processing error: {str(e)}")
                
        except MessageCorruptionError:
            retries += 1
            print(f"[PROCESS] Retrying after corruption (attempt {retries}/{MAX_RETRIES})")
            if retries >= MAX_RETRIES:
                raise MessageError("Maximum retries exceeded - message corrupted")
            time.sleep(1)
        except MessageError as e:
            print(f"[PROCESS] Fatal message processing error: {str(e)}")
            raise
        except Exception as e:
            print(f"[PROCESS] Unhandled error: {str(e)}")
            raise MessageError(f"Failed to process message: {str(e)}")

def receive_final_message(encrypted_data: bytes, recipient_private_key: str) -> Dict:
    """Receive and decrypt the final message at its destination with validation"""
    try:
        print("[RECEIVE] Starting to process final message")
        
        # Validate input
        if not encrypted_data:
            raise MessageError("Empty encrypted data received")
        print(f"[RECEIVE] Received encrypted data of length: {len(encrypted_data)}")
        
        try:
            # Attempt to decrypt the final layer
            payload, _ = decrypt_layer(encrypted_data, recipient_private_key)
            print("[RECEIVE] Successfully decrypted final layer")
            
            try:
                # Try to decode and parse the message
                message_dict = json.loads(payload.decode())
                print("[RECEIVE] Successfully parsed message JSON")
                
                # Detailed message validation
                if not isinstance(message_dict, dict):
                    raise MessageValidationError("Message is not a valid dictionary")
                
                required_fields = ['content', 'sender_id', 'recipient_id', 
                                 'sequence_number', 'timestamp', 'message_id']
                missing_fields = [field for field in required_fields if field not in message_dict]
                if missing_fields:
                    raise MessageValidationError(f"Missing required fields: {missing_fields}")
                
                # Validate the message
                if not validate_message(message_dict):
                    raise MessageValidationError("Message validation failed")
                
                # Check message age
                current_time = time.time()
                message_age = current_time - message_dict['timestamp']
                if message_age > MAX_MESSAGE_AGE:
                    raise MessageValidationError(f"Message too old (age: {message_age}s)")
                
                print(f"[RECEIVE] Message validation successful. ID: {message_dict.get('message_id')}")
                return message_dict
                
            except json.JSONDecodeError as e:
                print(f"[RECEIVE] JSON decode error: {str(e)}")
                print(f"[RECEIVE] Raw payload (first 100 bytes): {payload[:100]}")
                raise MessageError(f"Failed to decode message JSON: {str(e)}")
            except MessageValidationError as e:
                print(f"[RECEIVE] Validation error: {str(e)}")
                raise
            
        except MessageError as e:
            print(f"[RECEIVE] Decryption error: {str(e)}")
            raise
            
    except MessageError as e:
        print(f"[RECEIVE] Fatal error receiving message: {str(e)}")
        raise
    except Exception as e:
        print(f"[RECEIVE] Unhandled error: {str(e)}")
        raise MessageError(f"Failed to receive message: {str(e)}")

def create_message_ack(message_id: str, recipient_id: str) -> Dict:
    """Create acknowledgment for received message"""
    return {
        'type': 'ack',
        'message_id': message_id,
        'recipient_id': recipient_id,
        'timestamp': time.time()
    }

# a class to hold plain messages.
class LocalMessage:
    def __init__(self, message_id: int, recipient_username: str, message_type: int, is_income: bool, message, timestamp: Timestamp, is_read: bool):
        self.message_id = message_id
        self.recipient_username = recipient_username
        self.message_type = message_type
        self.is_income = is_income
        self.message = message
        self.timestamp = timestamp
        self.is_read = is_read