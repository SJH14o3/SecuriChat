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

# Constants
MAX_MESSAGE_AGE = 300  # 5 minutes in seconds
MAX_RETRIES = 3
CHUNK_SIZE = 1024 * 64  # 64KB chunks for large messages

class MessageError(Exception):
    """Base class for message-related errors"""
    pass

class MessageValidationError(MessageError):
    """Raised when message validation fails"""
    pass

class MessageCorruptionError(MessageError):
    """Raised when message corruption is detected"""
    pass

class OnionLayer:
    def __init__(self, node_public_key: str, next_address: Tuple[str, str]):
        self.node_public_key = node_public_key
        self.next_address = next_address
        self.layer_id = str(uuid.uuid4())

class OnionMessage:
    def __init__(self, content: str, sender_id: str, recipient_id: str):
        self.content = content
        self.sender_id = sender_id
        self.recipient_id = recipient_id
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
    return checksum + message_data

def verify_checksum(message_with_checksum: bytes) -> Tuple[bool, bytes]:
    """Verify message integrity using checksum"""
    checksum = message_with_checksum[:32]  # SHA-256 is 32 bytes
    message = message_with_checksum[32:]
    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(message)
    calculated_checksum = hasher.finalize()
    return checksum == calculated_checksum, message

def validate_message(message_dict: Dict) -> bool:
    """Validate required message fields and format"""
    required_fields = ['content', 'sender_id', 'recipient_id', 
                      'sequence_number', 'timestamp', 'message_id']
    
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
    """Create a random route through the network for onion routing"""
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
    """Encrypt a layer using the node's public key"""
    try:
        # Step 1: Load the public key
        try:
            print(f"Attempting to load public key. Key starts with: {public_key_pem[:50]}...")
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode(),
                backend=default_backend()
            )
        except Exception as e:
            raise MessageError(f"Failed to load public key: {str(e)}")

        # Step 2: Generate AES key and IV
        try:
            aes_key = os.urandom(32)
            iv = os.urandom(16)
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
        except Exception as e:
            raise MessageError(f"Failed to encrypt AES key with RSA: {str(e)}")

        # Step 4: Create AES cipher
        try:
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
        except Exception as e:
            raise MessageError(f"Failed to create AES cipher: {str(e)}")

        # Step 5: Add padding
        try:
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(data) + padder.finalize()
        except Exception as e:
            raise MessageError(f"Failed to add padding: {str(e)}")

        # Step 6: Encrypt data with AES
        try:
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        except Exception as e:
            raise MessageError(f"Failed to encrypt data with AES: {str(e)}")

        # Step 7: Generate HMAC
        try:
            h = hmac.HMAC(aes_key, hashes.SHA256())
            h.update(encrypted_data)
            mac = h.finalize()
        except Exception as e:
            raise MessageError(f"Failed to generate HMAC: {str(e)}")

        # Step 8: Format final output
        try:
            return json.dumps({
                'encrypted_key': encrypted_key.hex(),
                'iv': iv.hex(),
                'data': encrypted_data.hex(),
                'mac': mac.hex()
            }).encode()
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
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(),
            password=None,
            backend=default_backend()
        )
        
        # Parse the encrypted data
        data_dict = json.loads(encrypted_data.decode())
        encrypted_key = bytes.fromhex(data_dict['encrypted_key'])
        iv = bytes.fromhex(data_dict['iv'])
        ciphertext = bytes.fromhex(data_dict['data'])
        mac = bytes.fromhex(data_dict['mac'])
        
        # Decrypt the AES key
        aes_key = private_key.decrypt(
            encrypted_key,
            asymmetric_padding.OAEP(
                mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Verify HMAC
        h = hmac.HMAC(aes_key, hashes.SHA256())
        h.update(ciphertext)
        try:
            h.verify(mac)
        except Exception:
            raise MessageCorruptionError("Message integrity check failed")
        
        # Decrypt the data with AES
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        # Remove padding
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        
        # Parse the decrypted data to get the next hop
        decrypted_dict = json.loads(data.decode())
        next_address = (str(decrypted_dict['next_ip']), str(decrypted_dict['next_port']))
        payload = decrypted_dict['payload'].encode()
        
        # Verify checksum if present
        if 'checksum' in decrypted_dict:
            is_valid, payload = verify_checksum(payload)
            if not is_valid:
                raise MessageCorruptionError("Checksum verification failed")
        
        return payload, next_address
    except MessageError:
        raise
    except Exception as e:
        raise MessageError(f"Decryption failed: {str(e)}")

def create_onion_message(message: OnionMessage, sender_private_key: str) -> bytes:
    """Create an onion-encrypted message with integrity checks"""
    try:
        # Split large messages into chunks
        if len(message.content.encode()) > CHUNK_SIZE:
            chunks = [message.content[i:i+CHUNK_SIZE] for i in range(0, len(message.content), CHUNK_SIZE)]
            message.chunks = chunks
            message.total_chunks = len(chunks)
            
        # Create the base message
        message_data = {
            'content': message.content if not message.chunks else message.chunks[0],
            'sender_id': message.sender_id,
            'recipient_id': message.recipient_id,
            'message_id': message.message_id,
            'sequence_number': message.sequence_number,
            'timestamp': message.timestamp,
            'total_chunks': message.total_chunks,
            'chunk_index': 0 if not message.chunks else 1
        }
        
        # Convert to bytes and add checksum
        payload = json.dumps(message_data).encode()
        payload_with_checksum = add_checksum(payload)
        
        # Build the onion layers
        for layer in reversed(message.layers):
            next_ip , next_port = layer.next_address
            layer_data = json.dumps({
                'next_ip': str(next_ip),
                'next_port': next_port,
                'layer_id': layer.layer_id,
                'payload': payload_with_checksum.hex(),
                'checksum': True
            }).encode()
            
            payload_with_checksum = add_checksum(encrypt_layer(layer_data, layer.node_public_key))
        
        return payload_with_checksum
    except Exception as e:
        raise MessageError(f"Failed to create onion message: {str(e)}")

def process_onion_message(encrypted_data: bytes, node_private_key: str) -> Optional[Tuple[bytes, Tuple[str, str]]]:
    """Process an onion-encrypted message at a relay node with error handling"""
    retries = 0
    while retries < MAX_RETRIES:
        try:
            return decrypt_layer(encrypted_data, node_private_key)
        except MessageCorruptionError:
            retries += 1
            if retries >= MAX_RETRIES:
                raise MessageError("Maximum retries exceeded - message corrupted")
            time.sleep(1)
        except MessageError as e:
            raise MessageError(f"Failed to process message: {str(e)}")

def receive_final_message(encrypted_data: bytes, recipient_private_key: str) -> Dict:
    """Receive and decrypt the final message at its destination with validation"""
    try:
        payload, _ = decrypt_layer(encrypted_data, recipient_private_key)
        message_dict = json.loads(payload.decode())
        
        # Validate the message
        if not validate_message(message_dict):
            raise MessageValidationError("Message validation failed")
            
        # Check message age
        if time.time() - message_dict['timestamp'] > MAX_MESSAGE_AGE:
            raise MessageValidationError("Message too old")
            
        return message_dict
    except MessageError as e:
        raise MessageError(f"Failed to receive message: {str(e)}")

def create_message_ack(message_id: str, recipient_id: str) -> Dict:
    """Create acknowledgment for received message"""
    return {
        'type': 'ack',
        'message_id': message_id,
        'recipient_id': recipient_id,
        'timestamp': time.time()
    }
