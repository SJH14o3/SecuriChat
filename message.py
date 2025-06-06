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
    def __init__(self, content: str, sender_id: str, recipient_id: str, message_type: str = 'text',
                 file_name: str = None, file_size: int = None):
        self.content = content
        self.sender_id = sender_id
        self.recipient_id = recipient_id
        self.message_type = message_type
        self.file_name = file_name
        self.file_size = file_size
        self.layers: List[OnionLayer] = []
        self.message_id = str(uuid.uuid4())
        self.sequence_number = 0
        self.timestamp = time.time()
        self.chunks: List[str] = []
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
    if len(message_with_checksum) < 32:
        return False, b""

    checksum = message_with_checksum[:32]
    message = message_with_checksum[32:]

    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(message)
    calculated_checksum = hasher.finalize()

    return checksum == calculated_checksum, message


def validate_message(message_dict: Dict) -> bool:
    """Validate required message fields and format"""
    required_fields = ['content', 'sender_id', 'recipient_id',
                       'sequence_number', 'timestamp', 'message_id',
                       'message_type']

    if message_dict['message_type'] == 'file':
        required_fields.extend(['file_name', 'file_size'])

    if not all(field in message_dict for field in required_fields):
        return False

    if time.time() - message_dict['timestamp'] > MAX_MESSAGE_AGE:
        return False

    if not isinstance(message_dict['content'], str):
        return False

    if message_dict['message_type'] == 'file':
        if not isinstance(message_dict['file_name'], str) or not isinstance(message_dict['file_size'], int):
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

    for node in reversed(route_nodes):
        route.append(OnionLayer(
            node_public_key=node['public_key'],
            next_address=(node['ip_address'], str(node['port']))
        ))
        next_address = (node['ip_address'], str(node['port']))

    return route


def encrypt_layer(data: bytes, public_key_pem: str) -> bytes:
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode(),
            backend=default_backend()
        )
        aes_key = os.urandom(32)
        iv = os.urandom(16)
        encrypted_key = public_key.encrypt(
            aes_key,
            asymmetric_padding.OAEP(
                mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        h = hmac.HMAC(aes_key, hashes.SHA256())
        h.update(encrypted_data)
        mac = h.finalize()
        metadata = {
            'encrypted_key': encrypted_key.hex(),
            'iv': iv.hex(),
            'mac': mac.hex(),
            'data_length': len(encrypted_data)
        }
        metadata_json = json.dumps(metadata).encode('utf-8')
        metadata_length = len(metadata_json).to_bytes(4, byteorder='big')
        payload = metadata_length + metadata_json + encrypted_data
        hasher = hashes.Hash(hashes.SHA256())
        hasher.update(payload)
        checksum = hasher.finalize()
        result = checksum + payload
        return result
    except Exception as e:
        raise MessageError(f"Encryption failed: {str(e)}")


def decrypt_layer(encrypted_data: bytes, private_key_pem: str) -> Tuple[bytes, Tuple[str, str]]:
    try:
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(),
            password=None,
            backend=default_backend()
        )
        checksum = encrypted_data[:32]
        payload = encrypted_data[32:]
        hasher = hashes.Hash(hashes.SHA256())
        hasher.update(payload)
        calculated_checksum = hasher.finalize()
        if checksum != calculated_checksum:
            raise MessageCorruptionError("Checksum verification failed")
        metadata_length = int.from_bytes(payload[:4], byteorder='big')
        metadata_json = payload[4:4 + metadata_length]
        data_dict = json.loads(metadata_json.decode('utf-8'))
        encrypted_data_bytes = payload[4 + metadata_length:]
        encrypted_key = bytes.fromhex(data_dict['encrypted_key'])
        iv = bytes.fromhex(data_dict['iv'])
        mac = bytes.fromhex(data_dict['mac'])
        ciphertext = encrypted_data_bytes[:data_dict['data_length']]
        aes_key = private_key.decrypt(
            encrypted_key,
            asymmetric_padding.OAEP(
                mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        h = hmac.HMAC(aes_key, hashes.SHA256())
        h.update(ciphertext)
        h.verify(mac)
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        decrypted_dict = json.loads(data.decode('utf-8'))
        next_address = (str(decrypted_dict['next_ip']), str(decrypted_dict['next_port']))
        payload = bytes.fromhex(decrypted_dict['payload'])
        if 'checksum' in decrypted_dict:
            is_valid, payload = verify_checksum(payload)
            if not is_valid:
                raise MessageCorruptionError("Checksum verification failed")
        return payload, next_address
    except Exception as e:
        raise MessageError(f"Decryption failed: {str(e)}")


def create_onion_message(content: str, sender_id: str, recipient_id: str, message_type: str = 'text',
                        file_name: str = None, file_size: int = None) -> OnionMessage:
    """Create a new onion message with the given content and metadata"""
    message = OnionMessage(content, sender_id, recipient_id, message_type, file_name, file_size)
    return message


def create_onion_message_encrypted(message: OnionMessage, recipient_public_key: str) -> bytes:
    """Create an encrypted onion message from an OnionMessage object"""
    try:
        if len(message.content.encode()) > CHUNK_SIZE:
            chunks = [message.content[i:i + CHUNK_SIZE] for i in range(0, len(message.content), CHUNK_SIZE)]
            message.chunks = chunks
            message.total_chunks = len(chunks)

        message_data = {
            'content': message.content if not message.chunks else message.chunks[0],
            'sender_id': message.sender_id,
            'recipient_id': message.recipient_id,
            'message_id': message.message_id,
            'sequence_number': message.sequence_number,
            'timestamp': message.timestamp,
            'total_chunks': message.total_chunks,
            'chunk_index': 0 if not message.chunks else 1,
            'message_type': message.message_type,
            'file_name': message.file_name,
            'file_size': message.file_size
        }

        if not validate_message(message_data):
            raise MessageValidationError("Invalid message data")

        payload = json.dumps(message_data).encode('utf-8')
        payload_with_checksum = add_checksum(payload)

        # For direct messaging without onion routing, encrypt directly with recipient's public key
        layer_data = json.dumps({
            'next_ip': None,  # Not using onion routing
            'next_port': None,  # Not using onion routing
            'layer_id': str(uuid.uuid4()),
            'payload': payload_with_checksum.hex(),
            'checksum': True
        }).encode('utf-8')
        return encrypt_layer(layer_data, recipient_public_key)

    except MessageValidationError as e:
        raise
    except MessageError as e:
        raise
    except Exception as e:
        raise MessageError(f"Failed to create onion message: {str(e)}")


def process_onion_message(encrypted_data: bytes, node_private_key: str) -> Optional[Tuple[bytes, Tuple[str, str]]]:
    retries = 0
    while retries < MAX_RETRIES:
        try:
            if not encrypted_data:
                raise MessageError("Empty encrypted data received")
            result = decrypt_layer(encrypted_data, node_private_key)
            if not result or len(result) != 2:
                raise MessageError("Invalid decryption result format")
            payload, next_address = result
            if not payload:
                raise MessageError("Empty payload after decryption")
            if not next_address or len(next_address) != 2:
                raise MessageError(f"Invalid next_address format: {next_address}")
            return payload, next_address
        except MessageCorruptionError:
            retries += 1
            if retries >= MAX_RETRIES:
                raise MessageError("Maximum retries exceeded - message corrupted")
            time.sleep(1)
        except MessageError as e:
            raise
        except Exception as e:
            raise MessageError(f"Failed to process message: {str(e)}")


def receive_final_message(encrypted_data: bytes, recipient_private_key: str) -> Dict:
    """Receive and decrypt the final message layer"""
    try:
        if not encrypted_data:
            raise MessageError("Empty encrypted data received")
        if not isinstance(encrypted_data, bytes):
            raise MessageError(f"Expected bytes for encrypted_data, got {type(encrypted_data)}")
        if not isinstance(recipient_private_key, str):
            raise MessageError(f"Expected string for private key, got {type(recipient_private_key)}")

        try:
            payload, _ = decrypt_layer(encrypted_data, recipient_private_key)
            if not payload:
                raise MessageError("Empty payload after decryption")
        except Exception as e:
            raise MessageError(f"Decryption layer failed: {str(e)}")

        try:
            decoded_payload = payload.decode()
            if not decoded_payload:
                raise MessageError("Empty decoded payload")
        except UnicodeDecodeError as e:
            raise MessageError(f"Failed to decode payload as UTF-8: {str(e)}")
        except Exception as e:
            raise MessageError(f"Failed to decode payload: {str(e)}")

        try:
            message_dict = json.loads(decoded_payload)
        except json.JSONDecodeError as e:
            raise MessageError(f"Failed to parse JSON payload: {str(e)}, Payload: {decoded_payload[:100]}")
        except Exception as e:
            raise MessageError(f"Failed to parse message data: {str(e)}")

        if not isinstance(message_dict, dict):
            raise MessageValidationError(f"Message is not a valid dictionary, got {type(message_dict)}")

        required_fields = ['content', 'sender_id', 'recipient_id',
                           'sequence_number', 'timestamp', 'message_id']
        if message_dict.get('message_type') == 'file':
            required_fields.extend(['file_name', 'file_size'])

        missing_fields = [field for field in required_fields if field not in message_dict]
        if missing_fields:
            raise MessageValidationError(f"Missing required fields: {missing_fields}")

        if not validate_message(message_dict):
            raise MessageValidationError("Message validation failed")

        message_age = time.time() - message_dict['timestamp']
        if message_age > MAX_MESSAGE_AGE:
            raise MessageValidationError(f"Message too old (age: {message_age}s)")

        return message_dict
    except MessageError:
        raise
    except Exception as e:
        raise MessageError(f"Failed to receive message: {str(e)}")


def create_message_ack(message_id: str, recipient_id: str) -> Dict:
    return {
        'type': 'ack',
        'message_id': message_id,
        'recipient_id': recipient_id,
        'timestamp': time.time()
    }


class LocalMessage:
    def __init__(self, message_id: int, recipient_username: str, message_type: int, is_income: bool, message,
                 timestamp: Timestamp, is_read: bool):
        self.message_id = message_id
        self.recipient_username = recipient_username
        self.message_type = message_type
        self.is_income = is_income
        self.message = message
        self.timestamp = timestamp
        self.is_read = is_read