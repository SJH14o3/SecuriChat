import json
import random
from typing import List, Dict, Tuple
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asymmetric_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

class OnionLayer:
    def __init__(self, node_public_key: str, next_address: Tuple[str, int]):
        self.node_public_key = node_public_key
        self.next_address = next_address

class OnionMessage:
    def __init__(self, content: str, sender_id: str, recipient_id: str):
        self.content = content
        self.sender_id = sender_id
        self.recipient_id = recipient_id
        self.layers: List[OnionLayer] = []
        
    def add_layer(self, node_public_key: str, next_address: Tuple[str, int]):
        """Add a new layer to the onion routing path"""
        self.layers.append(OnionLayer(node_public_key, next_address))

def create_onion_route(online_users: List[Dict], recipient_address: Tuple[str, int], 
                      num_hops: int = 3) -> List[OnionLayer]:
    """Create a random route through the network for onion routing"""
    available_nodes = [user for user in online_users 
                      if (user['ip_address'], user['port']) != recipient_address]
    
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
        next_address = (node['ip_address'], node['port'])
    
    return route

def encrypt_layer(data: bytes, public_key_pem: str) -> bytes:
    """Encrypt a layer using the node's public key"""
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode(),
        backend=default_backend()
    )
    
    # Generate a random AES key
    aes_key = os.urandom(32)
    iv = os.urandom(16)
    
    # Encrypt the AES key with RSA
    encrypted_key = public_key.encrypt(
        aes_key,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Encrypt the data with AES
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Add padding
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    
    # Encrypt
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    # Combine all components
    return json.dumps({
        'encrypted_key': encrypted_key.hex(),
        'iv': iv.hex(),
        'data': encrypted_data.hex()
    }).encode()

def decrypt_layer(encrypted_data: bytes, private_key_pem: str) -> Tuple[bytes, Tuple[str, int]]:
    """Decrypt a layer using the node's private key"""
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
    
    # Decrypt the AES key
    aes_key = private_key.decrypt(
        encrypted_key,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Decrypt the data with AES
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Remove padding
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    
    # Parse the decrypted data to get the next hop
    decrypted_dict = json.loads(data.decode())
    next_address = (decrypted_dict['next_ip'], decrypted_dict['next_port'])
    payload = decrypted_dict['payload'].encode()
    
    return payload, next_address

def create_onion_message(message: OnionMessage, sender_private_key: str) -> bytes:
    """Create an onion-encrypted message"""
    # Start with the innermost payload
    payload = json.dumps({
        'content': message.content,
        'sender_id': message.sender_id,
        'recipient_id': message.recipient_id
    }).encode()
    
    # Build the onion from the inside out
    for layer in reversed(message.layers):
        layer_data = json.dumps({
            'next_ip': layer.next_address[0],
            'next_port': layer.next_address[1],
            'payload': payload.decode()
        }).encode()
        
        payload = encrypt_layer(layer_data, layer.node_public_key)
    
    return payload

def process_onion_message(encrypted_data: bytes, node_private_key: str) -> Tuple[bytes, Tuple[str, int]]:
    """Process an onion-encrypted message at a relay node"""
    return decrypt_layer(encrypted_data, node_private_key)

def receive_final_message(encrypted_data: bytes, recipient_private_key: str) -> Dict:
    """Receive and decrypt the final message at its destination"""
    payload, _ = decrypt_layer(encrypted_data, recipient_private_key)
    message_dict = json.loads(payload.decode())
    return message_dict
