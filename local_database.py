import os
import sqlite3
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from timestamp import Timestamp
from local_message import LocalMessage
from log import Log

TABLE_MESSAGES = "messages"

COLUMN_ID = "id"
COLUMN_OTHER_USERNAME = "other_username"
COLUMN_MESSAGE_TYPE = "message_type"
COLUMN_IS_INCOME = "is_income"
COLUMN_MESSAGE = "message"
COLUMN_TIMESTAMP = "timestamp"
COLUMN_NONCE = "nonce"
COLUMN_TAG = "tag"
COLUMN_IS_READ = "is_read"
COLUMN_FILE_METADATA = "file_metadata"

MESSAGE_TYPE_TEXT = 0
MESSAGE_TYPE_IMAGE = 1
MESSAGE_TYPE_VIDEO = 2
MESSAGE_TYPE_AUDIO = 3
MESSAGE_TYPE_FILE = 4

def encrypt_message(message: bytes, key: bytes):
    nonce = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce),
        backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    return ciphertext, nonce, encryptor.tag

def decrypt_message(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes):
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce, tag),
        backend=default_backend()
    ).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def create_database(username: str):
    with sqlite3.connect(f"users/{username}/local.db") as conn:
        # Create the main table
        conn.execute(f"""CREATE TABLE IF NOT EXISTS {TABLE_MESSAGES} (
            {COLUMN_ID} INTEGER PRIMARY KEY AUTOINCREMENT,
            {COLUMN_OTHER_USERNAME} TEXT NOT NULL,
            {COLUMN_MESSAGE_TYPE} INTEGER NOT NULL,
            {COLUMN_IS_INCOME} INTEGER NOT NULL,
            {COLUMN_MESSAGE} BLOB NOT NULL,
            {COLUMN_TIMESTAMP} INTEGER NOT NULL,
            {COLUMN_NONCE} BLOB NOT NULL,
            {COLUMN_TAG} BLOB NOT NULL,
            {COLUMN_IS_READ} INTEGER NOT NULL
        );""")
        
        # Check if file_metadata column exists
        cursor = conn.cursor()
        cursor.execute(f"PRAGMA table_info({TABLE_MESSAGES})")
        columns = [column[1] for column in cursor.fetchall()]
        
        # Add file_metadata column if it doesn't exist
        if COLUMN_FILE_METADATA not in columns:
            try:
                conn.execute(f"ALTER TABLE {TABLE_MESSAGES} ADD COLUMN {COLUMN_FILE_METADATA} TEXT;")
            except sqlite3.OperationalError:
                # Column might have been added by another process
                pass

class LocalDatabase:
    def __init__(self, username):
        self.path = f"users/{username}/local.db"
        create_database(username)  # Ensure database exists

    def store_message(self, message: LocalMessage, aes_key: bytes, log: Log):
        ciphertext, nonce, encrypted_tag = encrypt_message(message.message, aes_key)
        log.append_log("encrypted a message using AES and stored it in local database")
        file_metadata = json.dumps({'file_name': message.file_name, 'file_size': message.file_size}) if message.message_type == MESSAGE_TYPE_FILE else None
        with sqlite3.connect(self.path) as conn:
            cursor = conn.cursor()
            cursor.execute(f"""INSERT INTO {TABLE_MESSAGES} (
                {COLUMN_OTHER_USERNAME}, {COLUMN_MESSAGE_TYPE}, {COLUMN_IS_INCOME},
                {COLUMN_MESSAGE}, {COLUMN_TIMESTAMP}, {COLUMN_NONCE}, {COLUMN_TAG},
                {COLUMN_IS_READ}, {COLUMN_FILE_METADATA}
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                message.recipient_username,
                message.message_type,
                1 if message.is_income else 0,
                ciphertext,
                Timestamp.get_now().timestamp,
                nonce,
                encrypted_tag,
                1 if message.is_read else 0,
                file_metadata
            ))
            conn.commit()

    def get_message_by_id(self, message_id: int, aes_key: bytes, log: Log) -> LocalMessage:
        log.append_log(f"extracted ciphered message with id {message_id} from local database and decrypted it using AES")
        with sqlite3.connect(self.path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(f"""
                SELECT * FROM {TABLE_MESSAGES} 
                WHERE {COLUMN_ID} = ?
            """, (message_id,))
            row = cursor.fetchone()
            if not row:
                raise ValueError(f"Message ID {message_id} not found")
            decrypted_bytes = decrypt_message(
                row[COLUMN_MESSAGE],
                aes_key,
                row[COLUMN_NONCE],
                row[COLUMN_TAG]
            )
            file_metadata = json.loads(row[COLUMN_FILE_METADATA]) if row[COLUMN_FILE_METADATA] is not None else {}
            return LocalMessage(
                message_id=row[COLUMN_ID],
                recipient_username=row[COLUMN_OTHER_USERNAME],
                message_type=row[COLUMN_MESSAGE_TYPE],
                is_income=(row[COLUMN_IS_INCOME] == 1),
                message=decrypted_bytes,
                timestamp=Timestamp(row[COLUMN_TIMESTAMP]),
                is_read=(row[COLUMN_IS_READ] == 1),
                file_name=file_metadata.get('file_name'),
                file_size=file_metadata.get('file_size')
            )

    def get_latest_messages_per_user(self, aes_key: bytes) -> list[LocalMessage]:
        with sqlite3.connect(self.path) as conn:
            cursor = conn.cursor()
            # First check if file_metadata column exists
            cursor.execute(f"PRAGMA table_info({TABLE_MESSAGES})")
            columns = [column[1] for column in cursor.fetchall()]
            
            # Build the query based on available columns
            file_metadata_select = f"COALESCE({COLUMN_FILE_METADATA}, 'null') as {COLUMN_FILE_METADATA}" if COLUMN_FILE_METADATA in columns else "'null' as file_metadata"
            
            cursor.execute(f"""
                SELECT 
                    {COLUMN_ID},
                    {COLUMN_OTHER_USERNAME},
                    COALESCE({COLUMN_MESSAGE_TYPE}, 0) as {COLUMN_MESSAGE_TYPE},
                    COALESCE({COLUMN_IS_INCOME}, 0) as {COLUMN_IS_INCOME},
                    {COLUMN_MESSAGE},
                    COALESCE({COLUMN_TIMESTAMP}, 0) as {COLUMN_TIMESTAMP},
                    {COLUMN_NONCE},
                    {COLUMN_TAG},
                    COALESCE({COLUMN_IS_READ}, 1) as {COLUMN_IS_READ},
                    {file_metadata_select}
                FROM {TABLE_MESSAGES}
                WHERE {COLUMN_ID} IN (
                    SELECT MAX({COLUMN_ID}) FROM {TABLE_MESSAGES}
                    GROUP BY {COLUMN_OTHER_USERNAME}
                )
                ORDER BY {COLUMN_ID} DESC
            """)
            rows = cursor.fetchall()
            messages = []
            for row in rows:
                try:
                    # Map column indices to values based on table creation order
                    message_id = row[0]  # id
                    other_username = row[1]  # other_username
                    message_type = row[2]  # message_type
                    is_income = row[3]  # is_income
                    message = row[4]  # message
                    timestamp = row[5]  # timestamp
                    nonce = row[6]  # nonce
                    tag = row[7]  # tag
                    is_read = row[8]  # is_read
                    file_metadata_str = row[9]  # file_metadata
                    
                    decrypted_bytes = decrypt_message(
                        message,
                        aes_key,
                        nonce,
                        tag
                    )
                    try:
                        file_metadata = json.loads(file_metadata_str) if file_metadata_str and file_metadata_str != 'null' else {}
                    except (json.JSONDecodeError, TypeError):
                        file_metadata = {}
                        
                    message = LocalMessage(
                        message_id=message_id,
                        recipient_username=other_username,
                        message_type=message_type,
                        is_income=(is_income == 1),
                        message=decrypted_bytes,
                        timestamp=Timestamp(timestamp),
                        is_read=(is_read == 1),
                        file_name=file_metadata.get('file_name'),
                        file_size=file_metadata.get('file_size')
                    )
                    messages.append(message)
                except Exception as e:
                    print(f"Error processing message: {e}")
                    continue
            return messages

    def get_a_user_all_messages(self, other_username: str, aes_key: bytes) -> list[LocalMessage]:
        with sqlite3.connect(self.path) as conn:
            cursor = conn.cursor()
            # First check if file_metadata column exists
            cursor.execute(f"PRAGMA table_info({TABLE_MESSAGES})")
            columns = [column[1] for column in cursor.fetchall()]
            
            # Build the query based on available columns
            file_metadata_select = f"COALESCE({COLUMN_FILE_METADATA}, 'null') as {COLUMN_FILE_METADATA}" if COLUMN_FILE_METADATA in columns else "'null' as file_metadata"
            
            cursor.execute(f"""
                SELECT 
                    {COLUMN_ID},
                    {COLUMN_OTHER_USERNAME},
                    COALESCE({COLUMN_MESSAGE_TYPE}, 0) as {COLUMN_MESSAGE_TYPE},
                    COALESCE({COLUMN_IS_INCOME}, 0) as {COLUMN_IS_INCOME},
                    {COLUMN_MESSAGE},
                    COALESCE({COLUMN_TIMESTAMP}, 0) as {COLUMN_TIMESTAMP},
                    {COLUMN_NONCE},
                    {COLUMN_TAG},
                    COALESCE({COLUMN_IS_READ}, 1) as {COLUMN_IS_READ},
                    {file_metadata_select}
                FROM {TABLE_MESSAGES} 
                WHERE {COLUMN_OTHER_USERNAME} = ? 
                ORDER BY {COLUMN_ID} DESC
            """, (other_username,))
            out = []
            rows = cursor.fetchall()
            for row in rows:
                try:
                    # Map column indices to values based on table creation order
                    message_id = row[0]  # id
                    other_username = row[1]  # other_username
                    message_type = row[2]  # message_type
                    is_income = row[3]  # is_income
                    message = row[4]  # message
                    timestamp = row[5]  # timestamp
                    nonce = row[6]  # nonce
                    tag = row[7]  # tag
                    is_read = row[8]  # is_read
                    file_metadata_str = row[9]  # file_metadata
                    
                    decrypted_bytes = decrypt_message(
                        message,
                        aes_key,
                        nonce,
                        tag
                    )
                    try:
                        file_metadata = json.loads(file_metadata_str) if file_metadata_str and file_metadata_str != 'null' else {}
                    except (json.JSONDecodeError, TypeError):
                        file_metadata = {}
                        
                    message = LocalMessage(
                        message_id=message_id,
                        recipient_username=other_username,
                        message_type=message_type,
                        is_income=(is_income == 1),
                        message=decrypted_bytes,
                        timestamp=Timestamp(timestamp),
                        is_read=(is_read == 1),
                        file_name=file_metadata.get('file_name'),
                        file_size=file_metadata.get('file_size')
                    )
                    out.append(message)
                except Exception as e:
                    print(f"Error processing message: {e}")
                    continue
            return out

    def mark_messages_as_read_until_sent_or_read(self, other_username: str):
        with sqlite3.connect(self.path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(f"""
                SELECT * FROM {TABLE_MESSAGES}
                WHERE {COLUMN_OTHER_USERNAME} = ?
                ORDER BY {COLUMN_ID} DESC
            """, (other_username,))
            messages_to_mark = []
            for row in cursor.fetchall():
                is_income = row[COLUMN_IS_INCOME] == 1
                is_read = row[COLUMN_IS_READ] == 1
                if not is_income:
                    break
                if is_read:
                    break
                messages_to_mark.append(row[COLUMN_ID])
            if messages_to_mark:
                cursor.executemany(f"""
                    UPDATE {TABLE_MESSAGES}
                    SET {COLUMN_IS_READ} = 1
                    WHERE {COLUMN_ID} = ?
                """, [(msg_id,) for msg_id in messages_to_mark])
                conn.commit()