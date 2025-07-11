import os
import sqlite3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from timestamp import Timestamp
from message import LocalMessage
from log import Log

""" file for storing each user messages. messages will be encrypted """

TABLE_MESSAGES = "messages" # table name for messages

# columns used for storing message
COLUMN_ID = "id"
COLUMN_OTHER_USERNAME = "other_username"
COLUMN_MESSAGE_TYPE = "message_type"
COLUMN_iS_INCOME = "is_income" # 1 is income, 0 is outgoing
COLUMN_TIMESTAMP = "timestamp"
COLUMN_MESSAGE = "message"
COLUMN_IS_READ = "is_read" # 1: message is read by user, 0: message is not read by user
COLUMN_NONCE = "nonce"
COLUMN_TAG = "tag"
COLUMN_SUFFIX = "suffix"

# enumerate for message types. did not use actual enum since they can differ in runtime
MESSAGE_TYPE_TEXT = 0
MESSAGE_TYPE_IMAGE = 1
MESSAGE_TYPE_VIDEO = 2
MESSAGE_TYPE_AUDIO = 3
MESSAGE_TYPE_FILE = 4

# encrypt plain message in bytes using AES algorithm
def encrypt_message(message: bytes, key: bytes):
    nonce = os.urandom(12)  # 96-bit nonce is standard for AES-GCM
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce),
        backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    return ciphertext, nonce, encryptor.tag

# encrypt ciphered message using AES algorithm
def decrypt_message(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes):
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce, tag),
        backend=default_backend()
    ).decryptor()

    return decryptor.update(ciphertext) + decryptor.finalize()

# when a user creates a new account, this table will be made
def create_database(username: str):
    query = f"""CREATE TABLE IF NOT EXISTS {TABLE_MESSAGES} (
    {COLUMN_ID} INTEGER PRIMARY KEY AUTOINCREMENT,
    {COLUMN_OTHER_USERNAME} TEXT NOT NULL,
    {COLUMN_MESSAGE_TYPE} INT NOT NULL,
    {COLUMN_iS_INCOME} INTEGER NOT NULL,
    {COLUMN_MESSAGE} BLOB NOT NULL,
    {COLUMN_TIMESTAMP} INTEGER NOT NULL,
    {COLUMN_NONCE} BLOB NOT NULL,
    {COLUMN_TAG} BLOB NOT NULL,
    {COLUMN_IS_READ} INTEGER NOT NULL,
    {COLUMN_SUFFIX} TEXT NOT NULL
    );"""
    with sqlite3.connect(f"users/{username}/local.db") as conn:
        conn.execute(query)

# class only holds path...
def get_latest_messages_previous(message_bytes, type_: int) -> bytes:
    if type_ == MESSAGE_TYPE_TEXT:
        return message_bytes
    elif type_ == MESSAGE_TYPE_IMAGE:
        return b'image'
    elif type_ == MESSAGE_TYPE_VIDEO:
        return b'video'
    elif type_ == MESSAGE_TYPE_AUDIO:
        return b'audio'
    else:
        return b'file'


class LocalDatabase:
    def __init__(self, username):
        self.username = username
        self.path = f"users/{username}/local.db"

    # receives plain message and encrypt it then store it in database
    def store_message(self, message: LocalMessage, aes_key: bytes, log: Log):
        ciphertext, nonce, encrypted_tag = encrypt_message(message.message, aes_key)
        log.append_log("encrypted a message using AES and stored it in local database")
        with sqlite3.connect(self.path) as conn:
            cursor = conn.cursor()
            cursor.execute(f"""INSERT INTO {TABLE_MESSAGES} ({COLUMN_OTHER_USERNAME}, {COLUMN_MESSAGE_TYPE}, {COLUMN_iS_INCOME},
            {COLUMN_MESSAGE}, {COLUMN_TIMESTAMP}, {COLUMN_NONCE}, {COLUMN_TAG}, {COLUMN_IS_READ}, {COLUMN_SUFFIX}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                message.recipient_username,
                message.message_type,
                1 if message.is_income else 0,
                ciphertext,
                Timestamp.get_now().timestamp,
                nonce,
                encrypted_tag,
                1 if message.is_read else 0,
                message.suffix
            ))
            conn.commit()

    # extract ciphered message from database and decrypt it
    def get_message_by_id(self, message_id: int, aes_key: bytes, log: Log, username) -> LocalMessage:
        log.append_log(f"extracted ciphered message with id {message_id} from local database and decrypted it using AES")
        with sqlite3.connect(self.path) as conn:
            conn.row_factory = sqlite3.Row  # Enable named access
            cursor = conn.cursor()
            cursor.execute(f"""
                SELECT {COLUMN_MESSAGE_TYPE}, {COLUMN_iS_INCOME}, {COLUMN_MESSAGE}, 
                       {COLUMN_TIMESTAMP}, {COLUMN_NONCE}, {COLUMN_TAG}, 
                       {COLUMN_IS_READ}, {COLUMN_OTHER_USERNAME}, {COLUMN_SUFFIX}
                FROM {TABLE_MESSAGES} 
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

            return LocalMessage(
                message_id=message_id,
                recipient_username=row[COLUMN_OTHER_USERNAME],
                message_type=row[COLUMN_MESSAGE_TYPE],
                is_income=(row[COLUMN_iS_INCOME] == 1),
                message=decrypted_bytes,
                timestamp=Timestamp(row[COLUMN_TIMESTAMP]),
                is_read=(row[COLUMN_IS_READ] == 1),
                suffix=row[COLUMN_SUFFIX],
                receiver_id=username
            )

    def get_latest_messages_per_user(self, aes_key: bytes, username_) -> list[LocalMessage]:
        with sqlite3.connect(self.path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Subquery to get the latest message ID per user
            cursor.execute(f"""
                SELECT * FROM {TABLE_MESSAGES}
                WHERE {COLUMN_ID} IN (
                    SELECT MAX({COLUMN_ID}) FROM {TABLE_MESSAGES}
                    GROUP BY {COLUMN_OTHER_USERNAME}
                )
                ORDER BY {COLUMN_ID} DESC
            """)

            rows = cursor.fetchall()
            messages = []

            for row in rows:
                decrypted_bytes = decrypt_message(
                    row[COLUMN_MESSAGE],
                    aes_key,
                    row[COLUMN_NONCE],
                    row[COLUMN_TAG]
                )

                message = LocalMessage(
                    message_id=row[COLUMN_ID],
                    recipient_username=row[COLUMN_OTHER_USERNAME],
                    message_type=row[COLUMN_MESSAGE_TYPE],
                    is_income=(row[COLUMN_iS_INCOME] == 1),
                    message=get_latest_messages_previous(decrypted_bytes, row[COLUMN_MESSAGE_TYPE]),
                    timestamp=Timestamp(row[COLUMN_TIMESTAMP]),
                    is_read=(row[COLUMN_IS_READ] == 1),
                    suffix=row[COLUMN_SUFFIX],
                    receiver_id=username_
                )

                messages.append(message)

        return messages

    def get_a_user_all_messages(self, other_username: str, aes_key: bytes, username) -> list[LocalMessage]:
        with sqlite3.connect(self.path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                f"SELECT * FROM {TABLE_MESSAGES} WHERE {COLUMN_OTHER_USERNAME} = ? ORDER BY {COLUMN_ID} DESC",
                (other_username,)
            )
            out = []
            rows = cursor.fetchall()
            for row in rows:
                decrypted_bytes = decrypt_message(
                    row[COLUMN_MESSAGE],
                    aes_key,
                    row[COLUMN_NONCE],
                    row[COLUMN_TAG]
                )

                message = LocalMessage(
                    message_id=row[COLUMN_ID],
                    recipient_username=row[COLUMN_OTHER_USERNAME],
                    message_type=row[COLUMN_MESSAGE_TYPE],
                    is_income=(row[COLUMN_iS_INCOME] == 1),
                    message=decrypted_bytes,
                    timestamp=Timestamp(row[COLUMN_TIMESTAMP]),
                    is_read=(row[COLUMN_IS_READ] == 1),
                    suffix=row[COLUMN_SUFFIX],
                    receiver_id=username
                )
                out.append(message)
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
                is_income = row[COLUMN_iS_INCOME] == 1
                is_read = row[COLUMN_IS_READ] == 1

                if not is_income:
                    break  # Outgoing message: stop
                if is_read:
                    break  # Already read: stop

                messages_to_mark.append(row[COLUMN_ID])

            if messages_to_mark:
                cursor.executemany(f"""
                    UPDATE {TABLE_MESSAGES}
                    SET {COLUMN_IS_READ} = 1
                    WHERE {COLUMN_ID} = ?
                """, [(msg_id,) for msg_id in messages_to_mark])
                conn.commit()
