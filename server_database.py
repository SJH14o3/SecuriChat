import os
import sqlite3
from cryptography.fernet import Fernet
from timestamp import Timestamp
from statics import *
from log import Log
from user import User
KEY = Fernet(os.environ.get("SocketProjectServerKey").encode()) # for now, key is stored in environment variables
USERS_DB = "users.db"
USERS = "users"

# column names in database
COLUMN_USERNAME = "username"
COLUMN_PASSWORD = "password"
COLUMN_EMAIL = "email"
COLUMN_PUBLIC_KEY = "public_key"
COLUMN_PROFILE_PICTURE = "profile_picture"
COLUMN_LAST_SEEN = "last_seen"
COLUMN_DISPLAY_NAME = "display_name"

# called for signing in user
def sign_in_user(username, password, email, public_key, profile_picture_bytes, display_name, log: Log):
    conn = sqlite3.connect(USERS_DB)
    cursor = conn.cursor()

    # Checking if username already exists
    cursor.execute(f"SELECT 1 FROM {USERS} WHERE {COLUMN_USERNAME} = ?", (username,))
    if cursor.fetchone():
        return DATABASE_SIGNIN_USERNAME_CONFLICT

    # Encrypting sensitive fields
    try:
        encrypted_password = KEY.encrypt(password.encode())
        encrypted_email = KEY.encrypt(email.encode())
        log.append_log("encrypted new user password and email")
    except Exception as e:
        print(f"Encryption error: {e}")
        return DATABASE_ENCRYPTION_FAILED

    # Trying to insert new user into the database
    try:
        cursor.execute(
            f"""INSERT INTO {USERS} 
            ({COLUMN_USERNAME}, {COLUMN_PASSWORD}, {COLUMN_EMAIL}, {COLUMN_PUBLIC_KEY}, {COLUMN_PROFILE_PICTURE}, {COLUMN_LAST_SEEN}, {COLUMN_DISPLAY_NAME}) 
            VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                username,
                encrypted_password,
                encrypted_email,
                public_key,
                profile_picture_bytes,
                Timestamp.get_now().timestamp,  # current timestamp for last_seen
                display_name
            )
        )
        conn.commit()
        print("User registered successfully.")
        return DATABASE_SIGNIN_SUCCESS
    except Exception as e:
        print(f"Database error: {e}")
        return DATABASE_SIGNIN_FAILURE

# logging in the user
def login_user(username, password):
        try:
            with sqlite3.connect(USERS_DB) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
                row = cursor.fetchone()
                # checking if username exists
                if row is None:
                    return DATABASE_LOGIN_USERNAME_NOT_FOUND
                decrypted_password = KEY.decrypt(row[0]).decode()
                print("user log pass:", decrypted_password)
                if decrypted_password == password:
                    return DATABASE_LOGIN_SUCCESS
                return DATABASE_LOGIN_PASSWORD_MISSMATCH
        except Exception as e:
            return e

# returns a user public key
def get_user_public_key(username):
    with sqlite3.connect(USERS_DB) as conn:
        cursor = conn.cursor()
        cursor.execute(f"SELECT {COLUMN_PUBLIC_KEY} FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        if row is None:
            return DATABASE_USERNAME_NOT_FOUND
        return row[0]

# get user based on their username
def get_user(username) -> User | None:
    with sqlite3.connect(USERS_DB) as conn:
        cursor = conn.cursor()
        cursor.execute(f"SELECT {COLUMN_DISPLAY_NAME}, {COLUMN_PUBLIC_KEY}, {COLUMN_PROFILE_PICTURE}, {COLUMN_LAST_SEEN} FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        if row is None:
            return None
        display_name = row[0]
        public_key = row[1]
        profile_picture = row[2]
        last_seen = Timestamp(row[3])
        return User(username, display_name, public_key, profile_picture, last_seen)


# every time when server is run, this function's called. it will create database if it doesn't exist
def create_users_table_if_not_exists():
    conn = sqlite3.connect(USERS_DB)
    query = f"""CREATE TABLE IF NOT EXISTS {USERS} ({COLUMN_USERNAME} TEXT PRIMARY KEY, {COLUMN_PASSWORD} TEXT NOT NULL,
    {COLUMN_EMAIL} TEXT NOT NULL, {COLUMN_PUBLIC_KEY} TEXT NOT NULL, {COLUMN_PROFILE_PICTURE} BLOB, {COLUMN_LAST_SEEN} INT, {COLUMN_DISPLAY_NAME} TEXT);"""
    conn.execute(query)