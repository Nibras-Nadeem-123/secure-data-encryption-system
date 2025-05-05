import streamlit as st
import json
import os
import hashlib
import time
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from hashlib import pbkdf2_hmac

# File paths
DATA_FILE = "data.json"
USER_FILE = "users.json"

# Load data and users from JSON files
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            return json.load(f)
    return {}

def load_users():
    if os.path.exists(USER_FILE):
        try:
            with open(USER_FILE, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            return {}
    return {}

# Save data and users to JSON files
def save_data(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f)

def save_users(users):
    with open(USER_FILE, 'w') as f:
        json.dump(users, f)

# Derive Fernet key using PBKDF2
def derive_key(password: str, salt: bytes = b'static_salt_12345678') -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# Encryption and Decryption
def encrypt_data(password, data):
    key = derive_key(password)
    f = Fernet(key)
    return f.encrypt(data.encode()).decode()

def decrypt_data(password, encrypted_data):
    key = derive_key(password)
    f = Fernet(key)
    return f.decrypt(encrypted_data.encode()).decode()

# Password Hashing
def hash_password(password):
    salt = os.urandom(16)
    hash_bytes = pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return base64.b64encode(salt + hash_bytes).decode()

def verify_password(stored_hash, password):
    decoded = base64.b64decode(stored_hash.encode())
    salt = decoded[:16]
    original_hash = decoded[16:]
    test_hash = pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return test_hash == original_hash

# Lockout check
def check_lockout(user, failed_attempts, lockout_time):
    if user in failed_attempts:
        attempts, last_failed = failed_attempts[user]
        if attempts >= 3 and time.time() - last_failed < lockout_time:
            return True
    return False

# Login page
def login_page(users, failed_attempts):
    st.title("Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type='password')

    if st.button("Login"):
        if username in users:
            stored_hash = users[username]["password_hash"]
            if verify_password(stored_hash, password):
                failed_attempts[username] = (0, time.time())
                st.session_state.authenticated = True
                st.session_state.username = username
                st.success(f"Welcome back, {username}!")
            else:
                failed_attempts[username] = (failed_attempts.get(username, (0, 0))[0] + 1, time.time())
                st.error("Invalid credentials")
        else:
            st.error("Invalid username")

# Register page
def register_page(users):
    st.title("Register")
    new_username = st.text_input("New Username")
    new_password = st.text_input("New Password", type="password")
    confirm_password = st.text_input("Confirm Password", type="password")

    if st.button("Register"):
        if new_username in users:
            st.error("Username already exists.")
        elif new_password != confirm_password:
            st.error("Passwords do not match.")
        elif not new_username or not new_password:
            st.error("Please fill in all fields.")
        else:
            hashed_pw = hash_password(new_password)
            users[new_username] = {"password_hash": hashed_pw}
            save_users(users)
            st.success("Registration successful! You can now log in.")

# Main page
def main_page(data_storage, users, failed_attempts):
    if 'authenticated' not in st.session_state or not st.session_state.authenticated:
        login_page(users, failed_attempts)
        return

    user = st.session_state.username
    lockout_time = 60

    if check_lockout(user, failed_attempts, lockout_time):
        st.warning("Too many failed attempts. Try again later.")
        st.session_state.authenticated = False
        return

    st.title("Secure Data Storage System")
    action = st.selectbox("Choose an action", ["Store Data", "Retrieve Data"])

    if action == "Store Data":
        passkey = st.text_input("Enter a passkey (to encrypt your data)")
        data = st.text_area("Enter the data to store")

        if st.button("Store Data"):
            if passkey:
                encrypted_data = encrypt_data(passkey, data)
                data_storage[user] = {"encrypted_data": encrypted_data}
                save_data(data_storage)
                st.success("Data stored securely!")
            else:
                st.error("Please provide a passkey.")

    elif action == "Retrieve Data":
        if user not in data_storage or 'encrypted_data' not in data_storage[user]:
            st.warning("No data found for this user.")
            return

        passkey = st.text_input("Enter your passkey to decrypt the data")

        if st.button("Retrieve Data"):
            encrypted_data = data_storage[user]["encrypted_data"]
            try:
                decrypted_data = decrypt_data(passkey, encrypted_data)
                st.text_area("Your data", decrypted_data, height=200)
            except Exception as e:
                st.error("Incorrect passkey or corrupted data.")
                failed_attempts[user] = (failed_attempts.get(user, (0, 0))[0] + 1, time.time())
                st.warning("Too many failed attempts. You are being logged out.")
                st.session_state.authenticated = False

# App entry point
def app():
    users = load_users()
    data_storage = load_data()

    st.session_state.setdefault('authenticated', False)
    st.session_state.setdefault('username', None)
    st.session_state.setdefault('failed_attempts', {})

    tab1, tab2 = st.tabs(["Login", "Register"])

    with tab1:
        if not st.session_state.authenticated:
            login_page(users, st.session_state.failed_attempts)
        else:
            main_page(data_storage, users, st.session_state.failed_attempts)

    with tab2:
        register_page(users)

if __name__ == "__main__":
    app()
