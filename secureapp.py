import streamlit as st  # type: ignore
import hashlib
import json
import time
from cryptography.fernet import Fernet  # type: ignore
import base64
import os

DATA_FILE = "user_data.json"

# Load stored data from JSON file
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

# Save data to JSON file
def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

# Hash any input
def hash_text(text):
    return hashlib.sha256(text.encode()).hexdigest()

# Generate encryption key from passkey
def generate_key(passkey):
    hashed = hashlib.sha256(passkey.encode()).digest()
    return base64.urlsafe_b64encode(hashed[:32])

# Encrypt text
def encrypt_data(text, passkey):
    key = generate_key(passkey)
    cipher = Fernet(key)
    return cipher.encrypt(text.encode()).decode()

# Decrypt text
def decrypt_data(encrypted_text, passkey):
    try:
        key = generate_key(passkey)
        cipher = Fernet(key)
        return cipher.decrypt(encrypted_text.encode()).decode()
    except Exception:
        return None

# Session state initialization
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'last_attempt_time' not in st.session_state:
    st.session_state.last_attempt_time = 0
if 'current_page' not in st.session_state:
    st.session_state.current_page = "Home"
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = load_data()

# Lockout handling
def reset_failed_attempts():
    st.session_state.failed_attempts = 0

# UI
st.set_page_config(layout="wide", page_title="Secure Data Storer")
st.title("🔐 Username + Passkey Secure Storage")

# Navigation
pages = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", pages, index=pages.index(st.session_state.current_page))
st.session_state.current_page = choice

# Lockout check
if st.session_state.failed_attempts >= 3:
    st.session_state.current_page = "Login"
    st.warning("🔒 Too many failed attempts! Admin login required.")

# Home
if st.session_state.current_page == "Home":
    st.subheader("🏠 Welcome")
    st.write("Store & retrieve your encrypted data using your **username** and **passkey**.")
    st.info(f"🧠 Total users with stored data: {len(st.session_state.stored_data)}")
    if st.button("Store New Data"):
        st.session_state.current_page = "Store Data"
    if st.button("Retrieve Data"):
        st.session_state.current_page = "Retrieve Data"

# Store Data
elif st.session_state.current_page == "Store Data":
    st.subheader("📂 Store Encrypted Data")

    username = st.text_input("Username:")
    passkey = st.text_input("Passkey:", type="password")
    confirm_passkey = st.text_input("Confirm Passkey:", type="password")
    data = st.text_area("Enter data to encrypt:")

    if st.button("Encrypt & Save"):
        if username and passkey and confirm_passkey and data:
            if passkey != confirm_passkey:
                st.error("❌ Passkeys do not match!")
            else:
                user_key = hash_text(username)
                passkey_hash = hash_text(passkey)
                encrypted_data = encrypt_data(data, passkey)
                st.session_state.stored_data[user_key] = {
                    "passkey_hash": passkey_hash,
                    "encrypted_data": encrypted_data
                }
                save_data(st.session_state.stored_data)
                st.success("✅ Data encrypted and saved successfully!")
        else:
            st.error("⚠️ Please fill out all fields.")

# Retrieve Data
elif st.session_state.current_page == "Retrieve Data":
    st.subheader("🔍 Retrieve Encrypted Data")

    attempts_left = 3 - st.session_state.failed_attempts
    st.info(f"Attempts remaining: {attempts_left}")

    username = st.text_input("Username:")
    passkey = st.text_input("Passkey:", type="password")

    if st.button("Decrypt"):
        if username and passkey:
            user_key = hash_text(username)
            passkey_hash = hash_text(passkey)

            if user_key in st.session_state.stored_data:
                user_record = st.session_state.stored_data[user_key]

                if user_record["passkey_hash"] == passkey_hash:
                    decrypted = decrypt_data(user_record["encrypted_data"], passkey)
                    if decrypted:
                        st.success("✅ Data decrypted successfully!")
                        st.code(decrypted, language="text")
                        reset_failed_attempts()
                    else:
                        st.session_state.failed_attempts += 1
                        st.session_state.last_attempt_time = time.time()
                        st.error("❌ Decryption failed. Maybe wrong passkey?")
                else:
                    st.session_state.failed_attempts += 1
                    st.session_state.last_attempt_time = time.time()
                    st.error("❌ Incorrect passkey!")
            else:
                st.session_state.failed_attempts += 1
                st.session_state.last_attempt_time = time.time()
                st.error("❌ Username not found!")

            if st.session_state.failed_attempts >= 3:
                st.warning("🔐 Too many failed attempts. Redirecting to Admin Login.")
                st.session_state.current_page = "Login"
                st.rerun()
        else:
            st.error("⚠️ Please enter both username and passkey.")

# Admin Login Page
elif st.session_state.current_page == "Login":
    st.subheader("🔑 Admin Login")

    if time.time() - st.session_state.last_attempt_time < 10:
        wait_time = int(10 - (time.time() - st.session_state.last_attempt_time))
        st.warning(f"⏳ Please wait {wait_time} seconds before trying again.")
    else:
        admin_pass = st.text_input("Enter Admin Password:", type="password")
        if st.button("Login"):
            if admin_pass == "admin123":
                reset_failed_attempts()
                st.success("✅ Reauthorized successfully.")
                st.session_state.current_page = "Home"
                st.rerun()
            else:
                st.error("❌ Incorrect admin password.")

# Footer
st.markdown("---")
st.markdown("🔐 Username + Passkey Secure Storage | Educational Project")
