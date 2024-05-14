import streamlit as st
import hashlib
import io
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

def hash_text(text, hash_type):
    if hash_type == "MD5":
        return hashlib.md5(text.encode()).hexdigest()
    elif hash_type == "SHA-1":
        return hashlib.sha1(text.encode()).hexdigest()
    elif hash_type == "SHA-256":
        return hashlib.sha256(text.encode()).hexdigest()
    elif hash_type == "SHA-512":
        return hashlib.sha512(text.encode()).hexdigest()

def hash_file(file, hash_type):
    if hash_type == "MD5":
        hasher = hashlib.md5()
    elif hash_type == "SHA-1":
        hasher = hashlib.sha1()
    elif hash_type == "SHA-256":
        hasher = hashlib.sha256()
    elif hash_type == "SHA-512":
        hasher = hashlib.sha512()
    file_contents = file.read()
    hasher.update(file_contents)
    return hasher.hexdigest()

def encrypt_text(text, key):
    iv = os.urandom(16)
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.pad(text.encode())
    encrypted_text = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_text

def decrypt_text(encrypted_text, key):
    iv = encrypted_text[:16]
    encrypted_text = encrypted_text[16:]
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_padded_text = decryptor.update(encrypted_text) + decryptor.finalize()
    decrypted_text = unpadder.unpad(decrypted_padded_text)
    return decrypted_text.decode()

def encrypt_file(file, key):
    iv = os.urandom(16)
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.pad(file.read())
    encrypted_file = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_file

def decrypt_file(encrypted_file, key):
    iv = encrypted_file[:16]
    encrypted_file = encrypted_file[16:]
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_padded_file = decryptor.update(encrypted_file) + decryptor.finalize()
    decrypted_file = unpadder.unpad(decrypted_padded_file)
    return decrypted_file

# Streamlit app
st.title("Hashing and Encryption Functions🔐")

option = st.radio("Choose input method:", ("Text", "File"))

if option == "Text":
    text = st.text_input("Enter text:")
    if text:
        hash_type = st.selectbox("Choose a hash function:", ("MD5", "SHA-1", "SHA-256", "SHA-512"))
        hashed_text = hash_text(text, hash_type)
        st.write("Hash value:", hashed_text)
        key = st.text_input("Enter encryption key (16, 24, or 32 bytes):")
        if key:
            key = key.encode()
            if len(key) in [16, 24, 32]:
                encrypted_text = encrypt_text(text, key)
                st.write("Encrypted text:", encrypted_text.hex())
                decrypted_text = decrypt_text(encrypted_text, key)
                st.write("Decrypted text:", decrypted_text)
            else:
                st.write("Error: Key must be 16, 24, or 32 bytes long.")
elif option == "File":
    file = st.file_uploader("Upload a file to hash:", type=["txt", "pdf", "docx", "csv", "xlsx"])
    if file:
        hash_type = st.selectbox("Choose a hash function:", ("MD5", "SHA-1", "SHA-256", "SHA-512"))
        hashed_file = hash_file(io.BytesIO(file.read()), hash_type)
        st.write("Hash value:", hashed_file)
        key = st.text_input("Enter encryption key (16, 24, or 32 bytes):")
        if key:
            key = key.encode()
            if len(key) in [16, 24, 32]:
                encrypted_file = encrypt_file(io.BytesIO(file.read()), key)
                st.write("Encrypted file:", encrypted_file.hex())
                decrypted_file = decrypt_file(encrypted_file, key)
                st.download_button("Download decrypted file", decrypted_file, file.name)
            else:
                st.write("Error: Key must be 16, 24, or 32 bytes long.")
