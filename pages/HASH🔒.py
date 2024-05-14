import streamlit as st
import hashlib
import io
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

def hash_text(text, hash_type):
    # Hash the input text using the specified hash function
    if hash_type == "MD5":
        return hashlib.md5(text.encode()).hexdigest()
    elif hash_type == "SHA-1":
        return hashlib.sha1(text.encode()).hexdigest()
    elif hash_type == "SHA-256":
        return hashlib.sha256(text.encode()).hexdigest()
    elif hash_type == "SHA-512":
        return hashlib.sha512(text.encode()).hexdigest()

def hash_file(file, hash_type):
    # Hash the contents of the input file using the specified hash function
    if hash_type == "MD5":
        hasher = hashlib.md5()
    elif hash_type == "SHA-1":
        hasher = hashlib.sha1()
    elif hash_type == "SHA-256":
        hasher = hashlib.sha256()
    elif hash_type == "SHA-512":
        hasher = hashlib.sha512()

    # Read the file contents
    file_contents = file.read()

    # Calculate the hash
    hasher.update(file_contents)

    return hasher.hexdigest()

def encrypt_text(text, key):
    # Encrypt the input text using AES encryption
    iv = os.urandom(16)
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.pad(text.encode())
    encrypted_text = encryptor.update(padded_data) + encryptor.finalize()

    return iv + encrypted_text

def decrypt_text(encrypted_text, key):
    # Decrypt the input text using AES encryption
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
    # Encrypt the contents of the input file using AES encryption
    iv = os.urandom(16)
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.pad(file.read())
    encrypted_file = encryptor.update(padded_data) + encryptor.finalize()

    return iv + encrypted_file

def decrypt_file(encrypted_file, key):
    # Decrypt the contents of the input file using AES encryption
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

# Ask the user to input text or upload a file
option = st.radio("Choose input method:", ("Text", "File"))

if option == "Text":
    # Ask the user to input text
    text = st.text_input("Enter text:")
    if text:
        # Ask the user to select the hash function
        hash_type = st.selectbox("Choose a hash function:", ("MD5", "SHA-1", "SHA-256", "SHA-512"))

        # Hash the text using the selected hash function
        hashed_text = hash_text(text, hash_type)

        # Display the hash value
        st.write("Hash value:", hashed_text)

        # Ask the user to input an encryption key
        key = st.text_input("Enter encryption key (16, 24, or 32 bytes):")
        if key:
            key = key.encode()
            if len(key) in [16, 24, 32]:
                # Encrypt the text
                encrypted_text = encrypt_text(text, key)
                st.write("Encrypted text:", encrypted_text.hex())

                # Decrypt the text
                decrypted_text = decrypt_text(encrypted_text, key)
                st.write("Decrypted text:", decrypted_text)
            else:
                st.write("Error: Key must be 16, 24, or 32 bytes long.")
elif option == "File":
    # Ask the user to upload a file
    file = st.file_uploader("Upload a file to hash:", type=["txt", "pdf", "docx", "csv", "xlsx"])
    if file:
        # Ask the user to select the hash function
        hash_type = st.selectbox("Choose a hash function:", ("MD5", "SHA-1", "SHA-256", "SHA-512"))

        # Hash the file contents using the selected hash function
        hashed_file = hash_file(io.BytesIO(file.read()), hash_type)

        # Display the hash value
        st.write("Hash value:", hashed_file)

        # Ask the user to input an encryption key
        key = st.text_input("Enter encryption key (16, 24, or 32 bytes):")
        if key:
            key = key.encode()
            if len(key) in [16, 24, 32]:
                # Encrypt the file
                encrypted_file = encrypt_file(io.BytesIO(file.read()), key)
                st.write("Encrypted file:", encrypted_file.hex())

                # Decrypt the file
                decrypted_file = decrypt_file(encrypted_file, key)
                st.download_button("Download decrypted file", decrypted_file, file.name)
            else:
                st.write("Error: Key must be 16, 24, or 32 bytes long.")
