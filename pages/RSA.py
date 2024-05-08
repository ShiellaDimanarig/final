import streamlit as st
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

def generate_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def rsa_encrypt(message, public_key):
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    encrypted_message = cipher.encrypt(message.encode())
    return encrypted_message

def rsa_decrypt(ciphertext, private_key):
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    decrypted_message = cipher.decrypt(ciphertext)
    return decrypted_message.decode()

def main():
    st.title("RSA Encryption App")

    private_key, public_key = generate_key_pair()

    st.text("Public Key:")
    st.text_area("Public Key", value=public_key.decode(), height=10, max_chars=None, key=None)

    st.text("Private Key:")
    st.text_area("Private Key", value=private_key.decode(), height=10, max_chars=None, key=None)

    mode = st.radio("Mode", ("Encrypt Text", "Decrypt Text"))
    text = st.text_area("Enter Text to Process")

    if st.button("Process"):
        if mode == "Encrypt Text":
            encrypted_text = rsa_encrypt(text, public_key)
            st.text_area("Encrypted Text", value=base64.b64encode(encrypted_text).decode(), height=10, max_chars=None, key=None)
        else:
            try:
                encrypted_text = base64.b64decode(text)
                decrypted_text = rsa_decrypt(encrypted_text, private_key)
                st.text_area("Decrypted Text", value=decrypted_text, height=10, max_chars=None, key=None)
            except Exception as e:
                st.error("Error decrypting text. Please check the input and try again.")

if __name__ == "__main__":
    main()
