import streamlit as st
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

def is_prime(num):
    if num <= 1:
        return False
    for i in range(2, int(num**0.5) + 1):
        if num % i == 0:
            return False
    return True

def compute_n_and_t(p, q):
    n = p * q
    t = (p - 1) * (q - 1)
    return n, t

def generate_key_pair(p, q):
    try:
        key = RSA.generate(2048, e=65537, p=int(p), q=int(q))
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return private_key, public_key, key.e, key.d
    except ValueError:
        st.error("Unable to generate RSA key pair. Please try different prime numbers.")

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

    p = st.number_input("Value of Prime number p:", min_value=2, step=1)
    q = st.number_input("Value of Prime number q:", min_value=2, step=1)

    if is_prime(int(p)) and is_prime(int(q)):
        n, t = compute_n_and_t(int(p), int(q))
        st.text_area("Value of n:", value=str(n), height=1, max_chars=None)
        st.text_area("Value of t:", value=str(t), height=1, max_chars=None)

        if st.button("Generate Key Pair"):
            private_key, public_key, e, d = generate_key_pair(int(p), int(q))
            if private_key and public_key:
                st.text_area("Public Key (e,n) for Encryption:", value=f"{e},{n}", height=1, max_chars=None)
                st.text_area("Private Key (d,n) for Decryption:", value=f"{d},{n}", height=1, max_chars=None)
                st.text_area("Public Key:", value=public_key.decode(), height=10, max_chars=None)
                st.text_area("Private Key:", value=private_key.decode(), height=10, max_chars=None)
    else:
        st.error("Please enter prime numbers for p and q.")

    mode = st.radio("Mode", ("Encrypt Text", "Decrypt Text"))
    text = st.text_area("Enter Text to Process")

    if st.button("Process"):
        if mode == "Encrypt Text":
            if public_key:
                encrypted_text = rsa_encrypt(text, public_key)
                st.text_area("Encrypted Text", value=base64.b64encode(encrypted_text).decode(), height=10, max_chars=None)
            else:
                st.error("Please generate the key pair first.")
        else:
            if private_key:
                if text.strip():
                    encrypted_text = base64.b64decode(text)
                    decrypted_text = rsa_decrypt(encrypted_text, private_key)
                    st.text_area("Decrypted Text", value=decrypted_text, height=10, max_chars=None)
                else:
                    st.error("Please enter text to decrypt.")
            else:
                st.error("Please generate the key pair first.")

if __name__ == "__main__":
    main()
