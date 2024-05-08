import streamlit as st

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def generate_keys(p, q):
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537  # Commonly used public exponent
    d = mod_inverse(e, phi)
    return ((e, n), (d, n))

def encrypt_message(message, public_key):
    e, n = public_key
    encrypted_message = [pow(ord(char), e, n) for char in message]
    return encrypted_message

def decrypt_message(encrypted_message, private_key):
    d, n = private_key
    decrypted_message = [chr(pow(char, d, n)) for char in encrypted_message]
    return ''.join(decrypted_message)

def main():
    st.title("RSA Encryption and Decryption")

    p = st.number_input("Enter prime number p:")
    q = st.number_input("Enter prime number q:")
    message = st.text_input("Enter message to encrypt:")

    if p > 1 and q > 1:
        public_key, private_key = generate_keys(p, q)
        st.write("Public Key (e, n):", public_key)
        st.write("Private Key (d, n):", private_key)

        if message:
            encrypted_message = encrypt_message(message, public_key)
            st.write("Encrypted Message:", encrypted_message)

            decrypted_message = decrypt_message(encrypted_message, private_key)
            st.write("Decrypted Message:", decrypted_message)

if __name__ == "__main__":
    main()
