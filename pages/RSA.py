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
    
    # Choose a value for e that is relatively prime to phi
    e = 65537  # Commonly used public exponent
    while gcd(e, phi) != 1:
        e += 2  # Increment e until it's relatively prime to phi
    
    # Compute the modular multiplicative inverse of e modulo phi
    d = mod_inverse(e, phi)
    
    return (e, n), (d, n)

# To encrypt the given number
def encrypt(message):
    global public_key, n
    e = public_key
    encrypted_text = 1
    while e > 0:
        encrypted_text *= message
        encrypted_text %= n
        e -= 1
    return encrypted_text
 
 
# To decrypt the given number
def decrypt(encrypted_text):
    global private_key, n
    d = private_key
    decrypted = 1
    while d > 0:
        decrypted *= encrypted_text
        decrypted %= n
        d -= 1
    return decrypted

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
            message_int = int.from_bytes(message.encode(), 'big')
            encrypted_message = encrypt_message(message_int, public_key)
            st.write("Encrypted Message:", encrypted_message)

            decrypted_message_int = decrypt_message(encrypted_message, private_key)
            decrypted_message = decrypted_message_int.to_bytes((decrypted_message_int.bit_length() + 7) // 8, 'big').decode()
            st.write("Decrypted Message:", decrypted_message)

if __name__ == "__main__":
    main()
