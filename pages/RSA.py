import streamlit as st

def encrypt(message, public_key, n):
    e = public_key
    encrypted_text = 1
    while e > 0:
        encrypted_text *= message
        encrypted_text %= n
        e -= 1
    return encrypted_text
 
def decrypt(encrypted_text, private_key, n):
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
        public_key, n = generate_keys(p, q)
        st.write("Public Key (e, n):", public_key)
        st.write("Private Key (d, n):", private_key)

        if message:
            message_int = int.from_bytes(message.encode(), 'big')
            encrypted_message = encrypt(message_int, public_key, n)
            st.write("Encrypted Message:", encrypted_message)

            decrypted_message_int = decrypt(encrypted_message, private_key, n)
            decrypted_message = decrypted_message_int.to_bytes((decrypted_message_int.bit_length() + 7) // 8, 'big').decode()
            st.write("Decrypted Message:", decrypted_message)

if __name__ == "__main__":
    main()
