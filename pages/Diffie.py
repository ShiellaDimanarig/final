import streamlit as st

# Function to compute modular exponentiation (base^exp mod mod)
def mod_exp(base, exp, mod):
    result = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        exp //= 2
        base = (base * base) % mod
    return result

def diffie_hellman(p, g, private_key):
    # Calculate public key
    public_key = mod_exp(g, private_key, p)
    return public_key

# Streamlit app
st.title("Diffie-Hellman Key Exchange")

# Input parameters
p = st.number_input("Enter the prime number (p):", min_value=2, step=1, value=23)
g = st.number_input("Enter the base (g):", min_value=2, step=1, value=5)
private_key = st.number_input("Enter your private key (a):", min_value=1, step=1, value=6)

# Calculate public key using Diffie-Hellman
if st.button("Calculate Public Key"):
    public_key = diffie_hellman(p, g, private_key)
    st.success(f"Your public key: {public_key}")

    # Input for received message
    received_message = st.text_input("Enter the received message:", "")

    # Display received message
    if received_message:
        st.info(f"Received Message: {received_message}")

# Simulate sent message (based on user input)
sent_message = st.text_input("Enter the message you sent:", "")
if sent_message:
    st.success(f"Sent Message: {sent_message}")
