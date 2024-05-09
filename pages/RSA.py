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
    e = 107  # Example public exponent
    d = mod_inverse(e, phi)
    
    return (e, n), (d, n)

def main():
    st.title("RSA Key Generation Example")

    p = st.number_input("Enter prime number p:")
    q = st.number_input("Enter prime number q:")

    if p > 1 and q > 1:
        public_key, private_key = generate_keys(p, q)
        n = p * q
        phi = (p - 1) * (q - 1)
        t = phi
        st.write("p:", p)
        st.write("q:", q)
        st.write("n:", n)
        st.write("t:", t)
        st.write("gcd(e, t):", gcd(107, t))  # Check gcd(e, phi) for validation
        st.write("Public Key (e, n):", public_key)
        st.write("Private Key (d, n):", private_key)

    if st.button("Generate New Key Pair"):
        st.session_state.key_generated = True

if __name__ == "__main__":
    main()
