import streamlit as st
import random
import math

prime = set()
public_key = None
private_key = None
n = None

def primefiller():
    seive = [True] * 250
    seive[0] = False
    seive[1] = False
    for i in range(2, 250):
        for j in range(i * 2, 250, i):
            seive[j] = False
    for i in range(len(seive)):
        if seive[i]:
            prime.add(i)

def pickrandomprime():
    global prime
    k = random.randint(0, len(prime) - 1)
    it = iter(prime)
    for _ in range(k):
        next(it)
    ret = next(it)
    prime.remove(ret)
    return ret

def setkeys():
    global public_key, private_key, n
    prime1 = pickrandomprime()
    prime2 = pickrandomprime()
    n = prime1 * prime2
    fi = (prime1 - 1) * (prime2 - 1)
    e = 2
    while True:
        if math.gcd(e, fi) == 1:
            break
        e += 1
    public_key = e
    d = 2
    while True:
        if (d * e) % fi == 1:
            break
        d += 1
    private_key = d

def encrypt(message):
    global public_key, n
    e = public_key
    encrypted_text = 1
    while e > 0:
        encrypted_text *= message
        encrypted_text %= n
        e -= 1
    return encrypted_text

def decrypt(encrypted_text):
    global private_key, n
    d = private_key
    decrypted = 1
    while d > 0:
        decrypted *= encrypted_text
        decrypted %= n
        d -= 1
    return decrypted

def encoder(message):
    encoded = []
    for letter in message:
        encoded.append(encrypt(ord(letter)))
    return encoded

def decoder(encoded):
    s = ''
    for num in encoded:
        s += chr(decrypt(num))
    return s

def main():
    st.title("RSA Encryption App")
    primefiller()
    setkeys()

    st.text_input("Public Key:", value=str(public_key), key="public_key_input")
    st.text_input("Private Key:", value=str(private_key), key="private_key_input")

    mode = st.radio("Mode", ("Encrypt Text", "Decrypt Text"))
    text = st.text_area("Enter Text to Process")

    if st.button("Process"):
        if mode == "Encrypt Text":
            coded = encoder(text)
            st.text_area("Encrypted Text", value=''.join(str(p) for p in coded), height=10, max_chars=None)
        else:
            try:
                coded = [int(x) for x in text.split()]
                decoded_text = decoder(coded)
                st.text_area("Decrypted Text", value=decoded_text, height=10, max_chars=None)
            except Exception as e:
                st.error("Error decrypting text. Please check the input and try again.")

if __name__ == "__main__":
    main()
