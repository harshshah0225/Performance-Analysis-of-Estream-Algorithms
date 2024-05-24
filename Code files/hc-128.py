import sys
import secrets
import time
import psutil
from memory_profiler import memory_usage
import os

filename = 'hc-128.py'
size = os.path.getsize(filename)


def hc_128(key, iv, plaintext):
    """
    Encrypt plaintext using HC-128 algorithm
    key: bytes-like object containing the encryption key (should be 16 bytes long)
    iv: bytes-like object containing the initialization vector (should be 16 bytes long)
    plaintext: bytes-like object containing the plaintext to be encrypted
    returns: bytes-like object containing the ciphertext
    """
    
    # Initialize state and key
    state = [0] * 256
    for i in range(16):
        state[i] = key[i]
        state[i+16] = iv[i]
    for i in range(16, 256):
        state[i] = s1(state[i-16] ^ state[i-13] ^ s0(state[i-6] ^ state[i-16]))

    # Generate keystream
    keystream = b''
    i, j = 0, 0
    for _ in range(len(plaintext)):
        i = (i + 1) % 256
        j = (j + state[i]) % 256
        state[i], state[j] = state[j], state[i]
        keystream_byte = s2(state[i] + state[j])
        keystream += bytes([keystream_byte])

    # Encrypt plaintext
    ciphertext = b''
    for i in range(len(plaintext)):
        ciphertext_byte = plaintext[i] ^ keystream[i]
        ciphertext += bytes([ciphertext_byte])

    return ciphertext


def hc_128_decrypt(key, iv, ciphertext):
    """
    Decrypt ciphertext using HC-128 algorithm
    key: bytes-like object containing the decryption key (should be 16 bytes long)
    iv: bytes-like object containing the initialization vector (should be 16 bytes long)
    ciphertext: bytes-like object containing the ciphertext to be decrypted
    returns: bytes-like object containing the plaintext
    """

    # Initialize state and key
    state = [0] * 256
    for i in range(16):
        state[i] = key[i]
        state[i+16] = iv[i]
    for i in range(16, 256):
        state[i] = s1(state[i-16] ^ state[i-13] ^ s0(state[i-6] ^ state[i-16]))

    # Generate keystream
    keystream = b''
    i, j = 0, 0
    for _ in range(len(ciphertext)):
        i = (i + 1) % 256
        j = (j + state[i]) % 256
        state[i], state[j] = state[j], state[i]
        keystream_byte = s2(state[i] + state[j])
        keystream += bytes([keystream_byte])

    # Decrypt ciphertext
    plaintext = b''
    for i in range(len(ciphertext)):
        plaintext_byte = ciphertext[i] ^ keystream[i]
        plaintext += bytes([plaintext_byte])

    return plaintext


def s0(x):
    return (x >> 7) ^ ((x >> 2) & 0x3f) ^ ((x << 3) & 0xff)


def s1(x):
    return (x >> 3) ^ ((x << 5) & 0xff)


def s2(x):
    return (x >> 1) ^ ((x << 7) & 0xff)


key = secrets.token_bytes(16)
iv = secrets.token_bytes(16)
plaintext = b'Hello'
# plaintext = b'Hello Harsh!'
# plaintext = b'Hello Harsh! How are you?'
# plaintext = b'Hello Harsh! Abracadabra shoo!!!!!'
# plaintext = b'Good Morning! Do you like cryptography?'
print("Plaintext:", plaintext)

start = time.time()
before = psutil.cpu_percent()
memory_usage = psutil.virtual_memory().used
ciphertext = hc_128(key, iv, plaintext)
end = time.time()
after = psutil.cpu_percent()
cpu_usage = abs(after - before)
memory_usage = psutil.virtual_memory().used - memory_usage
print("\n-----------------------------------------")
print("Ciphertext:", ciphertext)
print(f'Encryption time: {end - start:.5f} seconds')
print(f'CPU usage (encryption): {cpu_usage}%')
print(f"Memory usage (encryption): {abs(memory_usage)} bytes")
print("-----------------------------------------")


start = time.time()
before = psutil.cpu_percent()
memory_usage = psutil.virtual_memory().used
decrypted_plaintext = hc_128_decrypt(key, iv, ciphertext)
memory_usage = psutil.virtual_memory().used
end = time.time()
after = psutil.cpu_percent()
cpu_usage = abs(after - before)
memory_usage = psutil.virtual_memory().used - memory_usage
print("\n-----------------------------------------")
print("Decrypted plaintext:", decrypted_plaintext)
print(f'Decryption time: {end - start:.5f} seconds')
print(f'CPU usage (decryption): {cpu_usage}%')
print(f"Memory usage (decryption): {abs(memory_usage)} bytes")
print("-----------------------------------------")
# print(f'Message size: {sys.getsizeof(plaintext)} bytes')
# print(f'Message size: {sys.getsizeof(ciphertext)} bytes')
print(f'Code size: {size} bytes')

