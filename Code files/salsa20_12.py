import nacl.secret
import nacl.utils
import time
import sys
import psutil
import os

filename = 'salsa20_12.py'
size = os.path.getsize(filename)

# Generate a random 256-bit key
key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)

nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)

# Create a secret box using the key
box = nacl.secret.SecretBox(key)

# Encrypt a message
# message = b'Hello'
# message = b'Hello Harsh!'
# message = b'Hello Harsh! How are you?'
# message = b'Hello Harsh! Abracadabra shoo!!!!!'
message = b'Good Morning! Do you like cryptography?'
start = time.time()
before = psutil.cpu_percent()
memory_usage = psutil.virtual_memory().used
encrypted = box.encrypt(message, nonce)
end = time.time()
after = psutil.cpu_percent()
cpu_usage = abs(after - before)
memory_usage = psutil.virtual_memory().used - memory_usage
print("Original message:", message)
print("\n-----------------------------------------")
print("Encrypted message:", encrypted.ciphertext)
print(f'Encryption time: {end - start:.5f} seconds')
print(f'CPU usage (encryption): {cpu_usage}%')
print(f"Memory usage (encryption): {abs(memory_usage)} bytes")
print("-----------------------------------------")

# Decrypt the message
start = time.time()
before = psutil.cpu_percent()
memory_usage = psutil.virtual_memory().used
decrypted = box.decrypt(encrypted)
end = time.time()
after = psutil.cpu_percent()
cpu_usage = abs(after - before)
memory_usage = psutil.virtual_memory().used - memory_usage
print("\n-----------------------------------------")
print("Decrypted message:", decrypted)
print(f'Decryption time: {end - start:.5f} seconds')
print(f'CPU usage (decryption): {cpu_usage}%')
print(f"Memory usage (decryption): {abs(memory_usage)} bytes")
print("-----------------------------------------")


print(f'Code size: {size} bytes')
# print(f'Message size: {sys.getsizeof(plaintext)} bytes')
# print(f'Message size: {sys.getsizeof(ciphertext)} bytes')
