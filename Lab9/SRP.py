import socket
import hashlib
import random
import secrets
from Crypto.Cipher import AES
from Crypto.Util import Counter

# REFERENCE: 
# RFC 2945: https://www.rfc-editor.org/rfc/rfc2945#ref-SRP
# RFC 5054: https://www.ietf.org/rfc/rfc5054.txt 

# Function to convert long to bytes
def long_to_bytes(n):
    # Calculate the number of bytes required to represent the integer
    num_bytes = (n.bit_length() + 7) // 8
    # Convert the integer to a bytes object using big-endian byte order
    return n.to_bytes(num_bytes, byteorder='big')

# Function to convert bytes to long
def bytes_to_long(b):
    # Convert the byte string to a long integer using big-endian byte order
    return int.from_bytes(b, byteorder='big', signed=False)

# Message format
# TLV: | 1 Byte Type | 1 Byte Length | Variable |
def messageCon(typeID, lenVar, var):
    return typeID.to_bytes(1, 'little') + lenVar.to_bytes(1, 'little') + str(var).encode('utf-8')

def get_msb32(byte):
    # Convert the byte to a 32-bit integer
    value = int.from_bytes(byte, byteorder='big', signed=False)
    # Shift the value right by 32 bits to get the MSB32
    msb32 = value >> 32
    return msb32

# SHA Interleave Function
def SHA_Interleave(input_bytes):
    # Remove leading zero bytes in pre-master secret S
    data = long_to_bytes(input_bytes)
    data = data.lstrip(b'\x00')

    # If length of resulting S is odd, remove first byte
    if len(data) % 2 != 0:
        data = data[1:]

    # Extract even and odd numbered bytes
    E = data[::2] # Even = every second element starting from index 0: 0,2,4
    F = data[1::2] # Odd = every second element starting from index 1: 1,3,5

    # SHA1 hash E and F halves
    G = hashlib.sha1(E).digest() 
    H = hashlib.sha1(F).digest()

    # Interleave the hashes: G0, H0, G1, H1, G2, H2
    K = b''
    for g, h in zip(G, H):
        K += long_to_bytes(g) + long_to_bytes(h)
    return K

# RFC 865
echoServer = ('172.27.54.47', 7)
socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.connect(echoServer)

# 1: Prover sending ID to Verifier
# Prover ---> Verifier
id = 'alice' # username
w = 'password123' # password
typeID = 1
message = messageCon(typeID, len(str(id)), id) # Send message in TLV format
socket.send(message)
print(f"1. Prover: Login using {id}:{w}")

# 2: Verifer returns a salt
# Prover <--- Verifier
socket.recv(1)
length = socket.recv(1)
salt = socket.recv(int(length.hex(), 16)) # Received salt
print(f"2. Verifier: Salt = {salt}")

# 3: Generate random a and send A = g^a mod N
# Prover ---> Verifier
g = 2
N =  0xEEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3
#q = 0xF7E75FDC469067FFDC4E847C51F452DFA2F1D0B0117FDC90E3A6B6D0111D23C97EEE7C1C1E4A3F6393973FA33C8D3E80A00D749D23C35A932DF8CD8BEC4D
#N = 2 * q + 1
a = 3
#a = random.randint(1,100)
A = pow(g,a,N) # A = g^a mod N
typeID = 3
message = long_to_bytes(typeID) + long_to_bytes(1) + long_to_bytes(A)
socket.send(message) # Send A = g^a mod N
print(f"3. Prover: Sending A = {A}")

# 4: Receive B = (kv + g^b) mod N
# Prover <--- Verifier
socket.recv(1)
length = socket.recv(1)
B = socket.recv(int(length.hex(), 16)) # Receive B = (kv + g^b) mod N
print(f"4. Verifier: B = {B}")

# 5: Compute key K
# x = H [s || H(id||':'||w)]
x = hashlib.sha1(salt + hashlib.sha1(id.encode('utf-8') + b':' + w.encode('utf-8')).digest()).digest()

# u = MSB32bit(H(B)): Most Significant 4 Bytes
extractU = hashlib.sha1(B).digest()[:4]
u = int.from_bytes(extractU, 'big', signed=False)

# S = (B - kg^x) ^ a + ux
intB = int(B.hex(),16)
intX = int(x.hex(), 16)
S = pow((intB - pow(g, intX, N)), (a + u * intX), N)

# key K = SHA_Interleave(S)
K = SHA_Interleave(S)
print("Session Establishment")
print(f"S = {S}")
print(f"K = {K}")

# 6: M1 = H[H(N) XOR H(g) || H(id) || s || A || B || K]
# Prover ---> Verifier
xorHash = bytes_to_long(hashlib.sha1(long_to_bytes(N)).digest()) ^ bytes_to_long(hashlib.sha1(long_to_bytes(g)).digest()) # H(N) XOR H(g)
hashID = hashlib.sha1(id.encode('utf-8')).digest() # H(id)
M1 = hashlib.sha1(long_to_bytes(xorHash) + hashID + salt + long_to_bytes(A) + B + K).digest() # H[H(N) XOR H(g) || H(id) || s || A || B || K]
typeID = 5
message = long_to_bytes(typeID) + long_to_bytes(len(M1)) + M1 # Send message in TLV format
socket.send(message) # Prover send M1 to Verifier
print(f"6. Prover: M1 = {M1}")

# 7: Receive and Verify M1
socket.recv(1)

# 8: Send M2 = H(A || M1 || K)
# Prover <--- Verifier
length = socket.recv(1)
M2 = socket.recv(int(length.hex(), 16))
print(f"8. Verifier: M2 = {M2}")

# 9: Verify M2
if M2 == hashlib.sha1(long_to_bytes(A) + M1 + K).digest():
    print("9. M2 Verified")
else:
    print("9. M2 not Verified")

# Encrypt and Send Request
key = K[:24] # 192bits of session key K used as AES key for AES_CTR mode
IV = secrets.token_bytes(16) # IV 128bits
ctr = Counter.new(128, initial_value=int.from_bytes(IV, byteorder='big')) # Initialise counter
cipher = AES.new(key, AES.MODE_CTR, counter=ctr) # Create AES_CTR cipher
magicword = 'abracadabra'
ciphertext = cipher.encrypt(magicword.encode()) # Encrypted echo request of magicword
typeID = 7
message = long_to_bytes(typeID) + long_to_bytes(len(IV + ciphertext)) + IV + ciphertext # Send message in TLV format
socket.send(message)
print(f"Prover: Encrypted K = {message}")

# Receive Reply from Verifier
socket.recv(1)
length = socket.recv(1)
gem = socket.recv(int(length.hex(), 16))

gemIV = gem[:16] # IV 128bits
ctr = Counter.new(128, initial_value=int.from_bytes(gemIV, byteorder='big')) # Initialise counter
cipher = AES.new(key, AES.MODE_CTR, counter=ctr) # Create AES_CTR cipher
print(f"Gem: {cipher.decrypt(gem[16:]).decode()}") # Get decrypted messaged without IV

# For wisdom is better than rubies; and all the things that may be desired are not to be compared to it.