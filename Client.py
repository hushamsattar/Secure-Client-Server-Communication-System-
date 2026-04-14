# Client:
import rsa
import socket
import hashlib
from cryptography.fernet import Fernet

host = '192.168.1.10'
port = 65432

s = socket.socket()
s.connect((host, port))

print(f'connected with server!')

"""
# Generate Bob's (Encryption / Decryption) public and private key pair
public_key_ED_B, private_key_ED_B = rsa.newkeys(1024)

# Write Bob's (Encryption / Decryption) public key and save it as a PEM file
with open("public_ED_B.pem", "wb") as f:
    f.write(public_key_ED_B.save_pkcs1("PEM"))

# Write Bob's (Encryption / Decryption) private key and save it as a PEM file    
with open("private_ED_B.pem", "wb") as f:
    f.write(private_key_E_B.save_pkcs1("PEM"))
    
# Generate Bob's (Signature) public and private key pair
public_key_S_B, private_key_S_B = rsa.newkeys(1024)

# Write Bob's (Signature) public key and save it as a PEM file
with open("public_S_B.pem", "wb") as f:
    f.write(public_key_S_B.save_pkcs1("PEM"))

# Write Bob's (Signature) private key and save it as a PEM file    
with open("private_S_B.pem", "wb") as f:
    f.write(private_key_S_B.save_pkcs1("PEM"))
"""

# Reading Alice's (Encryption / Decryption) public key
with open("public_ED_A.pem", "rb") as f:
    public_key_ED_A = rsa.PublicKey.load_pkcs1(f.read())

# Reading Alice's (Signature) public key
with open("public_S_A.pem", "rb") as f:
    public_key_S_A = rsa.PublicKey.load_pkcs1(f.read())

# Reading Bob's (Encryption / Decryption) private key
with open("private_ED_B.pem", "rb") as f:
    private_key_ED_B = rsa.PrivateKey.load_pkcs1(f.read())

# Reading Bob's (Signature) private key
with open("private_S_B.pem", "rb") as f:
    private_key_S_B = rsa.PrivateKey.load_pkcs1(f.read())

# Receive encrypted symmetric key
symmetric_key = s.recv(1024)
print(f'Received Symmetric Key!')

# Decrypt Alice's sent symmetric key with Bob's private key
SymmKey = rsa.decrypt(symmetric_key, private_key_ED_B)
# print(SymmKey)

# Write symmetric key to Desktop
# f = open("SymmetricKey.key", "wb")
# f.write(SymmKey)
# f.close()

# The secret message
messageB = "This is Bob's secret message!"

# Receive encryption from Alice
encrypted_messageA = s.recv(1024)
print(f'Received encrypted message!')

# assign key value to variable
cipher = Fernet(SymmKey)

# Decrypting Alice's message with symmetric key
decrypted_messageA = cipher.decrypt(encrypted_messageA)

# Encrypt messageB with symmetric key
encrypted_messageB = cipher.encrypt(messageB.encode())

# Sending encrypted messageB
s.sendall(encrypted_messageB)
print(f'Sending encrypted messageB...')

# Hashing Alice's decrypted message
C_H_A = hashlib.new('SHA256')
C_H_A = hashlib.sha256(decrypted_messageA)
Calc_Hash_A = C_H_A.hexdigest()
# print(Calc_Hash_A)

# Message hash
Message_Hash_A = Calc_Hash_A.encode()


# writing Alice's decrypted message to Desktop
with open("Alice_Message.txt", "wb") as f:
    f.write(decrypted_messageA)

"""
# Hashing Bob's message
C_H_B = hashlib.new('SHA256')
C_H_B = hashlib.sha256(messageB.encode())
Calc_Hash_B = C_H_B.hexdigest()
print(Calc_Hash_B)

# Message Hash
Message_Hash_B = Calc_Hash_B.encode()

signature_Bob = rsa.sign(Message_Hash_B , private_key_S_B, "SHA-256")
with open("Signature_Bob", "wb") as f:
    f.write(signature_Bob)
"""
# Reading Bob's signature
with open("Signature_Bob", "rb") as f:
    signature_Bob = f.read()

# Sending Bob's signature
s.sendall(signature_Bob)
print(f"Sending Bob's Signature...")

# print("Bob's Signature: ", signature_Bob)

# receive signatureA
signature_Alice = s.recv(1024)
print(f"Alice's signature Received!")

# print("Alice's Signature: ", signature_Alice)

# verify Alice's signature
Ver_A_Sig = rsa.verify(Message_Hash_A, signature_Alice, public_key_S_A)
print("Verified: ", Ver_A_Sig)

# Close the socket
s.close()
