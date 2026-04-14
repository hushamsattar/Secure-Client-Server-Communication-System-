# Server:
import rsa
import socket
import hashlib
from cryptography.fernet import Fernet

host = '192.168.1.10'
port = 65432

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((host, port))
s.listen()

print(f'Listening for Client...')

# Accept connection from a client
client_socket, address = s.accept()

print(f'Connection established!')

"""
# Generate Alice's (encryption/decryption) private and public key pair
public_key_ED_A, private_key_ED_A = rsa.newkeys(1024)

# Generate Alice's (Signature) private and public key pair
public_key_S_A, private_key_S_A = rsa.newkeys(1024)

# Write Alice's (encryption/decryption) public key and save it on a PEM file
with open("public_ED_A.pem", "wb") as f:
    f.write(public_key_ED_A.save_pkcs1("PEM"))

# Write Alice's (encryption/decryption) private key and save it on a PEM file    
with open("private_ED_A.pem", "wb") as f:
    f.write(private_key_ED_A.save_pkcs1("PEM"))

# Write Alice's (Signature) public key and save it on a PEM file
with open("public_S_A.pem", "wb") as f:
    f.write(public_key_S_A.save_pkcs1("PEM"))

# Write Alice's (Signature) private key and save it on a PEM file    
with open("private_S_A.pem", "wb") as f:
    f.write(private_key_S_A.save_pkcs1("PEM"))

# Generating the symmetric key
key = Fernet.generate_key()
print(key)

# Write the symmetric key and save it as a .key file
f = open("SymmetricKey.key", "wb")
f.write(key)
file.close()
"""

# Read the symmetric key
f = open("SymmetricKey.key", "rb")
key = f.read()
f.close()
# print(key)

# Reading Bob's (Encryption / Decryption) public key
with open("public_ED_B.pem", "rb") as f:
    public_key_ED_B = rsa.PublicKey.load_pkcs1(f.read())

# Reading Bob's (Signature) public key
with open("public_S_B.pem", "rb") as f:
    public_key_S_B = rsa.PublicKey.load_pkcs1(f.read())

# Reading Alice's (Encryption / Decryption) private key
with open("private_ED_A.pem", "rb") as f:
    private_key_ED_A = rsa.PrivateKey.load_pkcs1(f.read())

# Reading Alice's (Encryption / Decryption) public key
with open("public_ED_A.pem", "rb") as f:
    public_key_ED_A = rsa.PublicKey.load_pkcs1(f.read())

# Reading Alice's (Signature) private key
with open("private_S_A.pem", "rb") as f:
    private_key_S_A = rsa.PrivateKey.load_pkcs1(f.read())

# Reading Alice's (Signature) public key
with open("public_S_A.pem", "rb") as f:
    public_key_S_A = rsa.PublicKey.load_pkcs1(f.read())

# Encrypting Alice's generated symmetric key with Bob's public key
symmetric_key = rsa.encrypt(key, public_key_ED_B)

# Sending encrypted key
client_socket.sendall(symmetric_key)
print(f'Sending encrypted Symmetric Key...')

# The secret message
messageA = "This is Alice's secret message!"

# assign key value to variable
cipher = Fernet(key)

# Encrypt Alice's secret message with Symmetric Key
encrypted_messageA = cipher.encrypt(messageA.encode())

# Sending encrypted messageA
client_socket.sendall(encrypted_messageA)
print(f'Sending Encrypted messageA...')

# Recieving encrypted messageB
encrypted_messageB = client_socket.recv(1024)
print(f'Received encrypted message!')

# Decrypting messageB with Symmetric Key
decrypt_messageB = cipher.decrypt(encrypted_messageB)

# hashing Bob's decrypted message
C_H_B = hashlib.new('SHA256')
C_H_B = hashlib.sha256(decrypt_messageB)
calculated_hash_B = C_H_B.hexdigest()
# print(calculated_hash_B)

# Message Hash
message_Hash_B = calculated_hash_B.encode()

# writing Bob's message to Desktop
with open("Bob_Message.txt", "wb") as f:
    f.write(decrypt_messageB)

"""
# hashing
C_H_A = hashlib.new('SHA256')
C_H_A = hashlib.sha256(messageA.encode())
calculated_hash_A = C_H_A.hexdigest()
print(calculated_hash_A)

# Message Hash
message_Hash_A = calculated_hash_A.encode()

signature_Alice = rsa.sign(message_Hash_A, private_key_S_A, "SHA-256")
with open("Signature_Alice", "wb") as f:
    f.write(signature_Alice) 
"""
with open("Signature_Alice", "rb") as f:
    signature_Alice = f.read()

# Sending Alice's signature
client_socket.sendall(signature_Alice)
print(f"Sending Alice's Signature...")

# print("Alice's Signature: ", signature_Alice)

# Receieving Bob's signature
signature_Bob = client_socket.recv(1024)
print(f"Bob's signature recieved")

# print("Bob's signature: ", signature_Bob)

# Verify Bob's signature
Ver_B_Sig = rsa.verify(message_Hash_B, signature_Bob, public_key_S_B)
print("Verified: ", Ver_B_Sig)

# Close the socket
client_socket.close()
s.close()
