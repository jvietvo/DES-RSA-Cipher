import socket                   # Import socket module
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

def append_space_padding(plaintext, blocksize):
    newp = pad(plaintext,blocksize) # Pad the plaintext by the blocksize passed in
    return newp

def encrypt(Plaintext_pad, key):
    desKeyE = DES3.new(key,DES3.MODE_ECB) # Create Triple DES key object based on Key passed in
    ciphertext = desKeyE.encrypt(Plaintext_pad) # Encrypt the Plaintext using the DES3 Key
    return ciphertext

def remove_space_padding(str, blocksize):
    new = unpad(str,blocksize) # Unpad the plaintext by the blocksize passed in
    return new

def decrypt(ciphertext, key):
    desKeyD = DES3.new(key,DES3.MODE_ECB) # Create Triple DES key object based on Key passed in
    plaintext = desKeyD.decrypt(ciphertext)# Decrypt the Plaintext using the DES3 Key
    return plaintext

s = socket.socket()             # Create a socket object
port = 60000                    # Reserve a port for your service.

s.connect(('127.0.0.1', port))
ida = b'INITIATOR A'
print("Sender Message 1: "+ida.decode(errors='ignore'))
s.send(ida) # Send Message
encrypted = s.recv(1024) # Recieve Message
encrypted = encrypted.split(b';') # Split encrypted text based on ; to get each value requested
Km = encrypted[0]
Emessage = encrypted[1]
print("Recieved Encrypted Text: "+Emessage.decode(errors='ignore'))
deccc = decrypt(Emessage,Km)

dec = remove_space_padding(deccc,8) # Unpad the recieved message
print("Decrypted Message 2: "+dec.decode(errors='ignore'))

x = dec.split(b',')
Ks = x[0]
idb = x[2]
nKs = append_space_padding(Ks,16) # Pad Key up to Triple DES key length
nidb = append_space_padding(idb,8) # Pad the message up to 8 bytes
print("Session Key: "+Ks.decode(errors='ignore'))
m3 = encrypt(nidb,nKs) # Encrypt Message 3 using the padded key and Message
s.send(m3)



s.close()