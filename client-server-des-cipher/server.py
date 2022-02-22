import socket                   # Import socket module
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

port = 60000                    # Reserve a port for your service.
s = socket.socket()             # Create a socket object
host = socket.gethostname()     # Get local machine name
print(host)
s.bind(('127.0.0.1', port))            # Bind to the port
s.listen(5)                     # Now wait for client connection.
BLOCK_SIZE = 8


def append_space_padding(plaintext, blocksize):
    newp = pad(plaintext,blocksize)
    return newp

def encrypt(Plaintext_pad, key):
    desKeyE = DES3.new(key,DES3.MODE_ECB)
    ciphertext = desKeyE.encrypt(append_space_padding(Plaintext_pad,BLOCK_SIZE))
    return ciphertext

def remove_space_padding(str):
    new = unpad(str,BLOCK_SIZE)
    return new

def decrypt(ciphertext, key):
    desKeyD = DES3.new(key,DES3.MODE_ECB)
    plaintext = desKeyD.decrypt(ciphertext)
    return plaintext
    
    

while True:
    conn, addr = s.accept()     # Establish connection with client.
    # Initialize Identity of Server, Master Key and Session Key
    idb = b'RESPONDER B'
    Km = b'NETWORK SECURITY'
    Ks = b'RYERSON'
    
    ida = conn.recv(1024) # Recieve Message 1
    print("Recieved Message 1: "+ida.decode(errors='ignore'))
    # Combine Session Key, Identity A and Identity B into Message 2
    mess = Ks + b',' + ida + b','+ idb
    print("Plaintext Message 2: "+mess.decode(errors='ignore'))
    encrypted= encrypt(mess,Km) # Encrypt Message 2 with Master Key
    print("Encrypted Message 2: "+encrypted.decode(errors='ignore'))
    sender = Km+b';'+encrypted # Send Master Key & Encrypted Message
    conn.send(sender)
    
    
    nKs = append_space_padding(Ks,16) # Pad the Session Key to be Triple DES length
    m3 = conn.recv(1024)
    print("Recieved Encrypted Message 3: "+m3.decode(errors='ignore'))
    message3 = decrypt(m3,nKs) # Decrypt the Message using the Padded Session Key
    nM3 = remove_space_padding(message3) # Remove the Message Padding
    print("Decrypted Message 3: "+nM3.decode(errors='ignore'))
    
    conn.close()
    break


