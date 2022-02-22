import Crypto
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import DES


BLOCK_SIZE = 32

def EncryptDes(plaintext,key):
    desKeyE = DES.new(key,DES.MODE_ECB)
    ciphertext = desKeyE.encrypt(pad(plaintext,BLOCK_SIZE))
    print(ciphertext.decode(errors='ignore'))
    return ciphertext
    
    

def DecryptDes(ciphertext,key):
    desKeyD = DES.new(key,DES.MODE_ECB)
    plaintext = desKeyD.decrypt(ciphertext)
    print(unpad(plaintext,BLOCK_SIZE).decode("utf-8").strip())
    return plaintext

if __name__ == "__main__":
   # plain = input("Enter No Body Can See Me\n")
    plain = b'No Body Can See Me'
    desKey = b'urmomgay'
    print(plain.decode("utf-8").strip())
    desCipher = EncryptDes(plain,desKey)
    desPlain = DecryptDes(desCipher,desKey)
