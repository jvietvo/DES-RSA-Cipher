import sys

# Encryption
def vigenere_encrypt(plain_text, key):    
    # Check if plaintext and key length is long enough
    if len(key) < 1:
        raise ValueError("Key too small")
    if len(plain_text) < 1:
        raise ValueError("Plaintext too small")

    # Plaintext and key to uppercase
    key = key.upper()
    plain_text = plain_text.upper()

    # Plaintext and key to lists
    key_list = [char for char in key]
    plain_list = [char for char in plain_text]

    # Check if key is larger than plaintext
    if len(key) > len(plain_text):
        raise ValueError("Key should not be larger than plaintext")

    # Match lengths of plaintext and key
    if len(key) < len(plain_text):
        for x in range(len(plain_text)):
            key_list.append(key_list[x])
            if len(plain_list) == len(key_list):
                break
    
    # Converting to ciphertext
    cipher_list = []
    for i in range(len(plain_text)):
        letters = ((ord(plain_list[i]) + ord(key_list[i])) % 26) + 65
        if ord(plain_list[i]) == 32:
            letters = 32
        cipher_list.append(chr(letters))
    cipher_text = "".join(cipher_list)

    # test print 
    print("Plaintext: " + plain_text)
    print("Key: " + key)
    print("Ciphertext: " + cipher_text)
    return cipher_text

# Decryption
def vigenere_decrypt(cipher_text, key):
    # Check if Ciphertext and key length is long enough
    if len(key) < 1:
        raise ValueError("Key too small")
    if len(cipher_text) < 1:
        raise ValueError("Ciphertext too small")

    # Ciphertext and key to uppercase
    key = key.upper()
    cipher_text = cipher_text.upper()

    # Ciphertext and key to lists
    key_list = [char for char in key]
    cipher_list = [char for char in cipher_text]

    # Check if key is larger than ciphertext
    if len(key) > len(cipher_text):
        raise ValueError("Key should not be larger than plaintext")

    # Match lengths of ciphertext and key
    if len(key) < len(cipher_text):
        for x in range(len(cipher_text)):
            key_list.append(key_list[x])
            if len(cipher_list) == len(key_list):
                break

    # Converting to plaintext
        plain_list = []
        for i in range(len(cipher_text)):
            letters = ((ord(cipher_list[i]) - ord(key_list[i])) % 26) + 65
            if ord(cipher_list[i]) == 32:
                letters = 32
            plain_list.append(chr(letters))
        plain_text = "".join(plain_list)

        # test print 
        print("Ciphertext: " + cipher_text)
        print("Key: " + "".join(key_list))
        print("Plaintext: " + plain_text)
        return plain_text

# Main function
if __name__ == "__main__":
        plaintext = input("Please Enter TO BE OR NOT TO BE THAT IS THE QUESTION \n")
        testkey = input("Please Enter the Key RELATIONS \n")
        encrypted = vigenere_encrypt(plaintext,testkey)
        decrypted = vigenere_decrypt(encrypted,testkey)
        print(decrypted)
    
	
