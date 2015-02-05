import sys
import chilkat

KEY_SIZE = 1024

def unlock_component(rsa): 
    success = rsa.UnlockComponent("T12302015RSA_nn56BzHGIRMg")
    
    if (success != True):
        print("RSA component unlock failed")
        sys.exit()

def generate_keys(rsa, key_size=KEY_SIZE):
    success = rsa.GenerateKey(KEY_SIZE)

    if (success != True):
        print(rsa.lastErrorText())
        sys.exit()

    #  Keys are exported in XML format:
    publicKey = rsa.exportPublicKey()
    privateKey = rsa.exportPrivateKey()

    return publicKey, privateKey

def encrypt_text(plainText, publicKey):
    #  Start with a new RSA object to demonstrate that all we
    #  need are the keys previously exported:
    rsaEncryptor = chilkat.CkRsa()

    #  Encrypted output is always binary.  In this case, we want
    #  to encode the encrypted bytes in a printable string.
    #  Our choices are "hex", "base64", "url", "quoted-printable".
    rsaEncryptor.put_EncodingMode("hex")

    #  We'll encrypt with the public key and decrypt with the private
    #  key.  It's also possible to do the reverse.
    rsaEncryptor.ImportPublicKey(publicKey)

    usePrivateKey = False
    cipherText = rsaEncryptor.encryptStringENC(plainText,usePrivateKey)
    print(cipherText)

    return cipherText

def decrypt_text(cipherText, privateKey):
    #  Now decrypt:
    rsaDecryptor = chilkat.CkRsa()

    rsaDecryptor.put_EncodingMode("hex")
    rsaDecryptor.ImportPrivateKey(privateKey)

    usePrivateKey = True
    plainText = rsaDecryptor.decryptStringENC(cipherText,usePrivateKey)

    print(plainText)

    return plainText

def setup():
    rsa = chilkat.CkRsa()
    unlock_component(rsa)

    return rsa

def main():
    rsa  = setup()

    plainText = "Encrypting and decrypting should be easy!"
    public_key, private_key = generate_keys(rsa)

    cipherText = encrypt_text(plainText, public_key)
    plainText = decrypt_text(cipherText, private_key)

if __name__ == "__main__":
    main()      