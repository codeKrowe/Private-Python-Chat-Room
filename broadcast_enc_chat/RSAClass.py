import sys
import chilkat
import base64

# define constant key size of 1024 bits
KEY_SIZE = 1024

class RSAClass:
  """ Class for encrypting strings with RSA"""

  def __init__(self):
    self.rsa = chilkat.CkRsa()
    self.unlock_component()
    self.publicKey = None
    self.privateKey = None

  def unlock_component(self):
    """ Method which unlocks rsa component """

    success = self.rsa.UnlockComponent("T12302015RSA_nn56BzHGIRMg")

    if (success != True):
        print("RSA component unlock failed")
        sys.exit()

  def generate_keys(self, key_size=KEY_SIZE):
    """ Generate a public and private key pair of a certain key size """

    success = self.rsa.GenerateKey(KEY_SIZE)

    if (success != True):
        print(self.rsa.lastErrorText())
        sys.exit()

    #  Keys are exported in XML format:
    self.publicKey = self.rsa.exportPublicKey()
    self.privateKey = self.rsa.exportPrivateKey()

    print type(self.publicKey)

    return self.publicKey, self.privateKey

  def encrypt_text(self, plainText, publicKey):
    """ Encrypt plainText with pubic key """

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
    cipherText = rsaEncryptor.encryptStringENC(plainText, usePrivateKey)
    # print(cipherText)

    return cipherText

  def decrypt_text(self, cipherText, privateKey):
    """ Decrypt cipherText with private key """

    #  Now decrypt:
    rsaDecryptor = chilkat.CkRsa()

    rsaDecryptor.put_EncodingMode("hex")
    rsaDecryptor.ImportPrivateKey(privateKey)

    usePrivateKey = True
    plainText = rsaDecryptor.decryptStringENC(cipherText, usePrivateKey)

    # print(plainText)

    return plainText

    
