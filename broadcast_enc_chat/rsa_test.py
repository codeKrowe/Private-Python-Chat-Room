from RSAClass import RSAClass

def main():

  # Create our rsa encryption class
  rsa = RSAClass()

  # some plaintext we want to encrypt
  plainText = "Gonna encrypt this string!"

  # Generate key pair
  public_key, private_key = rsa.generate_keys()

  # Encrypt our string
  cipherText = rsa.encrypt_text(plainText, public_key)

  # decrypt our string
  plainText = rsa.decrypt_text(cipherText, private_key)

  print "using public_key for encryption"
  print cipherText
  print plainText

  # Encrypt with private to sign message.
  cipherText = rsa.encrypt_with_private(plainText, private_key)

  # decrypt our message with corresponding public key
  plainText = rsa.decrypt_with_public(cipherText, public_key)

  print "using private_key for encryption"
  print cipherText
  print plainText

if __name__ == "__main__":
  main()
