from RSAClass import RSAClass

def main():

  # Create our rsa encryption class
  rsa = RSAClass()
  
  # some plaintext we want to encrypt
  plainText = "Gonna encrypt the shit out of this string!"

  # Generate key pair
  public_key, private_key = rsa.generate_keys()

  # Encrpyt our string
  cipherText = rsa.encrypt_text(plainText, public_key)

  # decrypt our string
  plainText = rsa.decrypt_text(cipherText, private_key)

if __name__ == "__main__":
  main()
