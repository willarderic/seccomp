import seccomp as sc

# Generates the secret key, the multiplication key, and the encryption key, respectively
sc.keygen("keys/secret.key", "keys/mult.key", "keys/enc.key")

# Creates a ciphertext with 0.5 in every slot
sc.encryptValue(0.5, "keys/enc.key", "ciphertexts/threshold.ctxt")

# Can do decryption here, but it is in a different file for example-sake