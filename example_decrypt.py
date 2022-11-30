import seccomp as sc
# Needs comparison result saved to `ciphertexts/result.ctxt` from example_client.py 
# for decryption to work
decryptedValues = sc.decrypt("ciphertexts/results.ctxt", "keys/secret.key")
# Print first 10 values
for i in range(10):
    print(decryptedValues[i])