# Secure comparison with HEAAN
Implemented the secure comparison idea from the paper [Efficient Homomorphic Comparison Methods with Optimal Complexity](https://eprint.iacr.org/2019/1234.pdf). Also included under `papers/`.

HEAAN allows single instruction multiple data (SIMD) operations, so we can put 2^16 values in one cipher, which allows us to perform 2^16 comparisons simultaneously. Examples of how the API works are in the `pdte.py` files. The server generates keys and a ciphertext, and saves them all to files. The files then can be send to the client (not included in the code) and the comparison can be performed. Finally, we can decrypt the values back on the server and view the results of the comparison.

To use the library, include `import seccomp` in the python file, where `seccomp.cpython-310-x86_64-linux-gnu.so` is present and in the same directory of the python file. You can then call the functions provided by `<retval => seccomp.<function>(<parameters>)`.

**NOTE**: The binary included with the repository is for python 3.10 only currently. If using another version of python, you will have to recompile with a different version of python specified in setup.py

**NOTE**: `seccomp.cpython-310-x86_64-linux-gnu.so` relies on `libntl.so.44` to be imported. To solve the error of `libntl.so.44` not being found, add /path/to/seccomp/ntl/lib` to the environment variable `LD_LIBRARY_PATH`.

List of functions:
- `void compare(list featureValues, string inCipherPath, string outCipherPath, string encKeyPath, string multKeyPath)`
    - given a list of numbers between [0,1], and a ciphertext of encrypted values `inCipherPath`, output a file with the result of the comparison `outCipherPath`
- `void keygen(string secretKeyPath, string multKeyPath, string encKeyPath)`
    - Generates and saves the secret, multiplication, and encryption keys to files
- `void encryptValue(double value, string encKeyPath, string ciphertextPath)`
    - Encrypts a single value into all the slots of the ciphertext and saves it to `ciphertextPath`
- `void encryptMany(list values, string encKeyPath, string ciphertextPath)`
    - Encrypts a list of values, where each value is one slot in the ciphertext (there are 2^16 slots).
    - For encrypting less that 2^16 numbers, leave the unused values as 0.
- `list decrypt(string cipherPath, string secretKeyPath)`
    - Decrypts the given ciphertext file with the secret key and returns the list of decrypted values
- `void pdte(list featureValues, string treeCipherPath, string outCipherPath, string encKeyPath, string multKeyPath, string rotKeyPath)`
    - Performs a private decision tree evaluation on a list of features. The `treeCipherPath` is the encrypted tree to evaluate the data on.
    - Requires and encryption key, multiplication, and rotation keys, which can be generated with `keygen()`
    - Outputs the evaluation results in `outCipherPath` which need to be multiplied to the labels to get the correct result.