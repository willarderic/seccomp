import seccomp

tree = [
                0.5,
            0.25,    0.75,
        0.125, 0.375, 0.625, 0.875,
    0.1, 0.2, 0.3, 0.4, 0.6, 0.7, 0.8, 0.9
]

data = [0.05, 0.11, 0.14, 0.24, 0.27, 0.35, 0.39, 0.45, 0.55, 0.61, 0.67, 0.73, 0.76, 0.84, 0.89, 0.95]

labels = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160]

def extractResults(labels, decryptedValues):
    tmp_results = []
    for i in range(len(decryptedValues) // 4):
        tmp = decryptedValues[i * 4 + 3] * labels[((i * 4) % 64) + 3]
        tmp_results.append(tmp)
    results = []
    for i in range(len(tmp_results) // 16):
        sum = 0
        for j in range(16):
            sum = sum + tmp_results[i * 16 + j]
        results.append(sum)
    
    for i in range(len(results)):
        if i % 16 == 1 or i % 16 == 2 or i % 16 == 4 or i % 16 == 7 or i % 16 == 8 or i % 16 == 11 or i % 16 == 13 or i % 16 == 14:
            results[i] = results[i] * -1

    return results

def encodeTree(tree):
    thresholds = [0] * (2 ** 16)
    for i in range(2**16 // 64):
        thresholds[i * 64 +  0] = tree[0]
        thresholds[i * 64 +  1] = tree[1]
        thresholds[i * 64 +  2] = tree[3]
        thresholds[i * 64 +  3] = tree[7]
        thresholds[i * 64 +  4] = tree[0]
        thresholds[i * 64 +  5] = tree[1]
        thresholds[i * 64 +  6] = tree[3]
        thresholds[i * 64 +  7] = tree[7]
        thresholds[i * 64 +  8] = tree[0]
        thresholds[i * 64 +  9] = tree[1]
        thresholds[i * 64 + 10] = tree[3]
        thresholds[i * 64 + 11] = tree[8]
        thresholds[i * 64 + 12] = tree[0]
        thresholds[i * 64 + 13] = tree[1]
        thresholds[i * 64 + 14] = tree[3]
        thresholds[i * 64 + 15] = tree[8]
        thresholds[i * 64 + 16] = tree[0]
        thresholds[i * 64 + 17] = tree[1]
        thresholds[i * 64 + 18] = tree[4]
        thresholds[i * 64 + 19] = tree[9]
        thresholds[i * 64 + 20] = tree[0]
        thresholds[i * 64 + 21] = tree[1]
        thresholds[i * 64 + 22] = tree[4]
        thresholds[i * 64 + 23] = tree[9]
        thresholds[i * 64 + 24] = tree[0]
        thresholds[i * 64 + 25] = tree[1]
        thresholds[i * 64 + 26] = tree[4]
        thresholds[i * 64 + 27] = tree[10]
        thresholds[i * 64 + 28] = tree[0]
        thresholds[i * 64 + 29] = tree[1]
        thresholds[i * 64 + 30] = tree[4]
        thresholds[i * 64 + 31] = tree[10]
        thresholds[i * 64 + 32] = tree[0]
        thresholds[i * 64 + 33] = tree[2]
        thresholds[i * 64 + 34] = tree[5]
        thresholds[i * 64 + 35] = tree[11]
        thresholds[i * 64 + 36] = tree[0]
        thresholds[i * 64 + 37] = tree[2]
        thresholds[i * 64 + 38] = tree[5]
        thresholds[i * 64 + 39] = tree[11]
        thresholds[i * 64 + 40] = tree[0]
        thresholds[i * 64 + 41] = tree[2]
        thresholds[i * 64 + 42] = tree[5]
        thresholds[i * 64 + 43] = tree[12]
        thresholds[i * 64 + 44] = tree[0]
        thresholds[i * 64 + 45] = tree[2]
        thresholds[i * 64 + 46] = tree[5]
        thresholds[i * 64 + 47] = tree[12]
        thresholds[i * 64 + 48] = tree[0]
        thresholds[i * 64 + 49] = tree[2]
        thresholds[i * 64 + 50] = tree[6]
        thresholds[i * 64 + 51] = tree[13]
        thresholds[i * 64 + 52] = tree[0]
        thresholds[i * 64 + 53] = tree[2]
        thresholds[i * 64 + 54] = tree[6]
        thresholds[i * 64 + 55] = tree[13]
        thresholds[i * 64 + 56] = tree[0]
        thresholds[i * 64 + 57] = tree[2]
        thresholds[i * 64 + 58] = tree[6]
        thresholds[i * 64 + 59] = tree[14]
        thresholds[i * 64 + 60] = tree[0]
        thresholds[i * 64 + 61] = tree[2]
        thresholds[i * 64 + 62] = tree[6]
        thresholds[i * 64 + 63] = tree[14]

    return thresholds

def encodeFeatures(data):
    if len(data) > 1024:
        print("Max number of features is 1024.")
        exit(1)

    features = [0] * (2 ** 16)
    for i in range(len(data)):
        for j in range(64):
            features[i * 64 + j] = data[i]
    
    return features

def encodeLabels(labels):
    if len(labels) != 16:
        print("Need exactly 16 labels (leaf values) for a depth 5 tree.")
        exit(1)
    
    leafValues = [0] * (64)
    for i in range(16):
        leafValues[i * 4 + 3] = labels[i]

    return leafValues

# This code would be executed by the party with the model (tree)
seccomp.keygen("keys/secret.key", "keys/mult.key", "keys/enc.key", "keys/rot/")
seccomp.encryptMany(encodeTree(tree), "keys/enc.key", "ciphertexts/tree.ctxt")

# This code would be executed on the party with the data (features)
seccomp.pdte(encodeFeatures(data), "ciphertexts/tree.ctxt", "ciphertexts/pdte.ctxt", "keys/enc.key", "keys/mult.key", "keys/rot/")

# This code would be executed again by the party with the model (tree)
decryptedValues = seccomp.decrypt("ciphertexts/pdte.ctxt", "keys/secret.key")
extractedResults = extractResults(encodeLabels(labels), decryptedValues)

print("----- Results of the evaluation of the 16 features -----")
for i in range(16):
    print(f"pdte({data[i]}) = {extractedResults[i]}")
print("------------------- End of Results ---------------------")

