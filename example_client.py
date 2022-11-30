import seccomp as sc

# Ciphertexts have 2^16 (65536) slots that can be filled with values
# for SIMD operation. This means 2^16 comparison can be done simultaneously
# If you do not need all the slots, you can put 0 in the unused slots.
featureValues = [0] * (2 ** 16)

# Fill 10 slots with arbitrary data
for i in range(10):
    featureValues[i] = 0.1 * i

sc.compare(featureValues, "ciphertexts/threshold.ctxt", "ciphertexts/results.ctxt", "keys/enc.key", "keys/mult.key")