#include <cmath>
#include <iostream>
#include <random>
#include <climits>

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <NTL/ZZ.h>

#include "HEAAN.h"

using namespace NTL;
using namespace std;
using namespace heaan;

namespace py = pybind11;

namespace constants {
    // Parameters for f_4(x) //
    const long NUM_ITERS = 5;
    // Parameters for HEAAN //
    const long CIRCUIT_DEPTH = 6;
    const long LOGP = 40; ///< scaling factor log ∆
    const long LOGQ = (LOGP * CIRCUIT_DEPTH) * NUM_ITERS + 2 * LOGP + 10; ///< Ciphertext modulus
    const long LOGN = 16; ///< number of slots (2^16 = 65536)
    const long NN = 1 << LOGN;
    const long SLOTS = NN;
    const long NUM_THREADS = 8;
}

// Secret key coefficients are in {-1, 0, 1}, so we can encode them as longs
void writeSecretKey(SecretKey& secretKey, std::string filename) {
    fstream fout;
	fout.open(filename, ios::binary | ios::out);
	for (int i = 0; i < N; i++) {
        long val = NTL::to_long(secretKey.sx[i]);
        fout.write((char*)&val, sizeof(long));
    }
	fout.close();
}

void readSecretKey(SecretKey& secretKey, std::string filename) {
    fstream fin;
	fin.open(filename, ios::binary | ios::in);
	for (int i = 0; i < N; i++) {
        long val;
        fin.read((char*)&val, sizeof(long));
        secretKey.sx[i] = NTL::ZZ(val);
    }
	fin.close();
}

// Future suggestions:
// Can use Paterson-Stockmeyer method to achieve optimal computation complexity
// On the Number of Nonscalar Multiplications Necessary to Evaluate Polynomials
// https://epubs.siam.org/doi/epdf/10.1137/0202007
void f4(Scheme& scheme, Ciphertext& fx, Ciphertext& x, long logp) {
    // Use SchemeAlgo::power to do non-powers of 2 for evaluating this function
    //                        x^1        x^3      x^5       x^7      x^9
    vector<double> coeffs = { 2.4609375, 3.28125, 2.953125, 1.40625, 0.2734375 };
    Ciphertext x2, x3, x4, x5, x6, x7, x8, x9, term1, term3, term5, term7, term9;
    // (315/128) * x
    scheme.multByConst(term1, x, coeffs[0], logp);
    // x^2
    scheme.square(x2, x);
    scheme.reScaleByAndEqual(x2, logp);
    // (420/128) * x^3
    scheme.mult(x3, x2, x);
    scheme.reScaleByAndEqual(x3, logp);
    scheme.multByConst(term3, x3, coeffs[1], logp);
    // (378/128) * x^5
    scheme.mult(x5, x3, x2);
    scheme.reScaleByAndEqual(x5, logp);
    scheme.multByConst(term5, x5, coeffs[2], logp);
    scheme.reScaleByAndEqual(term5, logp);
    // (180/128) * x^7
    scheme.mult(x7, x5, x2);
    scheme.reScaleByAndEqual(x7, logp);
    scheme.multByConst(term7, x7, coeffs[3], logp);
    scheme.reScaleByAndEqual(term7, logp);
    // (35/128) * x^9
    scheme.mult(x9, x7, x2);
    scheme.reScaleByAndEqual(x9, logp);
    scheme.multByConst(term9, x9, coeffs[4], logp);
    scheme.reScaleByAndEqual(term9, logp);
    
    // FOR ADDITION, THE logq's MUST MATCH TO WORK
    // REDUCE LEVELS TO LOWEST OF THE TERMS AND THEN ATTEMPT TO ADD THINGS TOGETHERS
    scheme.reScaleByAndEqual(term1, logp);
    for (int i = 0; i < 5; i++) {
        scheme.modDownByAndEqual(term1, logp);
    }

    for (int i = 0; i < 3; i++) {
        scheme.modDownByAndEqual(term3, logp);
    }

    for (int i = 0; i < 2; i++) {
        scheme.modDownByAndEqual(term5, logp);
    }

    for (int i = 0; i < 1; i++) {
        scheme.modDownByAndEqual(term7, logp);
    }
    // fx = term9 - term7 + term5 - term3 + term1
    // fx = (35/128) * x^9 - (180/128) * x^7 + (378/128) * x^5 - (420/128) * x^3 + (315/128) * x
    scheme.reScaleByAndEqual(term3, logp);
    scheme.negateAndEqual(term3);
    scheme.add(fx, term1, term3);
    scheme.addAndEqual(fx, term5);
    scheme.negateAndEqual(term7);
    scheme.addAndEqual(fx, term7);
    scheme.addAndEqual(fx, term9);
}

void keygen(std::string secretKeyPath, std::string multKeyPath, std::string encKeyPath) {
    // Seed random number generator
    std::uniform_int_distribution<unsigned int> dist(0, UINT_MAX);
    std::random_device urandom("/dev/urandom");
    srand(dist(urandom));
    SetNumThreads(constants::NUM_THREADS);

    // Generate keys
    Ring ring;
    SecretKey secretKey(ring);
    Scheme scheme(secretKey, ring);

    // Save all keys to files
    writeSecretKey(secretKey, secretKeyPath);
    SerializationUtils::writeKey(scheme.keyMap.at(MULTIPLICATION), multKeyPath);
    SerializationUtils::writeKey(scheme.keyMap.at(ENCRYPTION), encKeyPath);
}

void encryptValue(double value, std::string encKeyPath, std::string ciphertextPath) {
    // Seed random number generator
    std::uniform_int_distribution<unsigned int> dist(0, UINT_MAX);
    std::random_device urandom("/dev/urandom");
    srand(dist(urandom));
    SetNumThreads(constants::NUM_THREADS);

    // Read in encryption key
    Ring ring;
    Key* encKey = SerializationUtils::readKey(encKeyPath);
    Scheme scheme(ring, encKey, nullptr);

    // Set all slots to value
    double* data = new double[constants::SLOTS];
    for (int i = 0; i < constants::SLOTS; i++) {
        data[i] = value;
    }

    // Perform encryption
    Ciphertext cipher;
    scheme.encrypt(cipher, data, constants::NN, constants::LOGP, constants::LOGQ);
    SerializationUtils::writeCiphertext(cipher, ciphertextPath);
    delete[] data;
}

std::vector<double> decrypt(std::string cipherPath, std::string secretKeyPath) {
    // Read in secret key
    Ring ring;
    SecretKey secretKey(ring);
    Scheme scheme(ring, nullptr, nullptr);
    readSecretKey(secretKey, secretKeyPath);
    // Read in ciphertext
    Ciphertext* cipher = SerializationUtils::readCiphertext(cipherPath);
    // HEAAN represents values as complex numbers
    // Decrypt and extract the real number parts
    std::vector<double> decryptedValuesReal;
    decryptedValuesReal.reserve(constants::SLOTS);
    complex<double>* decryptedValues = scheme.decrypt(secretKey, *cipher);
    for (int i = 0; i < constants::SLOTS; i++) {
        decryptedValuesReal.push_back(decryptedValues[i].real());
    }
    return decryptedValuesReal;
}

/* 
*  Efficient Homomorphic Comparison Methods with Optimal Complexity
*          https://eprint.iacr.org/2019/1234.pdf
*/
void comparison(std::vector<double> featureValues, std::string inCipherPath, std::string outCipherPath, std::string encKeyPath, std::string multKeyPath) {
    std::uniform_int_distribution<unsigned int> dist(0, UINT_MAX);
    std::random_device urandom("/dev/urandom");
    srand(dist(urandom));
    SetNumThreads(constants::NUM_THREADS);
    // Need both encryption key and multiplication key
    Ring ring;
    Key* encKey = SerializationUtils::readKey(encKeyPath);
    Key* multKey = SerializationUtils::readKey(multKeyPath);
    Scheme scheme(ring, encKey, multKey);
    
    // Cannot declare default ciphertext and then try to assign like:
    // Ciphertext x1;
    // x1 = SerializationUtils::readCiphertext(ciphertextPath);
    // ^^^^^ BAD!!!! ^^^^^^
    // Have to do this in one line or it will seg fault
    Ciphertext* inCtxt = SerializationUtils::readCiphertext(inCipherPath);
    Ciphertext x, f4x;
    // x contains the threshold value (a)
    x.copy(*inCtxt);
    // f4x temporarily stores the features values (b)
    scheme.encrypt(f4x, featureValues.data(), constants::NN, constants::LOGP, constants::LOGQ);
    
    // x = a - b
    scheme.subAndEqual(x, f4x);
    // x = f_4(x), d (NUM_ITERS) times
    for (int i = 0; i < constants::NUM_ITERS; ++i) {
        f4(scheme, f4x, x, constants::LOGP);
        x.copy(f4x);
        f4x.free();
    }
    // return (x + 1) / 2
    scheme.addConstAndEqual(x, 1.0, constants::LOGP);
    scheme.multByConstAndEqual(x, 0.5, constants::LOGP);
    scheme.reScaleByAndEqual(x, constants::LOGP);
    // Write result to file
    SerializationUtils::writeCiphertext(x, outCipherPath);
}

// Module name needs to be same name as file
PYBIND11_MODULE(seccomp, m) {
    m.doc() = "pybind11 example plugin"; // optional module docstring

    m.def("compare", &comparison, "");
    m.def("keygen", &keygen, "");
    m.def("encryptValue", &encryptValue, "");
    m.def("decrypt", &decrypt, "");
}