#include <cmath>
#include <iostream>
#include <random>
#include <climits>
#include <sstream>

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
    const long D_F = 1;
    const long D_G = 4;
    // Parameters for HEAAN //
    const long CIRCUIT_DEPTH = 5;
    const long LOGP = 40; ///< scaling factor log ∆
    const long LOGQ = ((LOGP * CIRCUIT_DEPTH) * (D_F + D_G) + LOGP + 10) + (LOGP * 4); ///< Ciphertext modulus
    const long LOGN = 16; ///< number of slots (2^16 = 65536)
    const long NN = 1 << LOGN;
    const long SLOTS = NN;
    const long NUM_THREADS = 16;
    const long R[16] = { 32768, 49152, 57344, 61440, 63488, 64512, 65024, 65280, 65408, 65472, 65504, 65520, 65528, 65532, 65534, 65535 };
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

void decryptAndPrint(Ciphertext& cipher, int n) {
    Ring ring;
    SecretKey secretKey(ring);
    Scheme scheme(ring, nullptr, nullptr);
    readSecretKey(secretKey, "keys/secret.key");
    // Read in ciphertext
    // HEAAN represents values as complex numbers
    // Decrypt and extract the real number parts
    std::vector<double> decryptedValuesReal;
    decryptedValuesReal.reserve(constants::SLOTS);
    complex<double>* decryptedValues = scheme.decrypt(secretKey, cipher);
    std::cout << "-----------------------" << std::endl;
    for (int i = 0; i < n; i++) {
        std::cout << "[" << i << "] = " << decryptedValues[i].real() << std::endl;
    }
    std::cout << "-----------------------" << std::endl;
}

void g4(Scheme& scheme, Ciphertext& gx, Ciphertext& x, long logp) {
    //                        x^1      x^3       x^5      x^7         x^9                            
    vector<double> coeffs = { 5.71289, -34.1543, 94.7412, -110.83203, 45.530273 };
    Ciphertext term, x2, x3;
    scheme.square(x2, x);
    scheme.reScaleByAndEqual(x2, logp);
    scheme.mult(x3, x2, x);
    scheme.reScaleByAndEqual(x3, logp);

    scheme.modDownByAndEqual(x, logp);
    scheme.modDownByAndEqual(x, logp);

    scheme.multByConst(gx, x3, coeffs[4], logp);
    scheme.reScaleByAndEqual(gx, logp);
    scheme.multByConst(term, x, coeffs[3], logp);
    scheme.reScaleByAndEqual(term, logp);
    
    scheme.addAndEqual(gx, term);
    scheme.multAndEqual(gx, x3);
    scheme.reScaleByAndEqual(gx, logp);

    scheme.modDownByAndEqual(x2, logp);
    scheme.modDownByAndEqual(x2, logp);
    scheme.multByConst(term, x2, coeffs[2], logp);
    scheme.reScaleByAndEqual(term, logp);
    scheme.addAndEqual(gx, term);

    scheme.addConstAndEqual(gx, coeffs[1], logp);

    scheme.multAndEqual(gx, x3);
    scheme.reScaleByAndEqual(gx, logp);

    scheme.modDownByAndEqual(x, logp);
    scheme.modDownByAndEqual(x, logp);
    scheme.multByConst(term, x, coeffs[0], logp);
    scheme.reScaleByAndEqual(term, logp);
    scheme.addAndEqual(gx, term);
}

void f4(Scheme& scheme, Ciphertext& fx, Ciphertext& x, long logp) {
    //                        x^1        x^3       x^5       x^7       x^9                            
    vector<double> coeffs = { 2.4609375, -3.28125, 2.953125, -1.40625, 0.2734375 };
    Ciphertext term, x2, x3;
    scheme.square(x2, x);
    scheme.reScaleByAndEqual(x2, logp);
    scheme.mult(x3, x2, x);
    scheme.reScaleByAndEqual(x3, logp);

    scheme.modDownByAndEqual(x, logp);
    scheme.modDownByAndEqual(x, logp);

    scheme.multByConst(fx, x3, coeffs[4], logp);
    scheme.reScaleByAndEqual(fx, logp);
    scheme.multByConst(term, x, coeffs[3], logp);

    scheme.reScaleByAndEqual(term, logp);
    scheme.addAndEqual(fx, term);
    scheme.multAndEqual(fx, x3);
    scheme.reScaleByAndEqual(fx, logp);

    scheme.modDownByAndEqual(x2, logp);
    scheme.modDownByAndEqual(x2, logp);
    scheme.multByConst(term, x2, coeffs[2], logp);
    scheme.reScaleByAndEqual(term, logp);
    scheme.addAndEqual(fx, term);

    scheme.addConstAndEqual(fx, coeffs[1], logp);

    scheme.multAndEqual(fx, x3);
    scheme.reScaleByAndEqual(fx, logp);

    scheme.modDownByAndEqual(x, logp);
    scheme.modDownByAndEqual(x, logp);
    scheme.multByConst(term, x, coeffs[0], logp);
    scheme.reScaleByAndEqual(term, logp);
    scheme.addAndEqual(fx, term);
}

void keygen(std::string secretKeyPath, std::string multKeyPath, std::string encKeyPath, std::string rotKeyPath) {
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
    scheme.addRightRotKeys(secretKey);
    SerializationUtils::writeKey(scheme.keyMap.at(MULTIPLICATION), multKeyPath);
    SerializationUtils::writeKey(scheme.keyMap.at(ENCRYPTION), encKeyPath);

    for (int i = 0; i < 16; i++) {
        stringstream s;
        s << rotKeyPath << constants::R[i] << ".key";
        SerializationUtils::writeKey(scheme.leftRotKeyMap.at(constants::R[i]), s.str());
    }
}

void encryptSingle(double value, std::string encKeyPath, std::string ciphertextPath) {
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

void encryptMany(std::vector<double> values, std::string encKeyPath, std::string ciphertextPath) {
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
        data[i] = values[i];
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
    // x = g_4(x), d_g  times
    for (int i = 0; i < constants::D_G; ++i) {
        g4(scheme, f4x, x, constants::LOGP);
        x.copy(f4x);
        f4x.free();
    }
    // x = f_4(x), d_f  times
    for (int i = 0; i < constants::D_F; ++i) {
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

void depthFiveMult(std::string inCipherPath, std::string outCipherPath, std::string encKeyPath, std::string multKeyPath, std::string rotKeyPath, std::string secretKeyPath) {
    std::uniform_int_distribution<unsigned int> dist(0, UINT_MAX);
    std::random_device urandom("/dev/urandom");
    srand(dist(urandom));
    SetNumThreads(constants::NUM_THREADS);
    // Need both encryption key and multiplication key
    Ring ring;
    SecretKey secretKey(ring);
    readSecretKey(secretKey, secretKeyPath);
    Key* encKey = SerializationUtils::readKey(encKeyPath);
    Key* multKey = SerializationUtils::readKey(multKeyPath);
    Scheme scheme(ring, encKey, multKey);

    double* data = new double[constants::SLOTS];
    for (int i = 0; i < constants::SLOTS / 64; ++i) {
        for (int j = 0; j < 16; ++j) {
            data[i + j + 0] = (j >> 0) & 1;
            data[i + j + 1] = (j >> 1) & 1;
            data[i + j + 2] = (j >> 2) & 1;
            data[i + j + 3] = (j >> 3) & 1;
        }
    }

    Ciphertext* c = SerializationUtils::readCiphertext(inCipherPath);
    
    for (int i = 0; i < 16; ++i){
        stringstream s;
        s << rotKeyPath << constants::R[i] << ".key";
        scheme.leftRotKeyMap.insert(std::pair<long, Key*>(constants::R[i], SerializationUtils::readKey(s.str())));
    }

    Ciphertext ones, c1, c2;
    scheme.encrypt(ones, data, constants::NN, constants::LOGP, constants::LOGQ);
    scheme.sub(*c, ones, *c);
    c1.copy(*c);
    scheme.rightRotateFastAndEqual(*c, 1);
    scheme.multAndEqual(c1, *c);
    scheme.reScaleByAndEqual(c1, constants::LOGP);
    c2.copy(c1);
    scheme.rightRotateFastAndEqual(c2, 2);
    scheme.multAndEqual(c1, c2);
    scheme.reScaleByAndEqual(c1, constants::LOGP);
    
    // Ensure the only data that is left are the results of the tree evaluation
    delete[] data;
    data = new double[constants::SLOTS];
    for (int i = 0; i < constants::SLOTS; i++) {
            data[i] = (i % 4 == 3) ? 1 : 0; 
    }

    ones.free();
    scheme.encrypt(ones, data, constants::NN, constants::LOGP, constants::LOGQ);
    scheme.multAndEqual(c1, ones);
    scheme.reScaleByAndEqual(c1, constants::LOGP);

    SerializationUtils::writeCiphertext(c1, outCipherPath);

    delete[] data;
}

void pdte(std::vector<double> featureValues, std::string inCipherPath, std::string outCipherPath, std::string encKeyPath, std::string multKeyPath, std::string rotKeyPath) {
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
    // x = g_4(x), d_g  times
    for (int i = 0; i < constants::D_G; ++i) {
        g4(scheme, f4x, x, constants::LOGP);
        x.copy(f4x);
        f4x.free();
    }
    // x = f_4(x), d_f  times
    for (int i = 0; i < constants::D_F; ++i) {
        f4(scheme, f4x, x, constants::LOGP);
        x.copy(f4x);
        f4x.free();
    }
    
    // return (x + 1) / 2
    scheme.addConstAndEqual(x, 1.0, constants::LOGP);
    scheme.multByConstAndEqual(x, 0.5, constants::LOGP);
    scheme.reScaleByAndEqual(x, constants::LOGP);

    double* data = new double[constants::SLOTS];
    for (int i = 0; i < constants::SLOTS / 64; ++i) {
        for (int j = 0; j < 16; ++j) {
            data[(i*64) + (j*4) + 0] = (j >> 3) & 1;
            data[(i*64) + (j*4) + 1] = (j >> 2) & 1;
            data[(i*64) + (j*4) + 2] = (j >> 1) & 1;
            data[(i*64) + (j*4) + 3] = (j >> 0) & 1;
        }
    }
    for (int i = 0; i < 16; ++i){
        stringstream s;
        s << rotKeyPath << constants::R[i] << ".key";
        scheme.leftRotKeyMap.insert(std::pair<long, Key*>(constants::R[i], SerializationUtils::readKey(s.str())));
    }
    Ciphertext ones, c1, c2;
    scheme.encrypt(ones, data, constants::NN, constants::LOGP, constants::LOGQ);
    scheme.modDownByAndEqual(ones, 1040);
    scheme.sub(x, ones, x);

    c1.copy(x);
    scheme.rightRotateFastAndEqual(x, 1);
    scheme.multAndEqual(c1, x);
    scheme.reScaleByAndEqual(c1, constants::LOGP);
    c2.copy(c1);
    scheme.rightRotateFastAndEqual(c2, 2);
    scheme.multAndEqual(c1, c2);
    scheme.reScaleByAndEqual(c1, constants::LOGP);
    SerializationUtils::writeCiphertext(c1, outCipherPath);

    delete[] data;
}

// void secure_branch(std::vector<double> featureValues, std::string inCipherPath, std::string outCipherPath, std::string encKeyPath, std::string multKeyPath)

// Module name needs to be same name as file
PYBIND11_MODULE(seccomp, m) {
    m.doc() = "pybind11 example plugin"; // optional module docstring

    m.def("compare", &comparison, "");
    m.def("keygen", &keygen, "");
    m.def("encryptSingle", &encryptSingle, "");
    m.def("encryptMany", &encryptMany, "");
    m.def("decrypt", &decrypt, "");
    m.def("pdte", &pdte, "");
}