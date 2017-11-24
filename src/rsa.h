#pragma once

#include "utils/typedefine.h"
#include "utils/bigint.h"
#include "utils/random.h"

using namespace std;
using namespace crypt::utils;

namespace crypt {
namespace rsa {

struct RSAKeyPair {
public:
    string privateKey;
    string publicKey;

    RSAKeyPair(string privateKey, string publicKey) {
        this->privateKey    = privateKey;
        this->publicKey     = publicKey;
    }
};

struct RSAKeyInfo {
public:
    BigInt  modulus;
    BigInt  exponent;

    RSAKeyInfo(BigInt modulus, BigInt exponent) {
        this->modulus               = modulus;
        this->exponent              = exponent;
    }
};

class RSA {
public:
    static RSAKeyPair generateKeyPair(uint);
    static string encodeKey(BigInt, BigInt);
    static RSAKeyInfo decodeKey(string const&);
    static uint encrypt(string const&, ubyte*, uint, ubyte*);
    static uint encrypt(RSAKeyInfo, ubyte*, uint, ubyte*);
    static uint decrypt(string const&, ubyte*, uint, ubyte*);
    static uint decrypt(RSAKeyInfo, ubyte*, uint, ubyte*);
};

}
}
