#pragma once

#include "utils/types.h"
#include "utils/bigint.h"
#include "utils/random.h"

using namespace std;
using namespace cryption::utils;

namespace cryption
{
namespace rsa
{

struct RSAKeyPair
{
public:
    string privateKey;
    string publicKey;

    RSAKeyPair()
    {
    }

    RSAKeyPair(string privateKey, string publicKey)
    {
        this->privateKey    = privateKey;
        this->publicKey     = publicKey;
    }
};

struct RSAKeyInfo
{
public:
    BigInt  modulus;
    BigInt  exponent;

    RSAKeyInfo()
    {
    }

    RSAKeyInfo(BigInt modulus, BigInt exponent)
    {
        this->modulus       = modulus;
        this->exponent      = exponent;
    }
};

class RSA
{
public:
    static RSAKeyPair generateKeyPair(uint);
    static string encodeKey(BigInt, BigInt);
    static RSAKeyInfo decodeKey(string const&);
    static size_t encrypt(string const&, ubyte*, size_t, ubyte*, bool mixinXteaMode = false);
    static size_t encrypt(RSAKeyInfo, ubyte*, size_t, ubyte*, bool mixinXteaMode = false);
    static size_t decrypt(string const&, ubyte*, size_t, ubyte*, bool mixinXteaMode = false);
    static size_t decrypt(RSAKeyInfo, ubyte*, size_t, ubyte*, bool mixinXteaMode = false);

private:
    static size_t encrypt_mixinXteaMode(RSAKeyInfo, ubyte*, size_t, ubyte*);
    static size_t decrypt_mixinXteaMode(RSAKeyInfo, ubyte*, size_t, ubyte*);

    static void generateXteaKey(ubyte* buf, size_t len, int* xteaKey);
};

}
}
