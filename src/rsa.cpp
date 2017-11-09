#include <cassert>

#include "rsa.h"
#include "utils/random.h"
#include "utils/utility.h"
#include "base64.h"

using namespace crypt::rsa;

#ifdef _WIN32

#include <windows.h>

#define DLL_EXPORT __declspec(dllexport) __stdcall
#ifdef __cplusplus
extern "C"
{
#endif
uint DLL_EXPORT rsaKeyGenerate(uint bitLength, char* buf);
#ifdef __cplusplus
}
#endif

extern "C" DLL_EXPORT BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            break;
        case DLL_PROCESS_DETACH:
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
    }

    return TRUE;
}

#else

extern "C" uint rsaKeyGenerate(uint bitLength, char* result);

#endif

uint rsaKeyGenerate(uint bitLength, char* result) {
    RSAKeyPair keyPair = RSA::generateKeyPair(bitLength);
    string key = "privateKey:\r\n" + keyPair.privateKey + "\r\npublicKey:\r\n" + keyPair.publicKey;

    ubyte* p = (ubyte*)key.c_str();
    int i;
    for (i = 0; i < (int)key.length(); i++) {
        result[i] = p[i];
    }
    result[i] = 0;

    return key.length();
}

namespace crypt {
namespace rsa {

Random rnd;

RSAKeyPair RSA::generateKeyPair(uint bitLength = 1024) {
    assert((bitLength >= 16) && (bitLength % 8 == 0));

    BigInt p, q, n, t, e;

    p = p.genPseudoPrime(bitLength / 2, 40, rnd);
    q = q.genPseudoPrime(bitLength / 2, 40, rnd);
    n = p * q;
    t = (p - 1) * (q - 1);
    e = Primes[(rnd.next() % 42) + 6500];

    BigInt d = e.modInverse(t);

    return RSAKeyPair(encodeKey(n, d), encodeKey(n, e));
}

string RSA::encodeKey(BigInt modulus, BigInt exponent) {
    uint m_len = modulus.dataLength << 2;
    ubyte* m_bytes = new ubyte[m_len];
    modulus.getBytes(m_bytes);

    uint e_len = exponent.dataLength << 2;
    ubyte* e_bytes = new ubyte[e_len];
    exponent.getBytes(e_bytes);

    ubyte* buffer = new ubyte[4 + m_len + e_len];
    Utility::writeIntToBytes<uint>(m_len, buffer, 2);

    for (int i = 0; i < m_len; i++) {
        buffer[i + 4] = m_bytes[i];
    }

    for (int i = 0; i < e_len; i++) {
        buffer[i + 4 + m_len] = e_bytes[i];
    }

    string ret = crypt::base64::Base64::encode(buffer, 4 + m_len + e_len);
    delete[] buffer;

    return ret;
}

RSAKeyInfo RSA::decodeKey(string const& key) {
    ubyte* buffer = new ubyte[key.size()];
    uint size = crypt::base64::Base64::decode(key, buffer);
    uint m_len = Utility::readIntFromBytes<uint>(buffer, 2);

    ubyte* m_bytes = new ubyte[m_len];
    for (int i = 0; i < m_len; i++) {
        m_bytes[i] = buffer[i + 4];
    }

    ubyte* e_bytes = new ubyte[size - 4 - m_len];
    for (uint i = 0; i < size - 4 - m_len; i++) {
        e_bytes[i] = buffer[i + 4 + m_len];
    }

    RSAKeyInfo ret = RSAKeyInfo(BigInt(m_bytes, m_len), BigInt(e_bytes, size - 4 - m_len));
    delete[] buffer;
    delete[] m_bytes;
    delete[] e_bytes;

    return ret;
}

uint RSA::encrypt(string const& key, ubyte* data, uint len, ubyte* result) {
    RSAKeyInfo keyInfo = decodeKey(key);
    return encrypt(keyInfo, data, len, result);
}

uint RSA::encrypt(RSAKeyInfo key, ubyte* data, uint len, ubyte* result) {
    uint keySize = key.modulus.dataLength << 2;
    uint pos = 0, ret_pos = 0;
    ubyte* block;
    BigInt bi;

    while (pos < len) {
        int blockSize = (keySize - 1) <= (len - pos) ? (keySize - 1) : (len - pos);
        ubyte preamble = (ubyte)rnd.next(0x01, 0xFF);

        while (true) {
            block = new ubyte[blockSize + 1];
            block[0] = preamble;

            for (uint i = pos; i < pos + blockSize; i++) {
                block[i - pos + 1] = data[i];
            }

            bi = BigInt(block, blockSize + 1);
            if (bi >= key.modulus) {
                delete[] block;
                blockSize--;
                assert(blockSize > 0);
                continue;
            }
            else
                break;
        }

        pos += blockSize;
        bi = bi.modPow(key.exponent, key.modulus);
        delete[] block;
        uint block_len = bi.dataLength << 2;
        block = new ubyte[block_len];
        bi.getBytes(block);

        if (block_len < keySize) {
            for (uint i = 0; i < keySize - block_len; i++) {
                result[ret_pos++] = 0x00;
            }
        }
        for (uint i = 0; i < block_len; i++) {
            result[ret_pos++] = block[i];
        }

        delete[] block;
    }

    result[ret_pos] = 0;
    return ret_pos;
}

uint RSA::decrypt(string const& key, ubyte* data, uint len, ubyte* result) {
    RSAKeyInfo keyInfo = decodeKey(key);
    return decrypt(keyInfo, data, len, result);
}

uint RSA::decrypt(RSAKeyInfo key, ubyte* data, uint len, ubyte* result) {
    uint keySize = key.modulus.dataLength << 2;
    uint pos = 0, ret_pos = 0;
    ubyte* block;
    BigInt bi;

    while (pos < len) {
        uint blockSize = keySize <= (len - pos) ? keySize : (len - pos);
        block = new ubyte[blockSize];

        for (uint i = pos; i < pos + blockSize; i++) {
            block[i - pos] = data[i];
        }

        bi = BigInt(block, blockSize);
        delete[] block;
        pos += blockSize;

        bi = bi.modPow(key.exponent, key.modulus);
        int block_len = bi.dataLength << 2;
        block = new ubyte[block_len];
        bi.getBytes(block);

        int t_pos = 0;
        while (block[t_pos++] == 0); // flite preamble 0, and let t_pos skip [0] first random element.

        for (int i = t_pos; i < block_len; i++) {
            result[ret_pos++] = block[i];
        }

        delete[] block;
    }

    result[ret_pos] = 0;
    return ret_pos;
}

}
}
