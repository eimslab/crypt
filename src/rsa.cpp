#include <cassert>

#include "rsa.h"
#include "tea/xtea.h"
#include "utils/random.h"
#include "utils/utility.h"
#include "base64.h"

using namespace cryption::rsa;

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
#endif
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

extern "C" DLL_EXPORT BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
    {
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

uint rsaKeyGenerate(uint bitLength, char* result)
{
    RSAKeyPair keyPair = RSA::generateKeyPair(bitLength);
    string key = "privateKey:\r\n" + keyPair.privateKey + "\r\npublicKey:\r\n" + keyPair.publicKey;

    ubyte* p = (ubyte*)key.c_str();
    int i;
    for (i = 0; i < (int)key.length(); i++)
    {
        result[i] = p[i];
    }
    result[i] = 0;

    return key.length();
}

namespace cryption
{
namespace rsa
{

Random rnd;

RSAKeyPair RSA::generateKeyPair(uint bitLength = 1024)
{
    assert((bitLength >= 128) && (bitLength % 8 == 0));

    BigInt p, q, n, t, e;

    p = p.genPseudoPrime(bitLength / 2, 40, rnd);
    q = q.genPseudoPrime(bitLength / 2, 40, rnd);
    n = p * q;
    t = (p - 1) * (q - 1);
    e = Primes[(rnd.next() % 42) + 6500];

    BigInt d = e.modInverse(t);

    return RSAKeyPair(encodeKey(n, d), encodeKey(n, e));
}

string RSA::encodeKey(BigInt modulus, BigInt exponent)
{
    uint m_len = modulus.dataLength << 2;
    ubyte* m_bytes = new ubyte[m_len];
    m_len = modulus.getBytesRemovedZero(m_bytes, m_len);

    uint e_len = exponent.dataLength << 2;
    ubyte* e_bytes = new ubyte[e_len];
    e_len = exponent.getBytesRemovedZero(e_bytes, e_len);

    ubyte* buffer = new ubyte[4 + m_len + e_len];
    Utility::writeIntToBytes<uint>(m_len, buffer, ENDIAN_BIG);

    for (uint i = 0; i < m_len; i++)
    {
        buffer[i + 4] = m_bytes[i];
    }

    for (uint i = 0; i < e_len; i++)
    {
        buffer[i + 4 + m_len] = e_bytes[i];
    }

    string ret = cryption::base64::Base64::encode(buffer, 4 + m_len + e_len);
    delete[] m_bytes;
    delete[] e_bytes;
    delete[] buffer;

    return ret;
}

RSAKeyInfo RSA::decodeKey(string const& key)
{
    ubyte* buffer = new ubyte[key.size()];
    uint size = cryption::base64::Base64::decode(key, buffer);
    uint m_len = Utility::readIntFromBytes<uint>(buffer, ENDIAN_BIG);

    ubyte* m_bytes = new ubyte[m_len];
    for (uint i = 0; i < m_len; i++)
    {
        m_bytes[i] = buffer[i + 4];
    }

    ubyte* e_bytes = new ubyte[(int)(size - 4 - m_len)];
    for (int i = 0; i < (int)(size - 4 - m_len); i++)
    {
        e_bytes[i] = buffer[i + 4 + m_len];
    }

    RSAKeyInfo ret = RSAKeyInfo(BigInt(m_bytes, m_len), BigInt(e_bytes, (int)(size - 4 - m_len)));
    delete[] buffer;
    delete[] m_bytes;
    delete[] e_bytes;

    return ret;
}

uint RSA::encrypt(string const& key, ubyte* data, uint len, ubyte* result, bool mixinXteaMode)
{
    RSAKeyInfo keyInfo = decodeKey(key);
    return encrypt(keyInfo, data, len, result, mixinXteaMode);
}

uint RSA::encrypt(RSAKeyInfo key, ubyte* data, uint len, ubyte* result, bool mixinXteaMode)
{
    if (mixinXteaMode)
    {
        return encrypt_mixinXteaMode(key, data, len, result);
    }

    uint keySize = key.modulus.dataLength << 2;
    ubyte* t_buf = new ubyte[keySize];
    keySize = key.modulus.getBytesRemovedZero(t_buf, keySize);
    delete[] t_buf;
    uint pos = 0, ret_pos = 0;
    ubyte* block;
    BigInt bi;

    while (pos < len)
    {
        int blockSize = ((keySize - 1) <= (len - pos)) ? (keySize - 1) : (len - pos);
        ubyte preamble = (ubyte)rnd.next(0x01, 0xFF);

        while (true)
        {
            block = new ubyte[blockSize + 1];
            block[0] = preamble;

            for (uint i = pos; i < pos + blockSize; i++)
            {
                block[i - pos + 1] = data[i];
            }

            bi = BigInt(block, blockSize + 1);
            if (bi >= key.modulus)
            {
                delete[] block;
                blockSize--;
                assert(blockSize > 0);
                continue;
            }
            else
            {
                break;
            }
        }

        pos += blockSize;
        bi = bi.modPow(key.exponent, key.modulus);
        delete[] block;
        uint block_len = bi.dataLength << 2;
        block = new ubyte[block_len];
        block_len = bi.getBytesRemovedZero(block, block_len);

        if (block_len < keySize)
        {
            for (int i = 0; i < (int)(keySize - block_len); i++)
            {
                result[ret_pos++] = 0x00;
            }
        }
        for (uint i = 0; i < block_len; i++)
        {
            result[ret_pos++] = block[i];
        }

        delete[] block;
    }

    result[ret_pos] = 0;
    return ret_pos;
}

uint RSA::encrypt_mixinXteaMode(RSAKeyInfo key, ubyte* data, uint len, ubyte* result)
{
    uint keySize = key.modulus.dataLength << 2;
    ubyte* t_buf = new ubyte[keySize];
    keySize = key.modulus.getBytesRemovedZero(t_buf, keySize);
    delete[] t_buf;
    uint pos = 0;
    ubyte* block;
    BigInt bi;

    int blockSize = ((keySize - 1) <= len) ? (keySize - 1) : len;
    ubyte preamble = (ubyte)rnd.next(0x01, 0xFF);
    int xteaKey[4];

    while (true)
    {
        block = new ubyte[blockSize + 1];
        block[0] = preamble;

        for (int i = 0; i < blockSize; i++)
        {
            block[i + 1] = data[i];
        }

        bi = BigInt(block, blockSize + 1);
        if (bi >= key.modulus)
        {
            delete[] block;
            blockSize--;
            assert(blockSize > 0);
            continue;
        }
        else
        {
            generateXteaKey(block, blockSize + 1, xteaKey);
            break;
        }
    }

    bi = bi.modPow(key.exponent, key.modulus);
    delete[] block;
    uint t_len = bi.dataLength << 2;
    block = new ubyte[t_len];
    t_len = bi.getBytesRemovedZero(block, t_len);

    if (t_len < keySize)
    {
        for (int i = 0; i < (int)(keySize - t_len); i++)
        {
            result[pos++] = 0x00;
        }
    }
    for (uint i = 0; i < t_len; i++)
    {
        result[pos++] = block[i];
    }

    delete[] block;

    if (blockSize >= (int)len)
    {
        result[pos] = 0;
        return pos;
    }

    block = new ubyte[len - blockSize + 12];
    t_len = cryption::tea::xtea::XTEAUtils::encrypt(data + blockSize, len - blockSize, xteaKey, block);
    for (uint i = 0; i < t_len; i++)
    {
        result[pos++] = block[i];
    }
    delete[] block;

    result[pos] = 0;
    return pos;
}

uint RSA::decrypt(string const& key, ubyte* data, uint len, ubyte* result, bool mixinXteaMode)
{
    RSAKeyInfo keyInfo = decodeKey(key);
    return decrypt(keyInfo, data, len, result, mixinXteaMode);
}

uint RSA::decrypt(RSAKeyInfo key, ubyte* data, uint len, ubyte* result, bool mixinXteaMode)
{
    if (mixinXteaMode)
    {
        return decrypt_mixinXteaMode(key, data, len, result);
    }

    uint keySize = key.modulus.dataLength << 2;
    ubyte* t_buf = new ubyte[keySize];
    keySize = key.modulus.getBytesRemovedZero(t_buf, keySize);
    delete[] t_buf;
    uint pos = 0, ret_pos = 0;
    ubyte* block;
    BigInt bi;

    while (pos < len)
    {
        uint blockSize = (keySize <= (len - pos)) ? keySize : (len - pos);
        block = new ubyte[blockSize];

        for (uint i = pos; i < pos + blockSize; i++)
        {
            block[i - pos] = data[i];
        }

        bi = BigInt(block, blockSize);
        delete[] block;
        pos += blockSize;
        bi = bi.modPow(key.exponent, key.modulus);

        int block_len = bi.dataLength << 2;
        block = new ubyte[block_len];
        block_len = bi.getBytesRemovedZero(block, block_len);

        for (int i = 1; i < block_len; i++) // skip [0] first random element.
        {
            result[ret_pos++] = block[i];
        }

        delete[] block;
    }

    result[ret_pos] = 0;
    return ret_pos;
}

uint RSA::decrypt_mixinXteaMode(RSAKeyInfo key, ubyte* data, uint len, ubyte* result)
{
    uint keySize = key.modulus.dataLength << 2;
    ubyte* t_buf = new ubyte[keySize];
    keySize = key.modulus.getBytesRemovedZero(t_buf, keySize);
    delete[] t_buf;
    uint pos = 0;
    ubyte* block;
    int xteaKey[4];

    uint blockSize = (keySize <= len) ? keySize : len;
    block = new ubyte[blockSize];

    for (uint i = 0; i < blockSize; i++)
    {
        block[i] = data[i];
    }

    BigInt bi = BigInt(block, blockSize);
    delete[] block;
    bi = bi.modPow(key.exponent, key.modulus);

    int t_len = bi.dataLength << 2;
    block = new ubyte[t_len];
    t_len = bi.getBytesRemovedZero(block, t_len);

    generateXteaKey(block, t_len, xteaKey);

    for (int i = 1; i < t_len; i++) // skip [0] first random element.
    {
        result[pos++] = block[i];
    }
    delete[] block;

    if (blockSize >= len)
    {
        result[pos] = 0;
        return pos;
    }

    block = new ubyte[len - blockSize];
    t_len = cryption::tea::xtea::XTEAUtils::decrypt(data + blockSize, len - blockSize, xteaKey, block);

    for (int i = 0; i < t_len; i++)
    {
        result[pos++] = block[i];
    }
    delete[] block;

    result[pos] = 0;
    return pos;
}

void RSA::generateXteaKey(ubyte* buf, uint len, int* xteaKey)
{
    ubyte* data = new ubyte[sizeof(int) * 4];
    for (int i = 0; i < (int)sizeof(int) * 4; i++)
    {
        data[i] = buf[i % len];
    }

    for (int i = 0; i < 4; i++)
    {
        *(xteaKey + i) = Utility::readIntFromBytes<int>(data + i * sizeof(int), ENDIAN_BIG);
    }

    delete[] data;
}

}
}
