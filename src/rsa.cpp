#include <cassert>

#include "rsa.h"
#include "tea/xtea.h"
#include "utils/random.h"
#include "utils/utility.h"
#include "base64.h"

using namespace crypto::rsa;

namespace crypto
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
    int m_len = modulus.dataLength << 2;
    ubyte* m_bytes = new ubyte[m_len];
    m_len = modulus.getBytesRemovedZero(m_bytes, m_len);

    int e_len = exponent.dataLength << 2;
    ubyte* e_bytes = new ubyte[e_len];
    e_len = exponent.getBytesRemovedZero(e_bytes, e_len);

    ubyte* buffer = new ubyte[4 + m_len + e_len];
    Utility::writeIntToBytes<int>(m_len, buffer, ENDIAN_BIG);

    for (int i = 0; i < m_len; i++)
    {
        buffer[i + 4] = m_bytes[i];
    }

    for (int i = 0; i < e_len; i++)
    {
        buffer[i + 4 + m_len] = e_bytes[i];
    }

    string ret = crypto::base64::Base64::encode(buffer, 4 + m_len + e_len);
    delete[] m_bytes;
    delete[] e_bytes;
    delete[] buffer;

    return ret;
}

RSAKeyInfo RSA::decodeKey(string const& key)
{
    ubyte* buffer = new ubyte[key.size()];
    size_t size = crypto::base64::Base64::decode(key, buffer);
    int m_len = Utility::readIntFromBytes<int>(buffer, ENDIAN_BIG);

    ubyte* m_bytes = new ubyte[m_len];
    for (int i = 0; i < m_len; i++)
    {
        m_bytes[i] = buffer[i + 4];
    }

    ubyte* e_bytes = new ubyte[size - 4 - m_len];
    for (size_t i = 0; i < size - 4 - m_len; i++)
    {
        e_bytes[i] = buffer[i + 4 + m_len];
    }

    RSAKeyInfo ret = RSAKeyInfo(BigInt(m_bytes, m_len), BigInt(e_bytes, (int)(size - 4 - m_len)));
    delete[] buffer;
    delete[] m_bytes;
    delete[] e_bytes;

    return ret;
}

size_t RSA::encrypt(string const& key, ubyte* data, size_t len, ubyte* result, bool mixinXteaMode)
{
    RSAKeyInfo keyInfo = decodeKey(key);
    return encrypt(keyInfo, data, len, result, mixinXteaMode);
}

size_t RSA::encrypt(RSAKeyInfo key, ubyte* data, size_t len, ubyte* result, bool mixinXteaMode)
{
    if (mixinXteaMode)
    {
        return encrypt_mixinXteaMode(key, data, len, result);
    }

    int keySize = key.modulus.dataLength << 2;
    ubyte* t_buf = new ubyte[keySize];
    keySize = key.modulus.getBytesRemovedZero(t_buf, keySize);
    delete[] t_buf;
    size_t pos = 0, ret_pos = 0;
    ubyte* block;
    BigInt bi;

    while (pos < len)
    {
        int blockSize = (int)(((keySize - 1) <= (int)(len - pos)) ? (keySize - 1) : (len - pos));
        ubyte preamble = (ubyte)rnd.next(0x01, 0xFF);

        while (true)
        {
            block = new ubyte[blockSize + 1];
            block[0] = preamble;

            for (size_t i = pos; i < pos + blockSize; i++)
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
        int block_len = bi.dataLength << 2;
        block = new ubyte[block_len];
        block_len = bi.getBytesRemovedZero(block, block_len);

        if (block_len < keySize)
        {
            for (int i = 0; i < keySize - block_len; i++)
            {
                result[ret_pos++] = 0x00;
            }
        }
        for (int i = 0; i < block_len; i++)
        {
            result[ret_pos++] = block[i];
        }

        delete[] block;
    }

    result[ret_pos] = 0;
    return ret_pos;
}

size_t RSA::encrypt_mixinXteaMode(RSAKeyInfo key, ubyte* data, size_t len, ubyte* result)
{
    int keySize = key.modulus.dataLength << 2;
    ubyte* t_buf = new ubyte[keySize];
    keySize = key.modulus.getBytesRemovedZero(t_buf, keySize);
    delete[] t_buf;
    size_t pos = 0;
    ubyte* block;
    BigInt bi;

    int blockSize = (int)(((keySize - 1) <= (int)len) ? (keySize - 1) : len);
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
    int t_len = bi.dataLength << 2;
    block = new ubyte[t_len];
    t_len = bi.getBytesRemovedZero(block, t_len);

    if (t_len < keySize)
    {
        for (int i = 0; i < keySize - t_len; i++)
        {
            result[pos++] = 0x00;
        }
    }
    for (int i = 0; i < t_len; i++)
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
    size_t remainder_len = crypto::tea::xtea::XTEAUtils::encrypt(data + blockSize, len - blockSize, xteaKey, block);
    for (size_t i = 0; i < remainder_len; i++)
    {
        result[pos++] = block[i];
    }
    delete[] block;

    result[pos] = 0;
    return pos;
}

size_t RSA::decrypt(string const& key, ubyte* data, size_t len, ubyte* result, bool mixinXteaMode)
{
    RSAKeyInfo keyInfo = decodeKey(key);
    return decrypt(keyInfo, data, len, result, mixinXteaMode);
}

size_t RSA::decrypt(RSAKeyInfo key, ubyte* data, size_t len, ubyte* result, bool mixinXteaMode)
{
    if (mixinXteaMode)
    {
        return decrypt_mixinXteaMode(key, data, len, result);
    }

    int keySize = key.modulus.dataLength << 2;
    ubyte* t_buf = new ubyte[keySize];
    keySize = key.modulus.getBytesRemovedZero(t_buf, keySize);
    delete[] t_buf;
    size_t pos = 0, ret_pos = 0;
    ubyte* block;
    BigInt bi;

    while (pos < len)
    {
        int blockSize = (int)((keySize <= (int)(len - pos)) ? keySize : (len - pos));
        block = new ubyte[blockSize];

        for (size_t i = pos; i < pos + blockSize; i++)
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

size_t RSA::decrypt_mixinXteaMode(RSAKeyInfo key, ubyte* data, size_t len, ubyte* result)
{
    int keySize = key.modulus.dataLength << 2;
    ubyte* t_buf = new ubyte[keySize];
    keySize = key.modulus.getBytesRemovedZero(t_buf, keySize);
    delete[] t_buf;
    size_t pos = 0;
    ubyte* block;
    int xteaKey[4];

    int blockSize = (int)((keySize <= (int)len) ? keySize : len);
    block = new ubyte[blockSize];

    for (int i = 0; i < blockSize; i++)
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

    if (blockSize >= (int)len)
    {
        result[pos] = 0;
        return pos;
    }

    block = new ubyte[len - blockSize];
    size_t remainder_len = crypto::tea::xtea::XTEAUtils::decrypt(data + blockSize, len - blockSize, xteaKey, block);

    for (size_t i = 0; i < remainder_len; i++)
    {
        result[pos++] = block[i];
    }
    delete[] block;

    result[pos] = 0;
    return pos;
}

void RSA::generateXteaKey(ubyte* buf, size_t len, int* xteaKey)
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
