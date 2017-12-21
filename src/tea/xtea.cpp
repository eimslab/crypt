#include <cassert>

#include "xtea.h"

using namespace cryption::utils;

namespace cryption
{
namespace tea
{
namespace xtea
{

XTEA::XTEA(int* key, int rounds)
{
    this->DELTA = 0x9E3779B9;
    this->m_key = key;
    this->m_rounds = rounds;
}

size_t XTEA::padding(ubyte* data, size_t len, ubyte* output)
{
    size_t output_len = len;
    while ((output_len + 4) % 8 != 0) output_len++;

    for (size_t i = 0; i < len; i++)
        output[i] = data[i];
    for (size_t i = len; i < output_len; i++)
        output[i] = 0;

    Utility::writeIntToBytes<uint>((uint)len, output + output_len, ENDIAN_BIG);

    return output_len + 4;
}

// Encrypt given ubyte array (length to be crypted must be 8 ubyte aligned)
size_t XTEA::encrypt(ubyte* data, size_t len, ubyte* result)
{
    size_t output_len = padding(data, len, result);

    for (size_t i = 0; i < (output_len + 4) / 8; i++)
    {
        int v0 = Utility::readIntFromBytes<int>(result + (i * 8));
        int v1 = Utility::readIntFromBytes<int>(result + (i * 8 + 4));

        int sum = 0;

        for (int j = 0; j < m_rounds; j++)
        {
            v0 += ((v1 << 4 ^ (int)((uint)v1 >> 5)) + v1) ^ (sum + m_key[sum & 3]);
            sum += DELTA;
            v1 += ((v0 << 4 ^ (int)((uint)v0 >> 5)) + v0) ^ (sum + m_key[(int)((uint)sum >> 11) & 3]);
        }

        Utility::writeIntToBytes<int>(v0, result + (i * 8));
        Utility::writeIntToBytes<int>(v1, result + (i * 8 + 4));
    }

    return output_len;
}

// Decrypt given ubyte array (length to be crypted must be 8 ubyte aligned)
size_t XTEA::decrypt(ubyte* data, size_t len, ubyte* result)
{
    assert(len > 0 && len % 8 == 0);

    for (size_t i = 0; i < len; i++)
        result[i] = data[i];

    for (size_t i = 0; i < len / 8; i++)
    {
        int v0 = Utility::readIntFromBytes<int>(result + (i * 8));
        int v1 = Utility::readIntFromBytes<int>(result + (i * 8 + 4));

        int sum = (int)((uint)DELTA * (uint)m_rounds);

        for (int j = 0; j < m_rounds; j++)
        {
            v1 -= ((v0 << 4 ^ (int)((uint)v0 >> 5)) + v0) ^ (sum + m_key[(int)((uint)sum >> 11) & 3]);
            sum -= DELTA;
            v0 -= ((v1 << 4 ^ (int)((uint)v1 >> 5)) + v1) ^ (sum + m_key[sum & 3]);
        }

        Utility::writeIntToBytes<int>(v0, result + (i * 8));
        Utility::writeIntToBytes<int>(v1, result + (i * 8 + 4));
    }

    return Utility::readIntFromBytes<uint>(result + (len - 4), ENDIAN_BIG);
}

size_t XTEAUtils::encrypt(ubyte* data, size_t len, int key[], ubyte* result)
{
    return handle(data, len, key, result, 1);
}

size_t XTEAUtils::decrypt(ubyte* data, size_t len, int key[], ubyte* result)
{
    return handle(data, len, key, result, 2);
}

size_t XTEAUtils::handle(ubyte* data, size_t len, int key[], ubyte* result, int EorD)
{
    XTEA xtea(key, 64);
    return (EorD == 1) ? xtea.encrypt(data, len, result) : xtea.decrypt(data, len, result);
}

}
}
}
