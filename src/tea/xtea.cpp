#include <cassert>
#include "xtea.h"

using namespace crypt::utils;

namespace crypt {
namespace tea {
namespace xtea {

XTEA::XTEA(int* key, int rounds) {
    this->DELTA = 0x9E3779B9;
    this->m_key = key;
    this->m_rounds = rounds;
}

uint XTEA::padding(ubyte* data, uint len, ubyte* output) {
    uint output_len = len;
    while ((output_len + 4) % 8 != 0) output_len++;

    for (uint i = 0; i < len; i++)
        output[i] = data[i];
    for (uint i = len; i < output_len; i++)
        output[i] = 0;

    Utility::writeIntToBytes(len, output + output_len, 2);

    return output_len + 4;
}

// Encrypt given ubyte array (length to be crypted must be 8 ubyte aligned)
uint XTEA::encrypt(ubyte* data, uint len, ubyte* result) {
    uint output_len = padding(data, len, result);

    for (uint i = 0; i < (output_len + 4) / 8; i++) {
        int v0 = Utility::readIntFromBytes(result + (i * 8));
        int v1 = Utility::readIntFromBytes(result + (i * 8 + 4));

        int sum = 0;

        for (int j = 0; j < m_rounds; j++) {
            v0 += ((v1 << 4 ^ (int)((uint)v1 >> 5)) + v1) ^ (sum + m_key[sum & 3]);
            sum += DELTA;
            v1 += ((v0 << 4 ^ (int)((uint)v0 >> 5)) + v0) ^ (sum + m_key[(int)((uint)sum >> 11) & 3]);
        }

        Utility::writeIntToBytes(v0, result + (i * 8));
        Utility::writeIntToBytes(v1, result + (i * 8 + 4));
    }

    return output_len;
}

// Decrypt given ubyte array (length to be crypted must be 8 ubyte aligned)
uint XTEA::decrypt(ubyte* data, uint len, ubyte* result) {
    assert(len % 8 == 0);

    for (uint i = 0; i < len; i++)
        result[i] = data[i];

    for (uint i = 0; i < len / 8; i++) {
        int v0 = Utility::readIntFromBytes(result + (i * 8));
        int v1 = Utility::readIntFromBytes(result + (i * 8 + 4));

        int sum = (int)((uint)DELTA * (uint)m_rounds);

        for (int j = 0; j < m_rounds; j++) {
            v1 -= ((v0 << 4 ^ (int)((uint)v0 >> 5)) + v0) ^ (sum + m_key[(int)((uint)sum >> 11) & 3]);
            sum -= DELTA;
            v0 -= ((v1 << 4 ^ (int)((uint)v1 >> 5)) + v1) ^ (sum + m_key[sum & 3]);
        }

        Utility::writeIntToBytes(v0, result + (i * 8));
        Utility::writeIntToBytes(v1, result + (i * 8 + 4));
    }

    return Utility::readIntFromBytes(result + (len - 4), 2);
}

}
}
}
