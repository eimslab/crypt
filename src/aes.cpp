#include <cassert>
#include "aes.h"

using namespace crypt::utils;

namespace crypt {
namespace aes {

AES::AES(uint Nb, uint Nk, uint Nr, ubyte* key, uint len) {
    this->Nb = Nb;
    this->Nk = Nk;
    this->Nr = Nr;

    w = new uint[Nb * (Nr + 1)];
    dw = new uint[Nb * (Nr + 1)];

    keyExpansion(key, len);
}

uint AES::padding(ubyte* input, uint len, ubyte* output) {
    uint output_len = len;
    while ((output_len + 4) % 16 != 0) output_len++;

    for (uint i = 0; i < len; i++)
        output[i] = input[i];
    for (uint i = len; i < output_len; i++)
        output[i] = 0;

    Utility::writeIntToBytes<uint>(len, output + output_len, ENDIAN_BIG);

    return output_len + 4;
}

void AES::keyExpansion(ubyte* key, uint len) {
    assert(len >= Nk * 4); // At least (Nk * 4) bytes long key must be set.

    const uint rCon[10] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

    uint i = 0;
    while (i < Nk)
    {
        w[i] = key[4 * i] | key[4 * i + 1] << 8 | key[4 * i + 2] << 16 | key[4 * i + 3] << 24;
        i++;
    }

    uint tmp;
    i = Nk;

    while (i < Nb * (Nr + 1))
    {
        tmp = w[i - 1];
        if (i % Nk == 0)
            tmp = subWord(rotWord(tmp)) ^ rCon[i/Nk-1];
        if (Nk > 6)
            if (i % Nk == 4)
                tmp = subWord(tmp);
        w[i] = w[i - Nk] ^ tmp;
        dw[i] = w[i];
        ++i;
    }

    for (i = 0; i < Nk; i++) {
        dw[i] = w[i];
    }

    for (i = 1; i < Nr; ++i)
        invMixColumns(dw + i * Nb);
}

// Need to compute xtimes(a, b). Use table lookup in inverse table (over 0x0b0d090e),
// and isbox(sbox(x)) = x to avoid implementing finite field multiplication in GF(256).
void AES::invMixColumns(uint* s) {
    for (uint col = 0; col < 4; ++col) {
        ubyte a = s[col] & 0xff;
        ubyte b = (s[col] >> 8) & 0xff;
        ubyte c = (s[col] >> 16) & 0xff;
        ubyte d = (s[col] >> 24) & 0xff;
        s[col]  =   (it[sbox[a]] & 0xff)        ^ ((it[sbox[b]] >> 24) & 0xff) ^ ((it[sbox[c]] >> 16) & 0xff) ^ ((it[sbox[d]] >> 8) & 0xff);
        s[col] |= (((it[sbox[a]] >> 8) & 0xff)  ^ (it[sbox[b]] & 0xff)         ^ ((it[sbox[c]] >> 24) & 0xff) ^ ((it[sbox[d]] >> 16) & 0xff)) << 8;
        s[col] |= (((it[sbox[a]] >> 16) & 0xff) ^ ((it[sbox[b]] >> 8) & 0xff)  ^ (it[sbox[c]] & 0xff)         ^ ((it[sbox[d]] >> 24) & 0xff)) << 16;
        s[col] |= (((it[sbox[a]] >> 24) & 0xff) ^ ((it[sbox[b]] >> 16) & 0xff) ^ ((it[sbox[c]] >> 8) & 0xff)  ^ (it[sbox[d]] & 0xff))         << 24;
    }
}

uint AES::rotate(uint n, uint w) {
    assert(n == 0 || n == 1 || n == 2 || n == 3);
    return w << (n * 8) | w >> ((4 - n) * 8);
}

uint AES::subWord(uint w) {
    return sbox[(ubyte)(w)] | sbox[(ubyte)(w >> 8)] << 8 | sbox[(ubyte)(w >> 16)] << 16 | sbox[(ubyte)(w >> 24)] << 24;
}

uint AES::rotWord(uint w) {
    return (w >> 8) | (w << 24);
}

uint AES::encrypt(ubyte* data, uint len, ubyte* result) {
    uint output_len = padding(data, len, result);

    for (uint i = 0; i < output_len / 16; i++) {
        uint* state = (uint*)result + i * 4;
        uint t[4] = { 0, 0, 0, 0 };
        uint round = 0;

        // Add initial round key
        state[0] ^= w[0];
        state[1] ^= w[1];
        state[2] ^= w[2];
        state[3] ^= w[3];
        for (uint i = 0; i < Nb; i++) {
            t[i] = state[i];
        }

        while (round++ < Nr - 1) {
            // SubBytes, ShiftRows and MixColumns
            state[0] = t1[(ubyte)(t[0])] ^ t2[(ubyte)(t[1] >> 8)] ^ t3[(ubyte)(t[2] >> 16)] ^ t4[(ubyte)(t[3] >> 24)] ^ w[round * Nb];
            state[1] = t1[(ubyte)(t[1])] ^ t2[(ubyte)(t[2] >> 8)] ^ t3[(ubyte)(t[3] >> 16)] ^ t4[(ubyte)(t[0] >> 24)] ^ w[round * Nb + 1];
            state[2] = t1[(ubyte)(t[2])] ^ t2[(ubyte)(t[3] >> 8)] ^ t3[(ubyte)(t[0] >> 16)] ^ t4[(ubyte)(t[1] >> 24)] ^ w[round * Nb + 2];
            state[3] = t1[(ubyte)(t[3])] ^ t2[(ubyte)(t[0] >> 8)] ^ t3[(ubyte)(t[1] >> 16)] ^ t4[(ubyte)(t[2] >> 24)] ^ w[round * Nb + 3];
            for (uint i = 0; i < Nb; i++) {
                t[i] = state[i];
            }
        }

        // SubBytes and ShiftRows
        state[0] = sbox[(ubyte)(t[0])] ^ ((sbox[(ubyte)(t[1] >> 8)]) << 8) ^ ((sbox[(ubyte)(t[2] >> 16)]) << 16) ^ ((sbox[(ubyte)(t[3] >> 24)]) << 24) ^ w[round * Nb];
        state[1] = sbox[(ubyte)(t[1])] ^ ((sbox[(ubyte)(t[2] >> 8)]) << 8) ^ ((sbox[(ubyte)(t[3] >> 16)]) << 16) ^ ((sbox[(ubyte)(t[0] >> 24)]) << 24) ^ w[round * Nb + 1];
        state[2] = sbox[(ubyte)(t[2])] ^ ((sbox[(ubyte)(t[3] >> 8)]) << 8) ^ ((sbox[(ubyte)(t[0] >> 16)]) << 16) ^ ((sbox[(ubyte)(t[1] >> 24)]) << 24) ^ w[round * Nb + 2];
        state[3] = sbox[(ubyte)(t[3])] ^ ((sbox[(ubyte)(t[0] >> 8)]) << 8) ^ ((sbox[(ubyte)(t[1] >> 16)]) << 16) ^ ((sbox[(ubyte)(t[2] >> 24)]) << 24) ^ w[round * Nb + 3];
    }

    return output_len;
}

uint AES::decrypt(ubyte* data, uint len, ubyte* result) {
    assert(len % 16 == 0);

    for (uint i = 0; i < len; i++) {
        result[i] = data[i];
    }

    for (uint i = 0; i < len / 16; i++) {
        uint *state = (uint*)result + i * 4;
        uint t[4] = { 0, 0, 0, 0 };

        // Add last round key
        state[0] ^= dw[Nr * Nb];
        state[1] ^= dw[Nr * Nb + 1];
        state[2] ^= dw[Nr * Nb + 2];
        state[3] ^= dw[Nr * Nb + 3];
        for (uint i = 0; i < Nb; i++) {
            t[i] = state[i];
        }

        for (int round = Nr - 1; round > 0; --round) {
            // InvSubBytes, InvShiftRows and InvMixColumns combined
            state[0] = it[(ubyte)(t[0])] ^ rotate(1, it[(ubyte)(t[3] >> 8)]) ^ rotate(2, it[(ubyte)(t[2] >> 16)]) ^ rotate(3, it[(ubyte)(t[1] >> 24)]) ^ dw[round * Nb];
            state[1] = it[(ubyte)(t[1])] ^ rotate(1, it[(ubyte)(t[0] >> 8)]) ^ rotate(2, it[(ubyte)(t[3] >> 16)]) ^ rotate(3, it[(ubyte)(t[2] >> 24)]) ^ dw[round * Nb + 1];
            state[2] = it[(ubyte)(t[2])] ^ rotate(1, it[(ubyte)(t[1] >> 8)]) ^ rotate(2, it[(ubyte)(t[0] >> 16)]) ^ rotate(3, it[(ubyte)(t[3] >> 24)]) ^ dw[round * Nb + 2];
            state[3] = it[(ubyte)(t[3])] ^ rotate(1, it[(ubyte)(t[2] >> 8)]) ^ rotate(2, it[(ubyte)(t[1] >> 16)]) ^ rotate(3, it[(ubyte)(t[0] >> 24)]) ^ dw[round * Nb + 3];
            for (uint i = 0; i < Nb; i++) {
                t[i] = state[i];
            }
        }

        // InvSubBytes and InvShiftRows combined
        state[0] = isbox[(ubyte)(t[0])] ^ ((isbox[(ubyte)(t[3] >> 8)]) << 8) ^ ((isbox[(ubyte)(t[2] >> 16)]) << 16) ^ ((isbox[(ubyte)(t[1] >> 24)]) << 24) ^ dw[0];
        state[1] = isbox[(ubyte)(t[1])] ^ ((isbox[(ubyte)(t[0] >> 8)]) << 8) ^ ((isbox[(ubyte)(t[3] >> 16)]) << 16) ^ ((isbox[(ubyte)(t[2] >> 24)]) << 24) ^ dw[1];
        state[2] = isbox[(ubyte)(t[2])] ^ ((isbox[(ubyte)(t[1] >> 8)]) << 8) ^ ((isbox[(ubyte)(t[0] >> 16)]) << 16) ^ ((isbox[(ubyte)(t[3] >> 24)]) << 24) ^ dw[2];
        state[3] = isbox[(ubyte)(t[3])] ^ ((isbox[(ubyte)(t[2] >> 8)]) << 8) ^ ((isbox[(ubyte)(t[1] >> 16)]) << 16) ^ ((isbox[(ubyte)(t[0] >> 24)]) << 24) ^ dw[3];
    }

    return Utility::readIntFromBytes<uint>(result + (len - 4), ENDIAN_BIG);
}

AES128::AES128(ubyte* key, uint len) : AES(4, 4, 10, key, len) {
}

uint AES128::encrypt(ubyte* data, uint len, ubyte* result) {
    return AES::encrypt(data, len, result);
}

uint AES128::decrypt(ubyte* data, uint len, ubyte* result) {
    return AES::decrypt(data, len, result);
}

AES192::AES192(ubyte* key, uint len) : AES(4, 6, 12, key, len) {
}

uint AES192::encrypt(ubyte* data, uint len, ubyte* result) {
    return AES::encrypt(data, len, result);
}

uint AES192::decrypt(ubyte* data, uint len, ubyte* result) {
    return AES::decrypt(data, len, result);
}

AES256::AES256(ubyte* key, uint len) : AES(4, 8, 14, key, len) {
}

uint AES256::encrypt(ubyte* data, uint len, ubyte* result) {
    return AES::encrypt(data, len, result);
}

uint AES256::decrypt(ubyte* data, uint len, ubyte* result) {
    return AES::decrypt(data, len, result);
}

}
}
