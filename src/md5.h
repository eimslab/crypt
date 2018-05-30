#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <string.h>

using namespace std;

namespace crypto
{

class MD5
{

private:

    #define __uint8  unsigned char
    #define __uint32 unsigned int

    struct MD5_DATA
    {
        unsigned int data[4];

        bool operator < (const MD5_DATA& p) const
        {
            return memcmp(data, p.data, 4 * sizeof(int)) > 0;
        }
    };

    struct md5_context
    {
        __uint32 total[2];
        __uint32 state[4];
        __uint8 buffer[64];
    };

    void md5_starts(struct md5_context* ctx);
    void md5_process(struct md5_context* ctx, __uint8 data[64]);
    void md5_update(struct md5_context* ctx, __uint8* input, size_t length);
    void md5_finish(struct md5_context* ctx, __uint8 digest[16]);

public:

    string GenerateMD5(unsigned char* buffer, size_t bufferlen);
    MD5();
    MD5(const char * md5src);
    MD5(unsigned int* md5src);
    MD5 operator +(MD5 adder);
    bool operator ==(MD5 cmper);
    string ToString();

    unsigned int m_data[4];
};

static MD5 MD5Utils;

}
