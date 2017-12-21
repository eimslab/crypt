#pragma once

#include <stddef.h>

#include "../utils/types.h"
#include "../utils/utility.h"

namespace cryption
{
namespace tea
{
namespace xtea
{

class XTEA
{
private:
    int DELTA;      // XTEA delta constant
    int* m_key;     // Key - 4 integer
    int m_rounds;   // Round to go - 64 are commonly used

    size_t padding(ubyte*, size_t, ubyte*);
public:
    XTEA(int* _key, int _rounds);

    size_t encrypt(ubyte*, size_t, ubyte*);
    size_t decrypt(ubyte*, size_t, ubyte*);
};

class XTEAUtils
{
public:
    static size_t encrypt(ubyte* data, size_t len, int key[], ubyte* result);
    static size_t decrypt(ubyte* data, size_t len, int key[], ubyte* result);

private:
    static size_t handle(ubyte* data, size_t len, int key[], ubyte* result, int EorD);
};

}
}
}

