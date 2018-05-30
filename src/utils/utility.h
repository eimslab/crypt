#pragma once

#include "types.h"

namespace crypto
{
namespace utils
{

enum Endian
{
    ENDIAN_LITTLE = 1234,
    ENDIAN_BIG    = 4321
};

class Utility
{
public:
    template <typename T>
    static void writeIntToBytes(T value, ubyte* buffer, Endian endianness = ENDIAN_LITTLE)
    {
        if (endianness == ENDIAN_LITTLE)
        {
            buffer[0] = (ubyte)(value);
            buffer[1] = (ubyte)(value >> 8);
            buffer[2] = (ubyte)(value >> 16);
            buffer[3] = (ubyte)(value >> 24);
        }
        else
        {
            buffer[0] = (ubyte)(value >> 24);
            buffer[1] = (ubyte)(value >> 16);
            buffer[2] = (ubyte)(value >> 8);
            buffer[3] = (ubyte)(value);
        }
    }

    template <typename T>
    static T readIntFromBytes(ubyte* buffer, Endian endianness = ENDIAN_LITTLE)
    {
        if (endianness == ENDIAN_LITTLE)
            return (T)(buffer[0] | buffer[1] << 8 | buffer[2] << 16 | buffer[3] << 24);
        else
            return (T)(buffer[0] << 24 | buffer[1] << 16 | buffer[2] << 8 | buffer[3]);
    }

    template <typename T>
    static void writeShortToBytes(T value, ubyte* buffer, Endian endianness = ENDIAN_LITTLE)
    {
        if (endianness == ENDIAN_LITTLE)
        {
            buffer[0] = (ubyte)(value);
            buffer[1] = (ubyte)(value >> 8);
        }
        else
        {
            buffer[0] = (ubyte)(value >> 8);
            buffer[1] = (ubyte)(value);
        }
    }

    template <typename T>
    static T readShortFromBytes(ubyte* buffer, Endian endianness = ENDIAN_LITTLE)
    {
        if (endianness == ENDIAN_LITTLE)
            return (T)(buffer[0] | buffer[1] << 8);
        else
            return (T)(buffer[0] << 8 | buffer[1]);
    }
};

}
}
