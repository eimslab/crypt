#ifndef _Included_CRYPT_UTILITY
#define _Included_CRYPT_UTILITY

#include "typedefine.h"

namespace crypt {
namespace utils {

class Utility {
public:
    template <typename T>
    static void writeIntToBytes(T value, ubyte* buffer, int endian = 0) {
        if (endian < 1 || endian > 2) {
            if (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
                endian = 1;
            else
                endian = 2;
        }

        if (endian == 1) {
            buffer[0] = (ubyte)(value);
            buffer[1] = (ubyte)(value >> 8);
            buffer[2] = (ubyte)(value >> 16);
            buffer[3] = (ubyte)(value >> 24);
        } else {
            buffer[0] = (ubyte)(value >> 24);
            buffer[1] = (ubyte)(value >> 16);
            buffer[2] = (ubyte)(value >> 8);
            buffer[3] = (ubyte)(value);
        }
    }

    template <typename T>
    static T readIntFromBytes(ubyte* buffer, int endian = 0) {
        if (endian < 1 || endian > 2) {
            if (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
                endian = 1;
            else
                endian = 2;
        }

        if (endian == 1)
            return (T)(buffer[0] | buffer[1] << 8 | buffer[2] << 16 | buffer[3] << 24);
        else
            return (T)(buffer[0] << 24 | buffer[1] << 16 | buffer[2] << 8 | buffer[3]);
    }

    template <typename T>
    static void writeShortToBytes(T value, ubyte* buffer, int endian = 0) {
        if (endian < 1 || endian > 2) {
            if (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
                endian = 1;
            else
                endian = 2;
        }

        if (endian == 1) {
            buffer[0] = (ubyte)(value);
            buffer[1] = (ubyte)(value >> 8);
        } else {
            buffer[0] = (ubyte)(value >> 8);
            buffer[1] = (ubyte)(value);
        }
    }

    template <typename T>
    static T readShortFromBytes(ubyte* buffer, int endian = 0) {
        if (endian < 1 || endian > 2) {
            if (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
                endian = 1;
            else
                endian = 2;
        }

        if (endian == 1)
            return (T)(buffer[0] | buffer[1] << 8);
        else
            return (T)(buffer[0] << 8 | buffer[1]);
    }
};

}
}

#endif
