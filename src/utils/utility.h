#ifndef _Included_CRYPT_UTILITY
#define _Included_CRYPT_UTILITY

#include "typedefine.h"

namespace crypt {
namespace utils {

class Utility {
public:
    static void writeIntToBytes(int, ubyte*, int endian = 0);
    static uint readIntFromBytes(ubyte*, int endian = 0);
};

}
}

#endif
