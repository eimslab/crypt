#pragma once

#include "../utils/typedefine.h"
#include "../utils/utility.h"

namespace crypt {
namespace tea {
namespace xtea {

class XTEA {
private:
    int DELTA;      // XTEA delta constant
    int* m_key;     // Key - 4 integer
    int m_rounds;   // Round to go - 64 are commonly used

    uint padding(ubyte*, uint, ubyte*);
public:
    XTEA(int* _key, int _rounds);

    uint encrypt(ubyte*, uint, ubyte*);
    uint decrypt(ubyte*, uint, ubyte*);
};

}
}
}

