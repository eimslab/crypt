#ifndef _Included_CRYPT_RANDOM
#define _Included_CRYPT_RANDOM

#include <random>
#include <limits>

#include "typedefine.h"

using namespace std;

namespace crypt {
namespace utils {

class Random {
private:
    random_device rd;

public:

    uint next(uint min = 0, uint max = numeric_limits<uint>::max()) {
        mt19937 gen(rd());
        std::uniform_int_distribution<uint> dis(min, max);
        return dis(gen);
    }
};

}
}

#endif
