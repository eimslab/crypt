#pragma once

#include <random>
#include <limits>

#include "types.h"

using namespace std;

namespace crypto
{
namespace utils
{

class Random
{
private:
    random_device rd;

public:

    uint next(uint min = 0, uint max = (numeric_limits<uint>::max)())
    {
        mt19937 gen(rd());
        std::uniform_int_distribution<uint> dis(min, max);
        return dis(gen);
    }
};

}
}
