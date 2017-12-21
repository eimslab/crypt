#pragma once

#include "utils/types.h"
#include "utils/bigint.h"

using namespace std;
using namespace cryption::utils;

namespace cryption
{
namespace base58
{

class Base58
{
private:
    static void init(int*, char*);
    static BigInt decodeToBigInteger(string input);
    static ubyte divmod(ubyte* number, size_t len, int firstDigit, int base, int divisor);
public:
    static string encode(ubyte*, size_t);
    static size_t decode(string const&, ubyte*);
};

}
}
