#ifndef _Included_CRYPT_BASE58
#define _Included_CRYPT_BASE58

#include "utils/typedefine.h"
#include "utils/bigint.h"

using namespace std;
using namespace crypt::utils;

namespace crypt {
namespace base58 {

class Base58 {
private:
    static void init(int*, char*);
    static BigInt decodeToBigInteger(string input);
    static ubyte divmod(ubyte* number, int len, int firstDigit, int base, int divisor);
public:
    static string encode(ubyte*, uint);
    static uint decode(string const&, ubyte*);
};

}
}

#endif
