#ifndef _Included_CRYPT_BASE64
#define _Included_CRYPT_BASE64

#include "utils/typedefine.h"

using namespace std;

namespace crypt {
namespace base64 {

static const string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

class Base64 {

private:

    static inline bool isBase64Char(unsigned char c) {
        return (isalnum(c) || (c == '+') || (c == '/'));
    }

public:
    static string encode(ubyte*, uint);
    static uint decode(string const&, ubyte*);
};

}
}
#endif
