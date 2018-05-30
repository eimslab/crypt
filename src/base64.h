#pragma once

#include "utils/types.h"

using namespace std;

namespace crypto
{
namespace base64
{

class Base64
{
private:

    static inline bool isBase64Char(unsigned char c)
    {
        return (isalnum(c) || (c == '+') || (c == '/'));
    }

public:

    static string encode(ubyte*, size_t);
    static size_t decode(string const&, ubyte*);
};

}
}
