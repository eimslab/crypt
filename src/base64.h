#pragma once

#include "utils/types.h"

using namespace std;

namespace cryption
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

    static string encode(ubyte*, uint);
    static uint decode(string const&, ubyte*);
};

}
}
