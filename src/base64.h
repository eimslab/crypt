#pragma once

#include "utils/types.h"

using namespace std;

namespace cryption
{
namespace base64
{

static const string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

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
