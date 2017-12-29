#include <stdlib.h>
#include <string>

#include "base58.h"

namespace cryption
{
namespace base58
{

void Base58::init(int* INDEXES, char* ALPHABET)
{
    for (int i = 0; i < 128; i++)
    {
        INDEXES[i] = -1;
    }

    for (int i = 0; i < 58; i++)
    {
        INDEXES[(int)ALPHABET[i]] = i;
    }
}

string Base58::encode(ubyte* data, size_t len)
{
    if (len == 0)
    {
        return "";
    }

    int INDEXES[128];
    char* ALPHABET = (char*)"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    init(INDEXES, ALPHABET);

    int zeros = 0;
    while ((zeros < (int)len) && (data[zeros] == 0))
    {
        ++zeros;
    }

    ubyte* input = new ubyte[len];
    for (size_t i = 0; i < len; i++)
    {
        input[i] = data[i];
    }

    char* encoded = new char[len * 3];
    size_t outputStart = len * 3;

    for (size_t inputStart = zeros; inputStart < len;)
    {
        encoded[--outputStart] = ALPHABET[divmod(input, len, (int)inputStart, 256, 58)];

        if (input[inputStart] == 0)
        {
            ++inputStart;
        }
    }

    while (outputStart < len * 3 && encoded[outputStart] == ALPHABET[0])
    {
        ++outputStart;
    }

    while (--zeros >= 0)
    {
        encoded[--outputStart] = ALPHABET[0];
    }

    string ret(encoded + outputStart, 0, len * 3 - outputStart);
    delete[] input;
    delete[] encoded;

    return ret;
}

size_t Base58::decode(string const& data, ubyte* result)
{
    if (data.length() == 0)
    {
        result[0] = 0;
        return 0;
    }

    int INDEXES[128];
    char* ALPHABET = (char*)"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    init(INDEXES, ALPHABET);

    ubyte* input58 = new ubyte[data.length()];

    for (size_t i = 0; i < data.length(); ++i)
    {
        char c = data[i];
        int digit = (int)c < 128 ? INDEXES[(int)c] : -1;

        if (digit < 0)
        {
            throw;
        }

        input58[i] = (ubyte)digit;
    }

    size_t zeros = 0;
    while (zeros < data.length() && input58[zeros] == 0)
    {
        ++zeros;
    }

    ubyte* decoded = new ubyte[data.length()];
    size_t outputStart = data.length();

    for (size_t inputStart = zeros; inputStart < data.length();)
    {
        decoded[--outputStart] = divmod(input58, data.length(), (int)inputStart, 58, 256);

        if (input58[inputStart] == 0)
        {
            ++inputStart;
        }
    }

    while (outputStart < data.length() && decoded[outputStart] == 0)
    {
        ++outputStart;
    }

    for (size_t i = outputStart - zeros; i < data.length(); i++)
    {
        result[i - outputStart - zeros] = decoded[i];
    }
    result[data.length() - outputStart - zeros] = 0;

    delete[] input58;
    delete[] decoded;

    return data.length() - outputStart - zeros;
}

BigInt Base58::decodeToBigInteger(string input)
{
    ubyte* buf = new ubyte[input.length() * 2];
    size_t len = Base58::decode(input, buf);

    BigInt bi(buf, (int)len);
    delete[] buf;

    return bi;
}

ubyte Base58::divmod(ubyte* number, size_t len, int firstDigit, int base, int divisor)
{
    int remainder = 0;

    for (size_t i = firstDigit; i < len; i++)
    {
        int digit = (int)number[i] & 0xFF;
        int temp = remainder * base + digit;
        number[i] = (ubyte)(temp / divisor);
        remainder = temp % divisor;
    }

    return (ubyte)remainder;
}

}
}
