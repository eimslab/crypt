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

// Encodes the given bytes as a base58 string (no checksum is appended).
string Base58::encode(ubyte* data, size_t len)
{
    if (len == 0)
    {
        return "";
    }

    int INDEXES[128];
    char* ALPHABET = (char*)"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    init(INDEXES, ALPHABET);

    // Count leading zeros.
    int zeros = 0;
    while ((zeros < (int)len) && (data[zeros] == 0))
    {
        ++zeros;
    }

    // Convert base-256 digits to base-58 digits (plus conversion to ASCII characters)
    ubyte* input = new ubyte[len];
    for (size_t i = 0; i < len; i++) // since we modify it in-place
    {
        input[i] = data[i];
    }

    char* encoded = new char[len * 3]; // upper bound
    size_t outputStart = len * 3;

    for (size_t inputStart = zeros; inputStart < len;)
    {
        encoded[--outputStart] = ALPHABET[divmod(input, len, (int)inputStart, 256, 58)];

        if (input[inputStart] == 0)
        {
            ++inputStart; // optimization - skip leading zeros
        }
    }

    // Preserve exactly as many leading encoded zeros in output as there were leading zeros in input.
    while (outputStart < len * 3 && encoded[outputStart] == ALPHABET[0])
    {
        ++outputStart;
    }

    while (--zeros >= 0)
    {
        encoded[--outputStart] = ALPHABET[0];
    }

    // Return encoded string (including encoded leading zeros).
    return string(encoded + outputStart, 0, len * 3 - outputStart);
}

// Decodes the given base58 string into the original data bytes.
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

    // Convert the base58-encoded ASCII chars to a base58 byte sequence (base58 digits).
    ubyte* input58 = new ubyte[data.length()];

    for (size_t i = 0; i < data.length(); ++i)
    {
        char c = data[i];
        int digit = (int)c < 128 ? INDEXES[(int)c] : -1;

        if (digit < 0)
        {
            throw;// exception("Illegal character.");
        }

        input58[i] = (ubyte)digit;
    }

    // Count leading zeros.
    size_t zeros = 0;
    while (zeros < data.length() && input58[zeros] == 0)
    {
        ++zeros;
    }

    // Convert base-58 digits to base-256 digits.
    ubyte* decoded = new ubyte[data.length()];
    size_t outputStart = data.length();

    for (size_t inputStart = zeros; inputStart < data.length();)
    {
        decoded[--outputStart] = divmod(input58, data.length(), (int)inputStart, 58, 256);

        if (input58[inputStart] == 0)
        {
            ++inputStart; // optimization - skip leading zeros
        }
    }

    // Ignore extra leading zeroes that were added during the calculation.
    while (outputStart < data.length() && decoded[outputStart] == 0)
    {
        ++outputStart;
    }

    // Return decoded data (including original number of leading zeros).
    for (size_t i = outputStart - zeros; i < data.length(); i++)
    {
        result[i - outputStart - zeros] = decoded[i];
    }
    result[data.length() - outputStart - zeros] = 0;

    return data.length() - outputStart - zeros;
}

/*
Divides a number, represented as an array of bytes each containing a single digit
in the specified base, by the given divisor. The given number is modified in-place
to contain the quotient, and the return value is the remainder.
*/
BigInt Base58::decodeToBigInteger(string input)
{
    ubyte* buf = new ubyte[input.length() * 2];
    size_t len = Base58::decode(input, buf);
    return BigInt(buf, (int)len);
}

ubyte Base58::divmod(ubyte* number, size_t len, int firstDigit, int base, int divisor)
{
    // this is just long division which accounts for the base of the input digits
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
