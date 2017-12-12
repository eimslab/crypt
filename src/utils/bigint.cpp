#include <math.h>
#include <iostream>

#include "bigint.h"

namespace cryption
{
namespace utils
{

BigInt::BigInt(void)
{
    init();
    dataLength = 1;
}

BigInt::BigInt(uint64 value)
{
    init();

    dataLength = 0;
    while (value != 0 && dataLength < maxLength)
    {
        data[dataLength] = (uint) (value & 0xFFFFFFFF);
        value = value >> 32;
        dataLength++;
    }

    if (dataLength == 0)
    {
        dataLength = 1;
    }
}

BigInt::BigInt(const BigInt &bi)
{
    init();

    dataLength = bi.dataLength;

    for (int i = 0; i < dataLength; i++)
    {
        data[i] = bi.data[i];
    }
}

BigInt::BigInt(const uint inData[], int length)
{
    init();

    dataLength = length;

    if (dataLength > maxLength)
    {
        dataLength = maxLength;
    }

    for (int i = dataLength - 1, j = 0; i >= 0; i--, j++)
    {
        data[j] = inData[i];
    }

    while (dataLength > 1 && data[dataLength - 1] == 0)
    {
        dataLength--;
    }

}

BigInt::BigInt(const uint inData[], int length, bool direct)
{
    init();

    dataLength = length;

    if (dataLength > maxLength)
    {
        dataLength = maxLength;
    }

    if (direct)
    {
        for (int i = 0; i < dataLength; i++)
        {
            data[i] = inData[i];
        }
    }
    else
    {
        for (int i = dataLength - 1, j = 0; i >= 0; i--, j++)
        {
            data[j] = inData[i];
        }
    }

    while (dataLength > 1 && data[dataLength - 1] == 0)
    {
        dataLength--;
    }
}

BigInt::BigInt(const ubyte inData[], int length)
{
    init();
    dataLength = length >> 2;

    int leftOver = length & 0x3;

    if (leftOver != 0)        // length not multiples of 4
    {
        dataLength++;
    }

    if (dataLength > maxLength)
    {
        dataLength = maxLength;
        length = dataLength << 2;
    }

    for (int i = length - 1, j = 0; i >= 3; i -= 4, j++)
    {
        data[j] = (uint) (((uint) inData[i - 3] << 24) + ((uint) inData[i - 2] << 16) + ((uint) inData[i - 1] << 8) + inData[i]);
    }

    if (leftOver == 1)
    {
        data[dataLength - 1] = (uint) inData[0];
    }
    else if (leftOver == 2)
    {
        data[dataLength - 1] = (uint) (((uint) inData[0] << 8) + inData[1]);
    }
    else if (leftOver == 3)
    {
        data[dataLength - 1] = (uint) (((uint) inData[0] << 16) + ((uint) inData[1] << 8) + inData[2]);
    }

    while (dataLength > 1 && data[dataLength - 1] == 0)
    {
        dataLength--;
    }
}

BigInt::~BigInt(void)
{
}

void BigInt::init()
{
    dataLength = 0;
    for (int i = 0; i < maxLength; i++)
    {
        data[i] = 0u;
    }
}

BigInt operator +(const BigInt &bi1, const BigInt &bi2)
{
    BigInt result;
    result.dataLength = (bi1.dataLength > bi2.dataLength) ? bi1.dataLength : bi2.dataLength;

    int64 carry = 0;
    for (int i = 0; i < result.dataLength; i++)
    {
        int64 sum = (int64) bi1.data[i] + (int64) bi2.data[i] + carry;
        carry = sum >> 32;
        result.data[i] = (uint) (sum & 0xFFFFFFFF);
    }

    if (carry != 0 && result.dataLength < maxLength)
    {
        result.data[result.dataLength] = (uint) (carry);
        result.dataLength++;
    }

    while (result.dataLength > 1 && result.data[result.dataLength - 1] == 0)
        result.dataLength--;

    return result;
}

BigInt operator ++(BigInt& bi)
{

    int64 val, carry = 1;
    int index = 0;

    while (carry != 0 && index < maxLength)
    {
        val = (int64) (bi.data[index]);
        val++;

        bi.data[index] = (uint) (val & 0xFFFFFFFF);
        carry = val >> 32;

        index++;
    }

    if (index > bi.dataLength)
        bi.dataLength = index;
    else
    {
        while (bi.dataLength > 1 && bi.data[bi.dataLength - 1] == 0)
            bi.dataLength--;
    }

    return bi;
}

BigInt operator -(const BigInt& bi1, const BigInt& bi2)
{
    BigInt result;

    result.dataLength = (bi1.dataLength > bi2.dataLength) ? bi1.dataLength : bi2.dataLength;

    int64 carryIn = 0;
    for (int i = 0; i < result.dataLength; i++)
    {
        int64 diff;

        diff = (int64) bi1.data[i] - (int64) bi2.data[i] - carryIn;
        result.data[i] = (uint) (diff & 0xFFFFFFFF);

        if (diff < 0)
            carryIn = 1;
        else
            carryIn = 0;
    }

    // roll over to negative
    if (carryIn != 0)
    {
        for (int i = result.dataLength; i < maxLength; i++)
            result.data[i] = 0xFFFFFFFF;
        result.dataLength = maxLength;
    }

    // fixed in v1.03 to give correct datalength for a - (-b)
    while (result.dataLength > 1 && result.data[result.dataLength - 1] == 0)
        result.dataLength--;

    return result;
}

BigInt operator --(BigInt &bi)
{
    int64 val;
    bool carryIn = true;
    int index = 0;

    while (carryIn && index < maxLength)
    {
        val = (int64) (bi.data[index]);
        val--;

        bi.data[index] = (uint) (val & 0xFFFFFFFF);

        if (val >= 0)
            carryIn = false;

        index++;
    }

    if (index > bi.dataLength)
        bi.dataLength = index;

    while (bi.dataLength > 1 && bi.data[bi.dataLength - 1] == 0)
        bi.dataLength--;

    return bi;
}

BigInt operator -=(BigInt &bi1, const BigInt &bi2)
{
    bi1 = bi1 - bi2;
    return bi1;
}

BigInt operator -(const BigInt& bi1)
{
    if (bi1.dataLength == 1 && bi1.data[0] == 0)
    {
        BigInt result;
        return result;
    }

    BigInt result(bi1);

    // 1's complement
    for (int i = 0; i < maxLength; i++)
    {
        result.data[i] = (uint) (~(bi1.data[i]));
    }
    // add one to result of 1's complement
    int64 val, carry = 1;
    int index = 0;

    while (carry != 0 && index < maxLength)
    {
        val = (int64) (result.data[index]);
        val++;

        result.data[index] = (uint) (val & 0xFFFFFFFF);
        carry = val >> 32;

        index++;
    }

    result.dataLength = maxLength;

    while (result.dataLength > 1 && result.data[result.dataLength - 1] == 0)
    {
        result.dataLength--;
    }

    return result;
}

BigInt operator *(BigInt bi1, BigInt bi2)
{
    int lastPos = maxLength - 1;
    bool bi1Neg = false, bi2Neg = false;

    if ((bi1.data[lastPos] & 0x80000000) != 0) // bi1 negative
    {
        bi1Neg = true;
        bi1 = -bi1;
    }

    if ((bi2.data[lastPos] & 0x80000000) != 0)    // bi2 negative
    {
        bi2Neg = true;
        bi2 = -bi2;
    }

    BigInt result;

    for (int i = 0; i < bi1.dataLength; i++)
    {
        if (bi1.data[i] == 0)
            continue;

        uint64 mcarry = 0;
        for (int j = 0, k = i; j < bi2.dataLength; j++, k++)
        {
            uint64 val = ((uint64) bi1.data[i] * (uint64) bi2.data[j]) + (uint64) result.data[k] + mcarry;

            result.data[k] = (uint) (val & 0xFFFFFFFF);
            mcarry = (val >> 32);
        }

        if (mcarry != 0)
        {
            result.data[i + bi2.dataLength] = (uint) mcarry;
        }
    }

    result.dataLength = bi1.dataLength + bi2.dataLength;
    if (result.dataLength > maxLength)
        result.dataLength = maxLength;

    while (result.dataLength > 1 && result.data[result.dataLength - 1] == 0)
        result.dataLength--;

    // overflow check (result is -ve)
    if ((result.data[lastPos] & 0x80000000) != 0)
    {
        if (bi1Neg != bi2Neg && result.data[lastPos] == 0x80000000) // different sign
        {
            // handle the special case where multiplication produces
            // a max negative number in 2's complement.

            if (result.dataLength == 1)
                return result;
            else
            {
                bool isMaxNeg = true;
                for (int i = 0; i < result.dataLength - 1 && isMaxNeg; i++)
                {
                    if (result.data[i] != 0)
                        isMaxNeg = false;
                }

                if (isMaxNeg)
                    return result;
            }
        } else {
            //Multiplication overflow
        }

    }

    // if input has different signs, then result is -ve
    if (bi1Neg != bi2Neg)
        return -result;

    return result;
}

BigInt operator <<(const BigInt &bi1, int offset)
{
    BigInt result = BigInt(bi1);

    if (offset == 0)
    {
        return result;
    }

    result.dataLength = BigInt::shiftLeft(result.data, result.dataLength, offset);

    return result;
}

BigInt operator >>(const BigInt &bi1, int shiftVal)
{
    BigInt result(bi1);

    if (shiftVal == 0)
    {
        return result;
    }

    result.dataLength = BigInt::shiftRight(result.data, result.dataLength, shiftVal);

    int i = 0;
    if ((bi1.data[maxLength - 1] & 0x80000000) != 0)    	// negative
    {
        for (i = maxLength - 1; i >= result.dataLength; i--)
            result.data[i] = 0xFFFFFFFF;

        uint mask = 0x80000000;
        for (i = 0; i < 32; i++)
        {
            if ((result.data[result.dataLength - 1] & mask) != 0)
                break;

            result.data[result.dataLength - 1] |= mask;
            mask >>= 1;
        }
        result.dataLength = maxLength;
    }

    return result;
}

int BigInt::shiftLeft(uint buffer[], int bufLen, int shiftVal)
{
    int shiftAmount = 32;

    int index = bufLen;

    while (index > 1 && buffer[index - 1] == 0)
    {
        index--;
    }

    for (int count = shiftVal; count > 0;)
    {
        if (count < shiftAmount)
        {
            shiftAmount = count;
        }

        uint64 carry = 0;
        for (int i = 0; i < index; i++)
        {
            uint64 val = ((uint64) buffer[i]) << shiftAmount;
            val |= carry;

            buffer[i] = (uint) (val & 0xFFFFFFFF);
            carry = val >> 32;
        }

        if (carry != 0)
        {
            if (index + 1 <= bufLen)
            {
                buffer[index] = (uint) carry;
                index++;
            }
        }
        count -= shiftAmount;
    }

    return index;
}

int BigInt::shiftRight(uint buffer[], int bufLen, int shiftVal)
{
    int shiftAmount = 32;
    int invShift = 0;

    while (bufLen > 1 && buffer[bufLen - 1] == 0)
        bufLen--;

    for (int count = shiftVal; count > 0;)
    {
        if (count < shiftAmount)
        {
            shiftAmount = count;
            invShift = 32 - shiftAmount;
        }

        uint64 carry = 0;
        for (int i = bufLen - 1; i >= 0; i--)
        {
            uint64 val = ((uint64) buffer[i]) >> shiftAmount;
            val |= carry;

            carry = ((uint64) buffer[i]) << invShift;
            buffer[i] = (uint) (val);
        }

        count -= shiftAmount;
    }

    while (bufLen > 1 && buffer[bufLen - 1] == 0)
        bufLen--;

    return bufLen;
}

BigInt operator ~(const BigInt &bi)
{
    BigInt result(bi);

    for (int i = 0; i < maxLength; i++)
    {
        result.data[i] = (uint) (~(bi.data[i]));
    }

    result.dataLength = maxLength;

    while (result.dataLength > 1 && result.data[result.dataLength - 1] == 0)
    {
        result.dataLength--;
    }

    return result;
}

bool operator ==(const BigInt &bi1, const BigInt &bi2)
{
    if (bi1.dataLength != bi2.dataLength)
    {
        return false;
    }

    for (int i = 0; i < bi1.dataLength; i++)
    {
        if (bi1.data[i] != bi2.data[i])
        {
            return false;
        }
    }

    return true;
}

bool operator !=(const BigInt &bi1, const BigInt &bi2)
{
    if (bi1.dataLength != bi2.dataLength)
    {
        return true;
    }

    for (int i = 0; i < bi1.dataLength; i++)
    {
        if (bi1.data[i] != bi2.data[i])
        {
            return true;
        }
    }

    return false;
}

bool operator >(const BigInt &bi1, const BigInt &bi2)
{
    int pos = maxLength - 1;

    // bi1 is negative, bi2 is positive
    if ((bi1.data[pos] & 0x80000000) != 0 && (bi2.data[pos] & 0x80000000) == 0)
        return false;

    // bi1 is positive, bi2 is negative
    else if ((bi1.data[pos] & 0x80000000) == 0 && (bi2.data[pos] & 0x80000000) != 0)
        return true;

    // same sign
    int len = (bi1.dataLength > bi2.dataLength) ? bi1.dataLength : bi2.dataLength;

    for (pos = len - 1; pos >= 0 && bi1.data[pos] == bi2.data[pos]; pos--);

    return ((pos >= 0) && (bi1.data[pos] > bi2.data[pos]));
}

bool operator <(const BigInt &bi1, const BigInt &bi2)
{
    int pos = maxLength - 1;

    // bi1 is negative, bi2 is positive
    if ((bi1.data[pos] & 0x80000000) != 0 && (bi2.data[pos] & 0x80000000) == 0)
        return true;

    // bi1 is positive, bi2 is negative
    else if ((bi1.data[pos] & 0x80000000) == 0 && (bi2.data[pos] & 0x80000000) != 0)
        return false;

    // same sign
    int len = (bi1.dataLength > bi2.dataLength) ? bi1.dataLength : bi2.dataLength;

    for (pos = len - 1; pos >= 0 && bi1.data[pos] == bi2.data[pos]; pos--);

    return ((pos >= 0) && (bi1.data[pos] < bi2.data[pos]));
}

bool operator >=(const BigInt &bi1, const BigInt &bi2)
{
    return (bi1 == bi2 || bi1 > bi2);
}

bool operator <=(const BigInt &bi1, const BigInt &bi2)
{
    return (bi1 == bi2 || bi1 < bi2);
}

void BigInt::multiByteDivide(BigInt bi1, BigInt bi2, BigInt &outQuotient, BigInt& outRemainder)
{
    int i = 0;
    uint result[maxLength];

    for (i = 0; i < maxLength; i++)
    {
        result[i] = 0;
    }

    int remainderLen = bi1.dataLength + 1;

    uint* remainder = new uint[remainderLen];

    for (i = 0; i < remainderLen; i++)
    {
        remainder[i] = 0;
    }

    uint mask = 0x80000000;
    uint val = bi2.data[bi2.dataLength - 1];

    int shift = 0, resultPos = 0;

    while (mask != 0 && (val & mask) == 0)
    {
        shift++;
        mask >>= 1;
    }

    for (i = 0; i < bi1.dataLength; i++)
    {
        remainder[i] = bi1.data[i];
    }

    BigInt::shiftLeft(remainder, remainderLen, shift);

    bi2 = bi2 << shift;

    int j = remainderLen - bi2.dataLength;
    int pos = remainderLen - 1;

    uint64 firstDivisorByte = bi2.data[bi2.dataLength - 1];
    uint64 secondDivisorByte = bi2.data[bi2.dataLength - 2];

    int divisorLen = bi2.dataLength + 1;
    uint* dividendPart = new uint[divisorLen];

    for (i = 0; i < divisorLen; i++)
    {
        dividendPart[i] = 0;
    }

    while (j > 0)
    {
        uint64 dividend = ((uint64) remainder[pos] << 32) + (uint64) remainder[pos - 1];

        uint64 q_hat = dividend / firstDivisorByte;
        uint64 r_hat = dividend % firstDivisorByte;

        bool done = false;
        while (!done)
        {
            done = true;

            if (q_hat == 0x100000000 || (q_hat * secondDivisorByte) > ((r_hat << 32) + remainder[pos - 2]))
            {
                q_hat--;
                r_hat += firstDivisorByte;

                if (r_hat < 0x100000000)
                    done = false;
            }
        }

        int h = 0;
        for (h = 0; h < divisorLen; h++)
            dividendPart[h] = remainder[pos - h];

        BigInt kk(dividendPart, divisorLen);
        BigInt ss = bi2 * (int64) q_hat;

        while (ss > kk)
        {
            q_hat--;
            ss -= bi2;
        }

        BigInt yy = kk - ss;

        for (h = 0; h < divisorLen; h++)
            remainder[pos - h] = yy.data[bi2.dataLength - h];

        result[resultPos++] = (uint) q_hat;

        pos--;
        j--;
    }

    outQuotient.dataLength = resultPos;
    int y = 0;
    for (int x = outQuotient.dataLength - 1; x >= 0; x--, y++)
        outQuotient.data[y] = result[x];
    for (; y < maxLength; y++)
        outQuotient.data[y] = 0;

    while (outQuotient.dataLength > 1 && outQuotient.data[outQuotient.dataLength - 1] == 0)
        outQuotient.dataLength--;

    if (outQuotient.dataLength == 0)
        outQuotient.dataLength = 1;

    outRemainder.dataLength = BigInt::shiftRight(remainder, remainderLen, shift);

    for (y = 0; y < outRemainder.dataLength; y++)
        outRemainder.data[y] = remainder[y];
    for (; y < maxLength; y++)
        outRemainder.data[y] = 0;
    if (remainder != 0)
    {
        delete[] remainder;
    }
    if (dividendPart != 0)
    {
        delete[] dividendPart;
    }
}

void BigInt::singleByteDivide(BigInt bi1, BigInt bi2, BigInt& outQuotient, BigInt& outRemainder)
{
    uint result[maxLength];
    int resultPos = 0;
    int i = 0;
    int j = 0;

    // copy dividend to reminder
    for (i = 0; i < maxLength; i++)
        outRemainder.data[i] = bi1.data[i];
    outRemainder.dataLength = bi1.dataLength;

    while (outRemainder.dataLength > 1 && outRemainder.data[outRemainder.dataLength - 1] == 0)
        outRemainder.dataLength--;

    uint64 divisor = (uint64) bi2.data[0];
    int pos = outRemainder.dataLength - 1;
    uint64 dividend = (uint64) outRemainder.data[pos];

    if (dividend >= divisor)
    {
        uint64 quotient = dividend / divisor;
        result[resultPos++] = (uint) quotient;

        outRemainder.data[pos] = (uint) (dividend % divisor);
    }
    pos--;

    while (pos >= 0)
    {

        dividend = ((uint64) outRemainder.data[pos + 1] << 32) + (uint64) outRemainder.data[pos];
        uint64 quotient = dividend / divisor;
        result[resultPos++] = (uint) quotient;

        outRemainder.data[pos + 1] = 0;
        outRemainder.data[pos--] = (uint) (dividend % divisor);
    }

    outQuotient.dataLength = resultPos;

    for (i = outQuotient.dataLength - 1; i >= 0; i--, j++)
        outQuotient.data[j] = result[i];
    for (; j < maxLength; j++)
        outQuotient.data[j] = 0;

    while (outQuotient.dataLength > 1 && outQuotient.data[outQuotient.dataLength - 1] == 0)
        outQuotient.dataLength--;

    if (outQuotient.dataLength == 0)
        outQuotient.dataLength = 1;

    while (outRemainder.dataLength > 1 && outRemainder.data[outRemainder.dataLength - 1] == 0)
        outRemainder.dataLength--;
}

BigInt operator /(BigInt bi1, BigInt bi2)
{
    BigInt quotient;
    BigInt remainder;

    int lastPos = maxLength - 1;
    bool divisorNeg = false, dividendNeg = false;

    if ((bi1.data[lastPos] & 0x80000000) != 0)     // bi1 negative
    {
        bi1 = -bi1;
        dividendNeg = true;
    }

    if ((bi2.data[lastPos] & 0x80000000) != 0)    // bi2 negative
    {
        bi2 = -bi2;
        divisorNeg = true;
    }

    if (bi1 < bi2)
    {
        return quotient;
    }
    else
    {
        if (bi2.dataLength == 1)
            BigInt::singleByteDivide(bi1, bi2, quotient, remainder);
        else
            BigInt::multiByteDivide(bi1, bi2, quotient, remainder);

        if (dividendNeg != divisorNeg)
            return -quotient;

        return quotient;
    }
}

BigInt operator %(BigInt bi1, BigInt bi2)
{
    BigInt quotient;
    BigInt remainder(bi1);

    int lastPos = maxLength - 1;
    bool dividendNeg = false;

    if ((bi1.data[lastPos] & 0x80000000) != 0)    // bi1 negative
    {
        bi1 = -bi1;
        dividendNeg = true;
    }

    if ((bi2.data[lastPos] & 0x80000000) != 0)     // bi2 negative
        bi2 = -bi2;

    if (bi1 < bi2)
    {
        return remainder;
    }
    else
    {
        if (bi2.dataLength == 1)
            BigInt::singleByteDivide(bi1, bi2, quotient, remainder);
        else
            BigInt::multiByteDivide(bi1, bi2, quotient, remainder);

        if (dividendNeg)
            return -remainder;

        return remainder;
    }
}

BigInt operator &(const BigInt &bi1, const BigInt &bi2)
{
    BigInt result;

    int len = (bi1.dataLength > bi2.dataLength) ? bi1.dataLength : bi2.dataLength;

    for (int i = 0; i < len; i++)
    {
        uint sum = (uint) (bi1.data[i] & bi2.data[i]);
        result.data[i] = sum;
    }

    result.dataLength = maxLength;

    while (result.dataLength > 1 && result.data[result.dataLength - 1] == 0)
        result.dataLength--;

    return result;
}

BigInt operator |(const BigInt& bi1, const BigInt& bi2)
{
    BigInt result;

    int len = (bi1.dataLength > bi2.dataLength) ? bi1.dataLength : bi2.dataLength;

    for (int i = 0; i < len; i++)
    {
        uint sum = (uint) (bi1.data[i] | bi2.data[i]);
        result.data[i] = sum;
    }

    result.dataLength = maxLength;

    while (result.dataLength > 1 && result.data[result.dataLength - 1] == 0)
        result.dataLength--;

    return result;
}

BigInt operator ^(const BigInt& bi1, const BigInt& bi2)
{
    BigInt result;

    int len = (bi1.dataLength > bi2.dataLength) ? bi1.dataLength : bi2.dataLength;

    for (int i = 0; i < len; i++)
    {
        uint sum = (uint) (bi1.data[i] ^ bi2.data[i]);
        result.data[i] = sum;
    }

    result.dataLength = maxLength;

    while (result.dataLength > 1 && result.data[result.dataLength - 1] == 0)
        result.dataLength--;

    return result;
}

int BigInt::jacobi(BigInt a, BigInt b)
{
    if ((b.data[0] & 0x1) == 0)
    {
        //Exception::Jacobi defined only for odd integers
    }

    if (a >= b)
        a = a % b;
    if (a.dataLength == 1 && a.data[0] == 0)
        return 0;  // a == 0
    if (a.dataLength == 1 && a.data[0] == 1)
        return 1;  // a == 1

    if (a < BigInt())
    {
        if ((((b - 1).data[0]) & 0x2) == 0) //if( (((b-1) >> 1).data[0] & 0x1) == 0)
            return jacobi(-a, b);
        else
            return -jacobi(-a, b);
    }

    int e = 0;
    for (int index = 0; index < a.dataLength; index++)
    {
        uint mask = 0x01;

        for (int i = 0; i < 32; i++)
        {
            if ((a.data[index] & mask) != 0)
            {
                index = a.dataLength;      // to break the outer loop
                break;
            }
            mask <<= 1;
            e++;
        }
    }

    BigInt a1 = a >> e;

    int s = 1;
    if ((e & 0x1) != 0 && ((b.data[0] & 0x7) == 3 || (b.data[0] & 0x7) == 5))
        s = -1;

    if ((b.data[0] & 0x3) == 3 && (a1.data[0] & 0x3) == 3)
        s = -s;

    if (a1.dataLength == 1 && a1.data[0] == 1)
        return s;
    else
        return (s * jacobi(b % a1, a1));
}

BigInt BigInt::genPseudoPrime(int bits, int confidence, Random &rnd)
{
    BigInt result;
    bool done = false;

    while (!done)
    {
        result.genRandomBits(bits, rnd);

        result.data[0] |= 0x01;        // make it odd

        // prime test
        done = result.isProbablePrime(confidence, rnd);
    }

    return result;
}

BigInt* BigInt::lucasSequence(BigInt P, BigInt Q, BigInt k, BigInt n)
{
    if (k.dataLength == 1 && k.data[0] == 0)
    {
        BigInt* result = new BigInt[3];

        result[0] = BigInt();
        result[1] = BigInt(2) % n;
        result[2] = BigInt(1) % n;
        return result;
    }

    // calculate constant = b^(2k) / m
    // for Barrett Reduction
    BigInt constant;

    int nLen = n.dataLength << 1;
    constant.data[nLen] = 0x00000001;
    constant.dataLength = nLen + 1;

    constant = constant / n;

    // calculate values of s and t
    int s = 0;

    for (int index = 0; index < k.dataLength; index++)
    {
        uint mask = 0x01;

        for (int i = 0; i < 32; i++)
        {
            if ((k.data[index] & mask) != 0)
            {
                index = k.dataLength;      // to break the outer loop
                break;
            }
            mask <<= 1;
            s++;
        }
    }

    BigInt t = k >> s;

    return lucasSequenceHelper(P, Q, t, n, constant, s);
}

BigInt* BigInt::lucasSequenceHelper(BigInt P, BigInt Q, BigInt k, BigInt n, BigInt constant, int s)
{
    int i = 0;

    BigInt* result = new BigInt[3];

    for (i = 0; i < 3; i++)
    {
        result[i] = 0;
    }

    if ((k.data[0] & 0x00000001) == 0)
    {
        //Exception::"Argument k must be odd."
    }
    int numbits = k.bitCount();

    uint mask = (uint) 0x1 << ((numbits & 0x1F) - 1);

    // v = v0, v1 = v1, u1 = u1, Q_k = Q^0

    BigInt v = 2 % n, Q_k = 1 % n, v1 = P % n, u1 = Q_k;
    bool flag = true;

    for (i = k.dataLength - 1; i >= 0; i--) // iterate on the binary expansion of k
    {
        while (mask != 0)
        {
            if (i == 0 && mask == 0x00000001)        // last bit
                break;

            if ((k.data[i] & mask) != 0)             // bit is set
            {
                // index doubling with addition
                u1 = (u1 * v1) % n;

                v = ((v * v1) - (P * Q_k)) % n;
                v1 = n.barrettReduction(v1 * v1, n, constant);
                v1 = (v1 - ((Q_k * Q) << 1)) % n;

                if (flag)
                    flag = false;
                else
                    Q_k = n.barrettReduction(Q_k * Q_k, n, constant);

                Q_k = (Q_k * Q) % n;
            }
            else
            {
                // index doubling
                u1 = ((u1 * v) - Q_k) % n;

                v1 = ((v * v1) - (P * Q_k)) % n;
                v = n.barrettReduction(v * v, n, constant);
                v = (v - (Q_k << 1)) % n;

                if (flag)
                {
                    Q_k = Q % n;
                    flag = false;
                }
                else
                {
                    Q_k = n.barrettReduction(Q_k * Q_k, n, constant);
                }
            }

            mask >>= 1;
        }
        mask = 0x80000000;
    }

    // at this point u1 = u(n+1) and v = v(n)
    // since the last bit always 1, we need to transform u1 to u(2n+1) and v to v(2n+1)

    u1 = ((u1 * v) - Q_k) % n;
    v = ((v * v1) - (P * Q_k)) % n;
    if (flag)
        flag = false;
    else
        Q_k = n.barrettReduction(Q_k * Q_k, n, constant);

    Q_k = (Q_k * Q) % n;

    for (i = 0; i < s; i++)
    {
        // index doubling
        u1 = (u1 * v) % n;
        v = ((v * v) - (Q_k << 1)) % n;

        if (flag)
        {
            Q_k = Q % n;
            flag = false;
        }
        else
        {
            Q_k = n.barrettReduction(Q_k * Q_k, n, constant);
        }
    }

    result[0] = u1;
    result[1] = v;
    result[2] = Q_k;

    return result;
}

bool BigInt::lucasStrongTestHelper(BigInt thisVal)
{
    int64 D = 5, sign = -1, dCount = 0;
    bool done = false;

    while (!done)
    {
        int Jresult = BigInt::jacobi(D, thisVal);

        if (Jresult == -1)
            done = true;    // J(D, this) = 1
        else
        {
            if ((Jresult == 0) && (BigInt::abs(D) < thisVal)) // divisor found
                return false;

            if (dCount == 20)
            {
                // check for square
                BigInt root = thisVal.sqrt();
                if (root * root == thisVal)
                    return false;
            }

            D = (BigInt::abs(D) + 2) * sign;
            sign = -sign;
        }
        dCount++;
    }

    int64 Q = (1 - D) >> 2;

    BigInt p_add1 = thisVal + 1;
    int s = 0;

    for (int index = 0; index < p_add1.dataLength; index++)
    {
        uint mask = 0x01;

        for (int i = 0; i < 32; i++)
        {
            if ((p_add1.data[index] & mask) != 0)
            {
                index = p_add1.dataLength;      // to break the outer loop
                break;
            }
            mask <<= 1;
            s++;
        }
    }

    BigInt t = p_add1 >> s;

    // calculate constant = b^(2k) / m
    // for Barrett Reduction
    BigInt constant;

    int nLen = thisVal.dataLength << 1;
    constant.data[nLen] = 0x00000001;
    constant.dataLength = nLen + 1;

    constant = constant / thisVal;

    BigInt* lucas = lucasSequenceHelper(1, Q, t, thisVal, constant, 0);
    bool isPrime = false;

    if ((lucas[0].dataLength == 1 && lucas[0].data[0] == 0) || (lucas[1].dataLength == 1 && lucas[1].data[0] == 0))
    {
        // u(t) = 0 or V(t) = 0
        isPrime = true;
    }

    for (int i = 1; i < s; i++)
    {
        if (!isPrime)
        {
            // doubling of index
            lucas[1] = thisVal.barrettReduction(lucas[1] * lucas[1], thisVal, constant);
            lucas[1] = (lucas[1] - (lucas[2] << 1)) % thisVal;

            if ((lucas[1].dataLength == 1 && lucas[1].data[0] == 0))
                isPrime = true;
        }

        lucas[2] = thisVal.barrettReduction(lucas[2] * lucas[2], thisVal, constant);     //Q^k
    }

    if (isPrime)    // additional checks for composite numbers
    {
        // If n is prime and gcd(n, Q) == 1, then
        // Q^((n+1)/2) = Q * Q^((n-1)/2) is congruent to (Q * J(Q, n)) mod n

        BigInt g = thisVal.gcd(Q);
        if (g.dataLength == 1 && g.data[0] == 1)        // gcd(this, Q) == 1
        {
            if ((lucas[2].data[maxLength - 1] & 0x80000000) != 0)
                lucas[2] = lucas[2] + thisVal;

            BigInt temp = (Q * BigInt::jacobi(Q, thisVal)) % thisVal;
            if ((temp.data[maxLength - 1] & 0x80000000) != 0)
                temp = temp + thisVal;

            if (lucas[2] != temp)
                isPrime = false;
        }
    }

    if (lucas != 0)
    {
        delete lucas;
    }

    return isPrime;
}

BigInt BigInt::max(const BigInt &bi)
{
    if (*this > bi)
        return BigInt(*this);
    else
        return BigInt(bi);
}

BigInt BigInt::min(const BigInt &bi)
{
    if (*this < bi)
        return BigInt(*this);
    else
        return BigInt(bi);
}

BigInt BigInt::abs()
{
    if ((this->data[maxLength - 1] & 0x80000000) != 0)
        return -(*this);
    else
        return BigInt(*this);
}

BigInt BigInt::modPow(BigInt exp, BigInt n)
{
    if ((exp.data[maxLength - 1] & 0x80000000) != 0)
    {
        //Exception::"Positive exponents only."
    }

    BigInt resultNum = 1;
    BigInt tempNum;
    bool thisNegative = false;

    if ((this->data[maxLength - 1] & 0x80000000) != 0)  // negative this
    {
        tempNum = (-(*this)) % n;
        thisNegative = true;
    }
    else
        tempNum = (*this) % n;  // ensures (tempNum * tempNum) < b^(2k)

    if ((n.data[maxLength - 1] & 0x80000000) != 0)   // negative n
        n = -n;

    // calculate constant = b^(2k) / m
    BigInt constant;

    int i = n.dataLength << 1;
    constant.data[i] = 0x00000001;
    constant.dataLength = i + 1;

    constant = constant / n;
    int totalBits = exp.bitCount();
    int count = 0;

    // perform squaring and multiply exponentiation
    for (int pos = 0; pos < exp.dataLength; pos++)
    {
        uint mask = 0x01;

        for (int index = 0; index < 32; index++)
        {
            if ((exp.data[pos] & mask) != 0)
                resultNum = barrettReduction(resultNum * tempNum, n, constant);

            mask <<= 1;

            tempNum = barrettReduction(tempNum * tempNum, n, constant);

            if (tempNum.dataLength == 1 && tempNum.data[0] == 1)
            {
                if (thisNegative && (exp.data[0] & 0x1) != 0)    //odd exp
                    return -resultNum;
                return resultNum;
            }

            count++;
            if (count == totalBits)
                break;
        }
    }

    if (thisNegative && (exp.data[0] & 0x1) != 0)    //odd exp
        return -resultNum;

    return resultNum;
}

BigInt BigInt::barrettReduction(BigInt x, BigInt n, BigInt constant)
{
    int k = n.dataLength, kPlusOne = k + 1, kMinusOne = k - 1;
    int i = 0, j = 0;
    BigInt q1;

    // q1 = x / b^(k-1)
    for (i = kMinusOne, j = 0; i < x.dataLength; i++, j++)
        q1.data[j] = x.data[i];

    q1.dataLength = x.dataLength - kMinusOne;
    if (q1.dataLength <= 0)
        q1.dataLength = 1;

    BigInt q2 = q1 * constant;
    BigInt q3;

    // q3 = q2 / b^(k+1)
    for (i = kPlusOne, j = 0; i < q2.dataLength; i++, j++)
        q3.data[j] = q2.data[i];
    q3.dataLength = q2.dataLength - kPlusOne;
    if (q3.dataLength <= 0)
        q3.dataLength = 1;

    BigInt r1;
    int lengthToCopy = (x.dataLength > kPlusOne) ? kPlusOne : x.dataLength;
    for (i = 0; i < lengthToCopy; i++)
        r1.data[i] = x.data[i];
    r1.dataLength = lengthToCopy;

    BigInt r2;
    for (i = 0; i < q3.dataLength; i++)
    {
        if (q3.data[i] == 0)
            continue;

        uint64 mcarry = 0;
        int t = i;
        for (int j = 0; j < n.dataLength && t < kPlusOne; j++, t++)
        {
            // t = i + j
            uint64 val = ((uint64) q3.data[i] * (uint64) n.data[j]) + (uint64) r2.data[t] + mcarry;

            r2.data[t] = (uint) (val & 0xFFFFFFFF);
            mcarry = (val >> 32);
        }

        if (t < kPlusOne)
            r2.data[t] = (uint) mcarry;
    }

    r2.dataLength = kPlusOne;
    while (r2.dataLength > 1 && r2.data[r2.dataLength - 1] == 0)
        r2.dataLength--;

    r1 -= r2;
    if ((r1.data[maxLength - 1] & 0x80000000) != 0)       // negative
    {
        BigInt val;
        val.data[kPlusOne] = 0x00000001;
        val.dataLength = kPlusOne + 1;
        r1 = r1 + val;
    }

    while (r1 >= n)
        r1 -= n;

    return r1;
}

BigInt BigInt::gcd(const BigInt &bi)
{
    BigInt x;
    BigInt y;

    if ((data[maxLength - 1] & 0x80000000) != 0)     // negative
        x = -(*this);
    else
        x = *this;

    if ((bi.data[maxLength - 1] & 0x80000000) != 0)     // negative
        y = -bi;
    else
        y = bi;

    BigInt g = y;

    while (x.dataLength > 1 || (x.dataLength == 1 && x.data[0] != 0))
    {
        g = x;
        x = y % x;
        y = g;
    }

    return g;
}

void BigInt::genRandomBits(int bits, Random &rnd)
{
    int dwords = bits >> 5;
    int remBits = bits & 0x1F;
    int i = 0;

    if (remBits != 0)
        dwords++;

    if (dwords > maxLength)
    {
        //Exception::"Number of required bits > maxLength."
    }

    for (i = 0; i < dwords; i++)
    {
        data[i] = rnd.next();
    }

    for (i = dwords; i < maxLength; i++)
        data[i] = 0;

    if (remBits != 0) {
        uint mask = (uint) (0x01 << (remBits - 1));
        data[dwords - 1] |= mask;

        mask = (uint) (0xFFFFFFFF >> (32 - remBits));
        data[dwords - 1] &= mask;
    } else
        data[dwords - 1] |= 0x80000000;

    dataLength = dwords;

    if (dataLength == 0)
        dataLength = 1;
}

int BigInt::bitCount()
{
    while (dataLength > 1 && data[dataLength - 1] == 0)
    {
        dataLength--;
    }

    uint value = data[dataLength - 1];

    uint mask = 0x80000000;

    int bits = 32;

    while (bits > 0 && (value & mask) == 0)
    {
        bits--;
        mask >>= 1;
    }

    bits += ((dataLength - 1) << 5);

    return bits;
}

bool BigInt::fermatLittleTest(int confidence, Random &rnd)
{
    BigInt thisVal;

    if ((this->data[maxLength - 1] & 0x80000000) != 0)        // negative
        thisVal = -(*this);
    else
        thisVal = *this;

    if (thisVal.dataLength == 1)
    {
        // test small numbers
        if (thisVal.data[0] == 0 || thisVal.data[0] == 1)
            return false;
        else if (thisVal.data[0] == 2 || thisVal.data[0] == 3)
            return true;
    }

    if ((thisVal.data[0] & 0x1) == 0)     // even numbers
        return false;

    int bits = thisVal.bitCount();
    BigInt a;
    BigInt p_sub1 = thisVal - BigInt(1);

    for (int round = 0; round < confidence; round++)
    {
        bool done = false;

        while (!done)       // generate a < n
        {
            int testBits = 0;

            // make sure "a" has at least 2 bits
            testBits = rnd.next(2, bits - 1);

            a.genRandomBits(testBits, rnd);

            int byteLen = a.dataLength;

            // make sure "a" is not 0
            if (byteLen > 1 || (byteLen == 1 && a.data[0] != 1))
                done = true;
        }

        // check whether a factor exists (fix for version 1.03)
        BigInt gcdTest = a.gcd(thisVal);
        if (gcdTest.dataLength == 1 && gcdTest.data[0] != 1)
            return false;

        // calculate a^(p-1) mod p
        BigInt expResult = a.modPow(p_sub1, thisVal);

        int resultLen = expResult.dataLength;

        // is NOT prime is a^(p-1) mod p != 1

        if (resultLen > 1 || (resultLen == 1 && expResult.data[0] != 1))
        {
            return false;
        }
    }

    return true;
}

bool BigInt::rabinMillerTest(int confidence, Random &rnd)
{
    BigInt thisVal;

    if ((this->data[maxLength - 1] & 0x80000000) != 0)        // negative
        thisVal = -(*this);
    else
        thisVal = *this;

    if (thisVal.dataLength == 1)
    {
        // test small numbers
        if (thisVal.data[0] == 0 || thisVal.data[0] == 1)
            return false;
        else if (thisVal.data[0] == 2 || thisVal.data[0] == 3)
            return true;
    }

    if ((thisVal.data[0] & 0x1) == 0)     // even numbers
        return false;

    // calculate values of s and t
    BigInt p_sub1 = thisVal - BigInt(1);
    int s = 0;

    for (int index = 0; index < p_sub1.dataLength; index++)
    {
        uint mask = 0x01;

        for (int i = 0; i < 32; i++)
        {
            if ((p_sub1.data[index] & mask) != 0)
            {
                index = p_sub1.dataLength;      // to break the outer loop
                break;
            }
            mask <<= 1;
            s++;
        }
    }

    BigInt t = p_sub1 >> s;

    int bits = thisVal.bitCount();
    BigInt a;

    for (int round = 0; round < confidence; round++)
    {
        bool done = false;

        while (!done)        // generate a < n
        {
            int testBits = 0;

            //make sure "a" has at least 2 bits
            testBits = rnd.next(2, bits - 1);
            a.genRandomBits(testBits, rnd);
            int byteLen = a.dataLength;

            // make sure "a" is not 0
            if (byteLen > 1 || (byteLen == 1 && a.data[0] != 1))
                done = true;
        }

        // check whether a factor exists (fix for version 1.03)
        BigInt gcdTest = a.gcd(thisVal);
        if (gcdTest.dataLength == 1 && gcdTest.data[0] != 1)
            return false;

        BigInt b = a.modPow(t, thisVal);

        bool result = false;

        if (b.dataLength == 1 && b.data[0] == 1)         // a^t mod p = 1
            result = true;

        for (int j = 0; result == false && j < s; j++)
        {
            if (b == p_sub1)   // a^((2^j)*t) mod p = p-1 for some 0 <= j <= s-1
            {
                result = true;
                break;
            }

            b = (b * b) % thisVal;
        }

        if (result == false)
            return false;
    }

    return true;
}

bool BigInt::solovayStrassenTest(int confidence, Random &rnd)
{
    BigInt thisVal;

    if ((this->data[maxLength - 1] & 0x80000000) != 0)        // negative
        thisVal = -(*this);
    else
        thisVal = (*this);

    if (thisVal.dataLength == 1)
    {
        // test small numbers
        if (thisVal.data[0] == 0 || thisVal.data[0] == 1)
            return false;
        else if (thisVal.data[0] == 2 || thisVal.data[0] == 3)
            return true;
    }

    if ((thisVal.data[0] & 0x1) == 0)     // even numbers
        return false;

    int bits = thisVal.bitCount();
    BigInt a;
    BigInt p_sub1 = thisVal - 1;
    BigInt p_sub1_shift = p_sub1 >> 1;

    //Random rand;

    for (int round = 0; round < confidence; round++)
    {
        bool done = false;

        while (!done)        // generate a < n
        {
            int testBits = 0;

            // make sure "a" has at least 2 bits

            testBits = rnd.next(2, bits - 1);

            a.genRandomBits(testBits, rnd);

            int byteLen = a.dataLength;

            // make sure "a" is not 0
            if (byteLen > 1 || (byteLen == 1 && a.data[0] != 1))
                done = true;
        }

        // check whether a factor exists (fix for version 1.03)
        BigInt gcdTest = a.gcd(thisVal);
        if (gcdTest.dataLength == 1 && gcdTest.data[0] != 1)
            return false;

        // calculate a^((p-1)/2) mod p

        BigInt expResult = a.modPow(p_sub1_shift, thisVal);
        if (expResult == p_sub1)
            expResult = -1;

        // calculate Jacobi symbol
        BigInt jacob = jacobi(a, thisVal);

        // if they are different then it is not prime
        if (expResult != jacob)
            return false;
    }

    return true;
}

bool BigInt::lucasStrongTest()
{
    BigInt thisVal;

    if ((this->data[maxLength - 1] & 0x80000000) != 0)        // negative
        thisVal = -(*this);
    else
        thisVal = *this;

    if (thisVal.dataLength == 1)
    {
        // test small numbers
        if (thisVal.data[0] == 0 || thisVal.data[0] == 1)
            return false;
        else if (thisVal.data[0] == 2 || thisVal.data[0] == 3)
            return true;
    }

    if ((thisVal.data[0] & 0x1) == 0)     // even numbers
        return false;

    return lucasStrongTestHelper(thisVal);
}

bool BigInt::isProbablePrime(int confidence, Random &rnd)
{
    BigInt thisVal;

    if ((this->data[maxLength - 1] & 0x80000000) != 0)        // negative
        thisVal = -(*this);
    else
        thisVal = *this;

    // test for divisibility by primes
    for (int p = 0; p < NumberPrimes; p++)
    {
        BigInt divisor = Primes[p];

        if (divisor >= thisVal)
            break;

        BigInt resultNum = thisVal % divisor;
        if (resultNum.intValue() == 0)
        {
            return false;
        }
    }

    return (thisVal.rabinMillerTest(confidence, rnd));
}

bool BigInt::isProbablePrime()
{
    BigInt thisVal;

    if ((this->data[maxLength - 1] & 0x80000000) != 0)        // negative
        thisVal = -(*this);
    else
        thisVal = (*this);

    if (thisVal.dataLength == 1)
    {
        // test small numbers
        if (thisVal.data[0] == 0 || thisVal.data[0] == 1)
            return false;
        else if (thisVal.data[0] == 2 || thisVal.data[0] == 3)
            return true;
    }

    if ((thisVal.data[0] & 0x1) == 0)     // even numbers
        return false;

    // test for divisibility by primes < 2000
    for (int p = 0; p < NumberPrimes; p++)
    {
        BigInt divisor = Primes[p];

        if (divisor >= thisVal)
            break;

        BigInt resultNum = thisVal % divisor;
        if (resultNum.intValue() == 0)
        {
            return false;
        }
    }

    // Perform BASE 2 Rabin-Miller Test

    // calculate values of s and t
    BigInt p_sub1 = thisVal - BigInt(1);
    int s = 0;

    for (int index = 0; index < p_sub1.dataLength; index++)
    {
        uint mask = 0x01;

        for (int i = 0; i < 32; i++)
        {
            if ((p_sub1.data[index] & mask) != 0)
            {
                index = p_sub1.dataLength;      // to break the outer loop
                break;
            }
            mask <<= 1;
            s++;
        }
    }

    BigInt t = p_sub1 >> s;

    //int bits = thisVal.bitCount();
    BigInt a = 2;

    // b = a^t mod p
    BigInt b = a.modPow(t, thisVal);
    bool result = false;

    if (b.dataLength == 1 && b.data[0] == 1)         // a^t mod p = 1
        result = true;

    for (int j = 0; result == false && j < s; j++)
    {
        if (b == p_sub1)     // a^((2^j)*t) mod p = p-1 for some 0 <= j <= s-1
        {
            result = true;
            break;
        }

        b = (b * b) % thisVal;
    }

    // if number is strong pseudoprime to base 2, then do a strong lucas test
    if (result)
        result = lucasStrongTestHelper(thisVal);

    return result;
}

int BigInt::intValue()
{
    return (int) data[0];
}

uint64 BigInt::longValue()
{
    uint64 val = 0;
    val = (uint64) data[0];
    val |= (uint64) data[1] << 32;

    return val;
}

BigInt BigInt::genCoPrime(int bits, Random &rnd)
{
    bool done = false;
    BigInt result;

    while (!done)
    {
        result.genRandomBits(bits, rnd);

        // gcd test
        BigInt g = result.gcd(*this);
        if (g.dataLength == 1 && g.data[0] == 1)
            done = true;
    }

    return result;
}

BigInt BigInt::modInverse(BigInt modulus)
{
    BigInt p[2] = { BigInt(), BigInt(1) };
    BigInt q[2] = { 0, 0 };    // quotients
    BigInt r[2] = { BigInt(), BigInt() };             // remainders

    int step = 0;

    BigInt a = modulus;
    BigInt b = *this;

    while (b.dataLength > 1 || (b.dataLength == 1 && b.data[0] != 0))
    {
        BigInt quotient;
        BigInt remainder;

        if (step > 1)
        {
            BigInt pval = (p[0] - (p[1] * q[0])) % modulus;
            p[0] = p[1];
            p[1] = pval;
        }

        if (b.dataLength == 1)
            singleByteDivide(a, b, quotient, remainder);
        else
            multiByteDivide(a, b, quotient, remainder);

        q[0] = q[1];
        r[0] = r[1];
        q[1] = quotient;
        r[1] = remainder;

        a = b;
        b = remainder;

        step++;
    }

    if (r[0].dataLength > 1 || (r[0].dataLength == 1 && r[0].data[0] != 1))
    {
        //Exception::"No inverse!"
    }

    BigInt result = ((p[0] - (p[1] * q[0])) % modulus);

    if ((result.data[maxLength - 1] & 0x80000000) != 0)
        result = result + modulus;  // get the least positive modulus

    return result;
}

void BigInt::getBytes(ubyte result[])
{
    int i = 0;
    int pos = 0;
    uint val = 0;

    for (i = dataLength - 1; i >= 0; i--, pos += 4)
    {
        val = data[i];
        result[pos + 3] = (ubyte)(val & 0xFF);
        val >>= 8;
        result[pos + 2] = (ubyte)(val & 0xFF);
        val >>= 8;
        result[pos + 1] = (ubyte)(val & 0xFF);
        val >>= 8;
        result[pos] = (ubyte)(val & 0xFF);
    }
}

int BigInt::getBytesRemovedZero(ubyte result[], int orgLength)
{
    int numBits = bitCount();
    int i = 0;
    int numBytes = numBits >> 3;

    if ((numBits & 0x7) != 0)
        numBytes++;

    for (i = 0; i < orgLength; i++)
    {
        result[i] = 0;
    }

    int pos = 0;

    uint val = data[dataLength - 1];
    bool isHaveData = false;

    uint tempVal = (val >> 24 & 0xFF);
    if (tempVal != 0)
    {
        result[pos++] = (ubyte) tempVal;
        isHaveData = true;
    }

    tempVal = (val >> 16 & 0xFF);
    if (isHaveData || tempVal != 0)
    {
        result[pos++] = (ubyte) tempVal;
        isHaveData = true;
    }

    tempVal = (val >> 8 & 0xFF);
    if (isHaveData || tempVal != 0)
    {
        result[pos++] = (ubyte) tempVal;
        isHaveData = true;
    }

    tempVal = (val & 0xFF);
    if (isHaveData || tempVal != 0)
    {
        result[pos++] = (ubyte) tempVal;
    }

    for (i = dataLength - 2; i >= 0; i--, pos += 4)
    {
        val = data[i];
        result[pos + 3] = (ubyte)(val & 0xFF);
        val >>= 8;
        result[pos + 2] = (ubyte)(val & 0xFF);
        val >>= 8;
        result[pos + 1] = (ubyte)(val & 0xFF);
        val >>= 8;
        result[pos] = (ubyte)(val & 0xFF);
    }

    return numBytes;
}

void BigInt::setBit(uint bitNum)
{
    uint bytePos = bitNum >> 5;             // divide by 32
    char bitPos = (char) (bitNum & 0x1F);    // get the lowest 5 bits

    uint mask = (uint) 1 << bitPos;
    this->data[bytePos] |= mask;

    if (bytePos >= (uint) this->dataLength)
    {
        this->dataLength = (int) bytePos + 1;
    }
}

void BigInt::unsetBit(uint bitNum)
{
    uint bytePos = bitNum >> 5;

    if (bytePos < (uint) this->dataLength)
    {
        char bitPos = (char) (bitNum & 0x1F);

        uint mask = (uint) 1 << bitPos;
        uint mask2 = 0xFFFFFFFF ^ mask;

        this->data[bytePos] &= mask2;

        if (this->dataLength > 1 && this->data[this->dataLength - 1] == 0)
            this->dataLength--;
    }
}

BigInt BigInt::sqrt()
{
    uint numBits = (uint) bitCount();

    if ((numBits & 0x1) != 0)        // odd number of bits
        numBits = (numBits >> 1) + 1;
    else
        numBits = (numBits >> 1);

    uint bytePos = numBits >> 5;
    char bitPos = (char) (numBits & 0x1F);

    uint mask;

    BigInt result;
    if (bitPos == 0)
        mask = 0x80000000;
    else
    {
        mask = (uint) 1 << bitPos;
        bytePos++;
    }
    result.dataLength = (int) bytePos;

    for (int i = (int) bytePos - 1; i >= 0; i--)
    {
        while (mask != 0)
        {
            // guess
            result.data[i] ^= mask;

            // undo the guess if its square is larger than this
            if ((result * result) > *this)
                result.data[i] ^= mask;

            mask >>= 1;
        }
        mask = 0x80000000;
    }

    return result;
}

int64 BigInt::abs(int64 value)
{
    return (value < 0) ? -value : value;
}

}
}
