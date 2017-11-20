#include "rsa.h"
#include "base58.h"
#include "tea/xtea.h"
#include "aes.h"
#include <iostream>

using namespace crypt::rsa;
using namespace crypt::base58;
using namespace crypt::tea::xtea;
using namespace crypt::aes;

//int main()
//{
//}

int main()
{
    ubyte key[] = "123456789012345678901234";
    AES128 aes(key, 24);

    ubyte data[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

    ubyte* en = new ubyte[16 + 20];
    int len = aes.encrypt(data, 16, en);

    for (int i = 0; i < len; i ++)
    {
        cout << (int)en[i] << ", ";
    }
    cout << endl;

    ubyte* de = new ubyte[len];
    len = aes.decrypt(en, len, de);

    for (int i = 0; i < len; i ++)
    {
        cout << (int)de[i] << ", ";
    }

    return 0;
}

//int main_xtea()
//{
//    int key[] = {10, 20, 30, 40};
//    XTEA xtea(key, 64);
//
//    ubyte data[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
//    ubyte* en = new ubyte[12 + 12];
//    int len = xtea.encrypt(data, 12, en);
//
//    for (int i = 0; i < len; i ++)
//    {
//        cout << (int)en[i] << endl;
//    }
//
//    ubyte* de = new ubyte[len];
//    len = xtea.decrypt(en, len, de);
//
//    for (int i = 0; i < len; i ++)
//    {
//        cout << (int)de[i] << endl;
//    }
//
//    return 0;
//}

//int main_xtea()
//{
//    string data = "abcdefg123";
//    ubyte* p = (ubyte*)data.c_str();
//
//    string ret = Base58::encode(p, data.length());
//    cout << ret << endl;
//
//    p = new ubyte[data.length() * 2];
//    int len = Base58::decode(ret, p);
//
//    cout << string((char*)p, 0, len);
//    return 0;
//}

//int main_rsa()
//{
//    RSAKeyPair keyPair = RSA::generateKeyPair(256);
//    cout << keyPair.privateKey << endl;
//    cout << keyPair.publicKey << endl;
//
//    string data = "Copyright: Copyright Digital Mars 2007 - 2011.License:   $(HTTP www.boost.org/LICENSE_1_0.txt, Boost License 1.0).";
//
//    ubyte* buf = new ubyte[data.length() * 2];
//    ubyte* p = (ubyte*)data.c_str();
//    int len = RSA::encrypt(keyPair.privateKey, p, strlen((char*)p), buf);
//
//    ubyte* buf2 = new ubyte[data.length() * 2];
//    len = RSA::decrypt(keyPair.publicKey, buf, len, buf2);
//
//    string ret((char*)buf2);
//    cout << ret;
//
//    return 0;
//}
