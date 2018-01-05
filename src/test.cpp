//#include "rsa.h"
//#include "base58.h"
//#include "tea/xtea.h"
//#include "aes.h"
//#include <iostream>
//
//using namespace cryption::rsa;
//using namespace cryption::base58;
//using namespace cryption::tea::xtea;
//using namespace cryption::aes;

//int main()
//{
//}

//int main_aes()
//{
//    ubyte key[] = "123456789012345678901234";
//    AES128 aes(key, 24);
//
//    ubyte data[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
//
//    ubyte* en = new ubyte[16 + 20];
//    size_t len = aes.encrypt(data, 16, en);
//
//    for (size_t i = 0; i < len; i ++)
//    {
//        cout << (int)en[i] << ", ";
//    }
//    cout << endl;
//
//    ubyte* de = new ubyte[len];
//    len = aes.decrypt(en, len, de);
//
//    for (size_t i = 0; i < len; i ++)
//    {
//        cout << (int)de[i] << ", ";
//    }
//
//    delete[] en;
//    delete[] de;
//
//    return 0;
//}

//int main_aes2()
//{
//    string key = "123456789012345678901234";
//    ubyte data[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
//
//    ubyte* en = new ubyte[16 + 20];
//    size_t len = AESUtils::encrypt<AES128>(data, 16, key, en);
//    for (size_t i = 0; i < len; i ++)
//    {
//        cout << (int)en[i] << ", ";
//    }
//    cout << endl;
//
//
//    ubyte* de = new ubyte[len];
//    len = AESUtils::decrypt<AES128>(en, len, key, de);
//
//    for (size_t i = 0; i < len; i ++)
//    {
//        cout << (int)de[i] << ", ";
//    }
//
//    delete[] en;
//    delete[] de;
//
//    return 0;
//}

//int main_xtea()
//{
//    int key[] = {10, 20, 30, 40};
//    XTEA xtea(key, 64);
//
//    ubyte data[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
//    ubyte* en = new ubyte[12 + 12];
//    size_t len = xtea.encrypt(data, 12, en);
//
//    for (size_t i = 0; i < len; i ++)
//    {
//        cout << (int)en[i] << endl;
//    }
//
//    ubyte* de = new ubyte[len];
//    len = xtea.decrypt(en, len, de);
//
//    for (size_t i = 0; i < len; i ++)
//    {
//        cout << (int)de[i] << endl;
//    }
//
//    delete[] en;
//    delete[] de;
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
//    size_t len = Base58::decode(ret, p);
//
//    cout << string((char*)p, len);
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
//    size_t len = RSA::encrypt(keyPair.privateKey, p, strlen((char*)p), buf);
//
//    ubyte* buf2 = new ubyte[data.length() * 2];
//    len = RSA::decrypt(keyPair.publicKey, buf, len, buf2);
//
//    string ret((char*)buf2);
//    cout << ret;
//
//    delete[] buf;
//    delete[] buf2;
//
//    return 0;
//}
