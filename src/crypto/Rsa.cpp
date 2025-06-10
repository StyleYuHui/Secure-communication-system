#include "crypto/Rsa.h"
#include <NTL/ZZ.h>
#include <ctime>
#include <random>
#include <string>
#include <iostream>
#include <sstream>
#include <iomanip>

using namespace NTL;
using namespace std;

// 构造函数，生成RSA密钥对
RSA::RSA(unsigned int keyBits) {
    // 初始化随机数种子
    SetSeed(ZZ(time(0)));
    
    // 生成两个大素数 p 和 q
    long primeBits = keyBits / 2;
    p = GenPrime_ZZ(primeBits);
    q = GenPrime_ZZ(primeBits);
    
    // 计算模数 n = p * q
    n = p * q;
    
    // 计算欧拉函数值 phi(n) = (p-1) * (q-1)
    phi = (p - 1) * (q - 1);
    
    // 选择公钥指数 e，通常选择65537作为公钥指数
    e = ZZ(65537);
    
    // 确保 e 与 phi 互质
    while (GCD(e, phi) != 1) {
        e = e + 2;  // 如果不互质，则递增e直到互质
    }
    
    // 计算私钥指数 d，使得 e * d ≡ 1 (mod phi)
    ZZ gcd;
    InvMod(d, e, phi);
}

RSA::RSA(NTL::ZZ moudle,NTL::ZZ key,std::string option) {
    n=moudle;
    if (option == "encrypt")
        this->e=key;
    else if (option == "decrypt")
        this->d=key;
    else
        cerr<<"plesa choose encrypt or decrypt "<<endl;
}

// 加密单个ZZ
ZZ RSA::encrypt(const ZZ& message) const {
    // 检查消息是否小于模数n
    if (message >= n) {
        cerr << "Error: 消息过大，无法加密" << endl;
        return ZZ(0);
    }
    // 使用公钥(e, n)加密: c = m^e mod n
    ZZ ciphertext;
    NTL::PowerMod(ciphertext, message, e, n);
    return ciphertext;
}

// 解密单个ZZ
ZZ RSA::decrypt(const ZZ& ciphertext) const {
    // 使用私钥(d, n)解密: m = c^d mod n
    ZZ message;
    NTL::PowerMod(message, ciphertext, d, n);
    return message;
}

// 对字符串消息进行加密
vector<ZZ> RSA::encryptString(const string& message) const {
    vector<ZZ> ciphertext;
    
    // 每次处理一个字节
    for (char c : message) {
        ZZ m = ZZ(static_cast<unsigned char>(c));
        ciphertext.push_back(encrypt(m));
    }
    
    return ciphertext;
}

// 对加密后的ZZ向量进行解密
string RSA::decryptString(const vector<ZZ>& ciphertext) const {
    string message;
    
    for (const ZZ& c : ciphertext) {
        ZZ m = decrypt(c);
        message.push_back(static_cast<char>(to_long(m)));
    }
    
    return message;
}

// 计算字符串的简单哈希值
ZZ RSA::hashFunction(const string& message) const {
    ZZ hash = ZZ(0);
    
    // 简单的哈希函数，将每个字符的ASCII值加权求和
    for (size_t i = 0; i < message.length(); ++i) {
        hash = (hash * 256 + ZZ(static_cast<unsigned char>(message[i]))) % n;
    }
    
    return hash;
}

// 对消息进行签名
ZZ RSA::sign(const ZZ& message) const {
    // 使用私钥(d, n)对消息签名: s = m^d mod n
    ZZ signature;
    NTL::PowerMod(signature, message, d, n);
    return signature;
}

// 验证签名
bool RSA::verify(const ZZ& message, const ZZ& signature) const {
    // 使用公钥(e, n)验证签名: m' = s^e mod n，然后检查m'是否等于m
    ZZ decrypted_signature;
    NTL::PowerMod(decrypted_signature, signature, e, n);
    return decrypted_signature == message;
}

// 对消息的哈希值进行签名
ZZ RSA::signHash(const string& message) const {
    // 先计算消息的哈希值，然后签名
    ZZ hash = hashFunction(message);
    return sign(hash);
}

// 验证哈希签名
bool RSA::verifyHash(const string& message, const ZZ& signature) const {
    // 计算消息的哈希值，然后验证签名
    ZZ hash = hashFunction(message);
    return verify(hash, signature);
}
