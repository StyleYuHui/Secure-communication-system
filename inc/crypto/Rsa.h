#ifndef CRYPTODLL_RSA_H
#define CRYPTODLL_RSA_H

#include <NTL/ZZ.h>
#include <string>
#include <vector>



class  RSA {
private:
    NTL::ZZ n;     // 模数 n = p * q
    NTL::ZZ e;     // 公钥指数
    NTL::ZZ d;     // 私钥指数
    NTL::ZZ p;     // 大素数p
    NTL::ZZ q;     // 大素数q
    NTL::ZZ phi;   // 欧拉函数φ(n) = (p-1)*(q-1)

public:
    // 构造函数
    RSA(unsigned int keyBits = 1024);
    RSA(NTL::ZZ moudle,NTL::ZZ key,std::string option);

    // 获取公钥
    NTL::ZZ getPublicKey() const { return e; }
    
    // 获取模数
    NTL::ZZ getModulus() const { return n; }

    // 获取私钥
    NTL::ZZ getPrivateKey() const { return d; }

    // 加密单个ZZ
    NTL::ZZ encrypt(const NTL::ZZ& message) const;
    
    // 解密单个ZZ
    NTL::ZZ decrypt(const NTL::ZZ& ciphertext) const;
    
    // 对字符串消息进行加密
    std::vector<NTL::ZZ> encryptString(const std::string& message) const;
    
    // 对加密后的ZZ向量进行解密
    std::string decryptString(const std::vector<NTL::ZZ>& ciphertext) const;
    
    // 签名
    NTL::ZZ sign(const NTL::ZZ& message) const;
    
    // 验证签名
    bool verify(const NTL::ZZ& message, const NTL::ZZ& signature) const;
    
    // 对消息的哈希值进行签名
    NTL::ZZ signHash(const std::string& message) const;
    
    // 验证哈希签名
    bool verifyHash(const std::string& message, const NTL::ZZ& signature) const;
    
    // 计算字符串的简单哈希值
    NTL::ZZ hashFunction(const std::string& message) const;
};

#endif // CRYPTODLL_RSA_H



