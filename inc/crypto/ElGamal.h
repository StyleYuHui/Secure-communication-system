#ifndef CRYPTODLL_ELGAMAL_H
#define CRYPTODLL_ELGAMAL_H

#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <string>
#include <vector>
#include <utility>



class  ElGamal {
private:
    NTL::ZZ p;         // 大素数p
    NTL::ZZ g;         // 生成元g
    NTL::ZZ x;         // 私钥x
    NTL::ZZ h;         // 公钥h = g^x mod p
    
public:
    // 构造函数
    ElGamal(unsigned int keyBits = 1024);
    ElGamal(NTL::ZZ p,std::pair<NTL::ZZ, NTL::ZZ> PublicKey,std::string option);
    // 获取公钥
    std::pair<NTL::ZZ, NTL::ZZ> getPublicKey() const { return {p, h}; }
    
    // 获取私钥
    NTL::ZZ getPrivateKey() const { return x; }
    
    // 获取生成元
    NTL::ZZ getGenerator() const { return g; }
    
    // 获取素数p
    NTL::ZZ getPrime() const { return p; }
    
    // 加密单个ZZ
    std::pair<NTL::ZZ, NTL::ZZ> encrypt(const NTL::ZZ& message) const;
    
    // 解密单个ZZ
    NTL::ZZ decrypt(const std::pair<NTL::ZZ, NTL::ZZ>& ciphertext) const;
    
    // 对字符串消息进行加密
    std::vector<std::pair<NTL::ZZ, NTL::ZZ>> encryptString(const std::string& message) const;
    
    // 对加密后的ZZ对向量进行解密
    std::string decryptString(const std::vector<std::pair<NTL::ZZ, NTL::ZZ>>& ciphertext) const;
    
    // 签名
    std::pair<NTL::ZZ, NTL::ZZ> sign(const NTL::ZZ& message) const;
    
    // 验证签名
    bool verify(const NTL::ZZ& message, const std::pair<NTL::ZZ, NTL::ZZ>& signature) const;
    
    // 对消息的哈希值进行签名
    std::pair<NTL::ZZ, NTL::ZZ> signHash(const std::string& message) const;
    
    // 验证哈希签名
    bool verifyHash(const std::string& message, const std::pair<NTL::ZZ, NTL::ZZ>& signature) const;
    
    // 计算字符串的简单哈希值
    NTL::ZZ hashFunction(const std::string& message) const;
};

#endif // CRYPTODLL_ELGAMAL_H



