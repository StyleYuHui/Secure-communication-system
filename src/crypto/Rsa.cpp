//
// Created by PaperPlane on 2025/6/7.
//


#include "crypto/Rsa.h"


// 构造函数，生成RSA密钥对
RSA::RSA(unsigned int keyBits) {
    SetSeed(NTL::ZZ(time(0)));
    
    // 生成两个大素数 p 和 q
    long primeBits = keyBits / 2;
    p = NTL::GenPrime_ZZ(primeBits);
    q = NTL::GenPrime_ZZ(primeBits);
    
    // 计算模数 n = p * q
    n = p * q;
    
    // 计算欧拉函数值 phi(n) = (p-1) * (q-1)
    phi = (p - 1) * (q - 1);

    e = NTL::ZZ(65537);
    
    // 确保 e 与 phi 互质
    while (GCD(e, phi) != 1) {
        e = e + 2;  // 如果不互质，则递增e直到互质
    }
    
    // 计算私钥指数 d，使得 e * d ≡ 1 (mod phi)
    NTL::ZZ gcd;
    InvMod(d, e, phi);
}

RSA::RSA(NTL::ZZ moudle,NTL::ZZ key,std::string option) {
    n=moudle;
    if (option == "encrypt")
        this->e=key;
    else if (option == "decrypt")
        this->d=key;
    else
        std::cerr<<"plesa choose encrypt or decrypt "<<std::endl;
}

// 加密单个ZZ
NTL::ZZ RSA::encrypt(const NTL::ZZ& message) const {
    // 检查消息是否小于模数n
    if (message >= n) {
        std::cerr << "Error: 消息过大，无法加密" << std::endl;
        return NTL::ZZ(0);
    }
    // 使用公钥(e, n)加密: c = m^e mod n
    NTL::ZZ ciphertext;
    NTL::PowerMod(ciphertext, message, e, n);
    return ciphertext;
}

// 解密单个ZZ
NTL::ZZ RSA::decrypt(const NTL::ZZ& ciphertext) const {
    // 使用私钥(d, n)解密: m = c^d mod n
    NTL::ZZ message;
    NTL::PowerMod(message, ciphertext, d, n);
    return message;
}

// 对字符串消息进行加密
std::vector<NTL::ZZ> RSA::encryptString(const std::string& message) const {
    std::vector<NTL::ZZ> ciphertext;
    
    // 每次处理一个字节
    for (char c : message) {
        NTL::ZZ m = NTL::ZZ(static_cast<unsigned char>(c));
        ciphertext.push_back(encrypt(m));
    }
    
    return ciphertext;
}

// 对加密后的ZZ向量进行解密
std::string RSA::decryptString(const std::vector<NTL::ZZ>& ciphertext) const {
    std::string message;
    
    for (const NTL::ZZ& c : ciphertext) {
        NTL::ZZ m = decrypt(c);
        message.push_back(static_cast<char>(to_long(m)));
    }
    
    return message;
}

// 计算字符串的简单哈希值
NTL::ZZ RSA::hashFunction(const std::string& message) const {
    NTL::ZZ hash = NTL::ZZ(0);
    
    // 简单的哈希函数，将每个字符的ASCII值加权求和
    for (size_t i = 0; i < message.length(); ++i) {
        hash = (hash * 256 + NTL::ZZ(static_cast<unsigned char>(message[i]))) % n;
    }
    
    return hash;
}

// 对消息进行签名
NTL::ZZ RSA::sign(const NTL::ZZ& message) const {
    // 使用私钥(d, n)对消息签名: s = m^d mod n
    NTL::ZZ signature;
    NTL::PowerMod(signature, message, d, n);
    return signature;
}

// 验证签名
bool RSA::verify(const NTL::ZZ& message, const NTL::ZZ& signature) const {
    // 使用公钥(e, n)验证签名: m' = s^e mod n，然后检查m'是否等于m
    NTL::ZZ decrypted_signature;
    NTL::PowerMod(decrypted_signature, signature, e, n);
    return decrypted_signature == message;
}

// 对消息的哈希值进行签名
NTL::ZZ RSA::signHash(const std::string& message) const {
    // 先计算消息的哈希值，然后签名
    NTL::ZZ hash = hashFunction(message);
    return sign(hash);
}

// 验证哈希签名
bool RSA::verifyHash(const std::string& message, const NTL::ZZ& signature) const {
    // 计算消息的哈希值，然后验证签名
    NTL::ZZ hash = hashFunction(message);
    return verify(hash, signature);
}
