//
// Created by PaperPlane on 2025/6/9.
//

#include "crypto/ElGamal.h"




// 构造函数，生成ElGamal密钥对
ElGamal::ElGamal(unsigned int keyBits) {
    // 初始化更好的随机种子

    SetSeed(NTL::ZZ(time(nullptr)));  // 128 bits 随机种子

    // 生成大素数 p，确保 p 是安全素数 p = 2q + 1
    NTL::ZZ q;
    do {
        q = NTL::GenPrime_ZZ(keyBits - 1);
        p = 2 * q + 1;
    } while (!NTL::ProbPrime(p));

    // p - 1 = 2 * q
    // 因此质因数为 2 和 q
    std::vector<NTL::ZZ> prime_factors = {NTL::ZZ(2), q};

    // 寻找生成元 g
    bool is_generator;
    long max_attempts = 1000;  // 防止死循环
    long attempts = 0;
    do {
        g = RandomBnd(p - 3) + 2;  // 2 <= g <= p-2

        is_generator = true;
        for (const NTL::ZZ& factor : prime_factors) {
            NTL::ZZ exp = (p - 1) / factor;
            NTL::ZZ res;
            NTL::PowerMod(res, g, exp, p);
            if (res == 1) {
                is_generator = false;
                break;
            }
        }

        attempts++;
        if (attempts > max_attempts) {
            throw std::runtime_error("Failed to find generator g after many attempts.");
        }
    } while (!is_generator);

    // 生成私钥 x，1 <= x <= p-2
    x = RandomBnd(p - 2) + 1;

    // 计算公钥 h = g^x mod p
    NTL::PowerMod(h, g, x, p);
}


ElGamal::ElGamal(NTL::ZZ p,std::pair<NTL::ZZ, NTL::ZZ> Key, std::string option) {
    if(option == "encrypt"){
        this->p=p;
        this->g=Key.first;
        this->h=Key.second;
    }else if(option == "decrypt"){
        this->p=p;
        this->x=Key.first;
    }else{
        std::cerr<<"plesa choose encrypt or decrypt "<<std::endl;
    }

}

// 加密单个ZZ
std::pair<NTL::ZZ, NTL::ZZ> ElGamal::encrypt(const NTL::ZZ& message) const {
    // 检查消息是否小于p
    if (message >= p) {
        std::cerr << "Error: 消息过大，无法加密" << std::endl;
        return {NTL::ZZ(0), NTL::ZZ(0)};
    }
    
    // 生成随机数y，1 <= y < p-1
    NTL::ZZ y = RandomBnd(p - 2) + 1;
    
    // 计算c1 = g^y mod p
    NTL::ZZ c1;
    NTL::PowerMod(c1, g, y, p);
    
    // 计算c2 = m * h^y mod p
    NTL::ZZ hy;
    NTL::PowerMod(hy, h, y, p);
    NTL::ZZ c2 = (message * hy) % p;
    
    return {c1, c2};
}

// 解密单个ZZ
NTL::ZZ ElGamal::decrypt(const std::pair<NTL::ZZ, NTL::ZZ>& ciphertext) const {
    NTL::ZZ c1 = ciphertext.first;
    NTL::ZZ c2 = ciphertext.second;
    
    // 计算 s = c1^x mod p
    NTL::ZZ s;
    NTL::PowerMod(s, c1, x, p);
    
    // 计算 s^(-1) mod p
    NTL::ZZ s_inv;
    InvMod(s_inv, s, p);
    
    // 计算 m = c2 * s^(-1) mod p
    NTL::ZZ message = (c2 * s_inv) % p;
    
    return message;
}

// 对字符串消息进行加密
std::vector<std::pair<NTL::ZZ, NTL::ZZ>> ElGamal::encryptString(const std::string& message) const {
    std::vector<std::pair<NTL::ZZ, NTL::ZZ>> ciphertext;
    
    // 每次处理一个字节
    for (char c : message) {
        NTL::ZZ m = NTL::ZZ(static_cast<unsigned char>(c));
        ciphertext.push_back(encrypt(m));
    }
    
    return ciphertext;
}

// 对加密后的ZZ对向量进行解密
std::string ElGamal::decryptString(const std::vector<std::pair<NTL::ZZ, NTL::ZZ>>& ciphertext) const {
    std::string message;
    
    for (const auto& c : ciphertext) {
        NTL::ZZ m = decrypt(c);
        message.push_back(static_cast<char>(to_long(m)));
    }
    
    return message;
}

// 计算字符串的简单哈希值
NTL::ZZ ElGamal::hashFunction(const std::string& message) const {
    NTL::ZZ hash = NTL::ZZ(0);
    
    // 简单的哈希函数，将每个字符的ASCII值加权求和
    for (size_t i = 0; i < message.length(); ++i) {
        hash = (hash * 256 + NTL::ZZ(static_cast<unsigned char>(message[i]))) % p;
    }
    
    return hash;
}

// ElGamal签名
std::pair<NTL::ZZ, NTL::ZZ> ElGamal::sign(const NTL::ZZ& message) const {
    // 选择随机数k，满足1 <= k < p-1且gcd(k, p-1) = 1
    NTL::ZZ k, gcd;
    NTL::ZZ p_minus_1 = p - 1;
    
    do {
        k = RandomBnd(p_minus_1 - 1) + 1;  // 1 <= k < p-1
        GCD(gcd, k, p_minus_1);
    } while (gcd != 1);
    
    // 计算r = g^k mod p
    NTL::ZZ r;
    NTL::PowerMod(r, g, k, p);
    
    // 计算k的乘法逆元k_inv
    NTL::ZZ k_inv;
    InvMod(k_inv, k, p_minus_1);
    
    // 计算s，使得 message = (x*r + k*s) mod (p-1)
    // 即 s = (message - x*r) * k_inv mod (p-1)
    NTL::ZZ s = (message - x * r) % p_minus_1;
    if (s < 0) {
        s += p_minus_1;
    }
    s = (s * k_inv) % p_minus_1;
    
    return {r, s};
}

// 验证ElGamal签名
bool ElGamal::verify(const NTL::ZZ& message, const std::pair<NTL::ZZ, NTL::ZZ>& signature) const {
    NTL::ZZ r = signature.first;
    NTL::ZZ s = signature.second;
    
    // 检查 0 < r < p 和 0 < s < p-1
    if (r <= 0 || r >= p || s <= 0 || s >= (p - 1)) {
        return false;
    }
    
    // 计算左边 = g^m mod p
    NTL::ZZ left;
    NTL::PowerMod(left, g, message, p);
    
    // 计算右边 = (h^r * r^s) mod p
    NTL::ZZ hr, rs;
    NTL::PowerMod(hr, h, r, p);
    NTL::PowerMod(rs, r, s, p);
    NTL::ZZ right = (hr * rs) % p;
    
    return left == right;
}

// 对消息的哈希值进行签名
std::pair<NTL::ZZ, NTL::ZZ> ElGamal::signHash(const std::string& message) const {
    // 先计算消息的哈希值，然后签名
    NTL::ZZ hash = hashFunction(message);
    return sign(hash);
}

// 验证哈希签名
bool ElGamal::verifyHash(const std::string& message, const std::pair<NTL::ZZ, NTL::ZZ>& signature) const {
    // 计算消息的哈希值，然后验证签名
    NTL::ZZ hash = hashFunction(message);
    return verify(hash, signature);
}
