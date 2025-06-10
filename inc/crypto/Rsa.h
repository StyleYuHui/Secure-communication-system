//
// Created by PaperPlane on 2025/6/9.
//
/**
 * @file RSA.h
 * @brief 定义 RSA 非对称加密算法类，支持加密、解密、签名、验签。
 *
 * 该类实现了 RSA 算法的完整流程，包括:
 * - 密钥生成
 * - 加密 / 解密
 * - 签名 / 验签
 * - 字符串加解密支持
 * - 简单哈希函数（用于签名哈希）
 *
 * 依赖库:
 * - NTL (Number Theory Library)，用于大数操作。
 * - <vector>, <string>
 */
#ifndef CRYPTODLL_RSA_H
#define CRYPTODLL_RSA_H

#include <NTL/ZZ.h>
#include <string>
#include <vector>
#include <ctime>
#include <random>
#include <string>
#include <iostream>
#include <sstream>
#include <iomanip>


class RSA {
private:
    NTL::ZZ n;   ///< 模数 n = p * q
    NTL::ZZ e;   ///< 公钥指数
    NTL::ZZ d;   ///< 私钥指数
    NTL::ZZ p;   ///< 大素数 p
    NTL::ZZ q;   ///< 大素数 q
    NTL::ZZ phi; ///< 欧拉函数 φ(n) = (p-1)*(q-1)

public:
    /**
     * @brief 构造函数，自动生成素数 p、q，计算密钥对。
     * @param keyBits 密钥长度（默认 1024 位）。
     */
    RSA(unsigned int keyBits = 1024);

    /**
     * @brief 使用已有模数和公钥/私钥初始化 RSA 对象。
     * @param moudle 模数 n。
     * @param key 公钥 e 或私钥 d（根据 option）。
     * @param option "public" 表示 key 是公钥 e，"private" 表示 key 是私钥 d。
     */
    RSA(NTL::ZZ moudle, NTL::ZZ key, std::string option);

    /**
     * @brief 获取公钥 e。
     * @return 公钥指数 e。
     */
    NTL::ZZ getPublicKey() const { return e; }

    /**
     * @brief 获取模数 n。
     * @return 模数 n。
     */
    NTL::ZZ getModulus() const { return n; }

    /**
     * @brief 获取私钥 d。
     * @return 私钥指数 d。
     */
    NTL::ZZ getPrivateKey() const { return d; }

    /**
     * @brief 加密单个大数 NTL::ZZ。
     * @param message 明文消息。
     * @return 密文。
     */
    NTL::ZZ encrypt(const NTL::ZZ& message) const;

    /**
     * @brief 解密单个大数 NTL::ZZ。
     * @param ciphertext 密文。
     * @return 解密出的明文。
     */
    NTL::ZZ decrypt(const NTL::ZZ& ciphertext) const;

    /**
     * @brief 对字符串进行分块加密。
     * @param message 明文字符串。
     * @return 密文向量。
     */
    std::vector<NTL::ZZ> encryptString(const std::string& message) const;

    /**
     * @brief 对加密后的字符串密文向量进行解密。
     * @param ciphertext 密文向量。
     * @return 解密出的字符串。
     */
    std::string decryptString(const std::vector<NTL::ZZ>& ciphertext) const;

    /**
     * @brief 对消息大数进行签名。
     * @param message 待签名消息（大数）。
     * @return 签名。
     */
    NTL::ZZ sign(const NTL::ZZ& message) const;

    /**
     * @brief 验证大数消息的签名。
     * @param message 原消息（大数）。
     * @param signature 签名。
     * @return 签名是否有效。
     */
    bool verify(const NTL::ZZ& message, const NTL::ZZ& signature) const;

    /**
     * @brief 对字符串消息的哈希值进行签名。
     * @param message 字符串消息。
     * @return 签名。
     */
    NTL::ZZ signHash(const std::string& message) const;

    /**
     * @brief 验证字符串消息的哈希签名。
     * @param message 字符串消息。
     * @param signature 签名。
     * @return 签名是否有效。
     */
    bool verifyHash(const std::string& message, const NTL::ZZ& signature) const;

    /**
     * @brief 计算字符串的简单哈希值，转为 NTL::ZZ，用于签名。
     * @param message 字符串消息。
     * @return 哈希值。
     */
    NTL::ZZ hashFunction(const std::string& message) const;
};

#endif // CRYPTODLL_RSA_H



