//
// Created by PaperPlane on 2025/6/9.
//
/**
 * @file ElGamal.h
 * @brief 定义 ElGamal 非对称加密算法类，支持加密、解密、签名、验签。
 *
 * 该类实现了 ElGamal 算法的完整流程，包括:
 * - 密钥生成
 * - 加密 / 解密
 * - 签名 / 验证
 * - 字符串加解密支持
 * - 简单哈希函数（用于签名哈希）
 *
 * 依赖库:
 * - NTL (Number Theory Library)，用于大数操作。
 * - <vector>, <string>, <utility>
 */
#ifndef CRYPTODLL_ELGAMAL_H
#define CRYPTODLL_ELGAMAL_H

#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <string>
#include <vector>
#include <utility>
#include <ctime>
#include <random>




/**
 * @brief ElGamal 非对称加密算法实现类。
 */
class ElGamal {
private:
    NTL::ZZ p; ///< 大素数 p，公参数
    NTL::ZZ g; ///< 生成元 g，公参数
    NTL::ZZ x; ///< 私钥 x
    NTL::ZZ h; ///< 公钥 h = g^x mod p

public:
    /**
     * @brief 构造函数，自动生成素数 p、生成元 g，计算密钥对。
     * @param keyBits 密钥长度（默认 1024 位）。
     */
    ElGamal(unsigned int keyBits = 1024);

    /**
     * @brief 使用已有公钥初始化 ElGamal 对象。
     * @param p 大素数 p。
     * @param PublicKey 公钥对 (g, h)。
     * @param option 预留选项（未具体实现，可用于区分场景）。
     */
    ElGamal(NTL::ZZ p, std::pair<NTL::ZZ, NTL::ZZ> PublicKey, std::string option);

    /**
     * @brief 获取公钥 (p, h)。
     * @return 公钥对。
     */
    std::pair<NTL::ZZ, NTL::ZZ> getPublicKey() const { return {p, h}; }

    /**
     * @brief 获取私钥 x。
     * @return 私钥。
     */
    NTL::ZZ getPrivateKey() const { return x; }

    /**
     * @brief 获取生成元 g。
     * @return 生成元。
     */
    NTL::ZZ getGenerator() const { return g; }

    /**
     * @brief 获取大素数 p。
     * @return 大素数 p。
     */
    NTL::ZZ getPrime() const { return p; }

    /**
     * @brief 加密单个大数 NTL::ZZ。
     * @param message 明文消息。
     * @return 密文对 (c1, c2)。
     */
    std::pair<NTL::ZZ, NTL::ZZ> encrypt(const NTL::ZZ& message) const;

    /**
     * @brief 解密单个大数 NTL::ZZ。
     * @param ciphertext 密文对 (c1, c2)。
     * @return 解密出的明文。
     */
    NTL::ZZ decrypt(const std::pair<NTL::ZZ, NTL::ZZ>& ciphertext) const;

    /**
     * @brief 对字符串进行分块加密。
     * @param message 明文字符串。
     * @return 密文对向量。
     */
    std::vector<std::pair<NTL::ZZ, NTL::ZZ>> encryptString(const std::string& message) const;

    /**
     * @brief 对加密后的字符串密文向量进行解密。
     * @param ciphertext 密文对向量。
     * @return 解密出的字符串。
     */
    std::string decryptString(const std::vector<std::pair<NTL::ZZ, NTL::ZZ>>& ciphertext) const;

    /**
     * @brief 对消息大数进行签名。
     * @param message 待签名消息（大数）。
     * @return 签名对 (r, s)。
     */
    std::pair<NTL::ZZ, NTL::ZZ> sign(const NTL::ZZ& message) const;

    /**
     * @brief 验证大数消息的签名。
     * @param message 原消息（大数）。
     * @param signature 签名对 (r, s)。
     * @return 签名是否有效。
     */
    bool verify(const NTL::ZZ& message, const std::pair<NTL::ZZ, NTL::ZZ>& signature) const;

    /**
     * @brief 对字符串消息的哈希值进行签名。
     * @param message 字符串消息。
     * @return 签名对 (r, s)。
     */
    std::pair<NTL::ZZ, NTL::ZZ> signHash(const std::string& message) const;

    /**
     * @brief 验证字符串消息的哈希签名。
     * @param message 字符串消息。
     * @param signature 签名对 (r, s)。
     * @return 签名是否有效。
     */
    bool verifyHash(const std::string& message, const std::pair<NTL::ZZ, NTL::ZZ>& signature) const;

    /**
     * @brief 计算字符串的简单哈希值，转为 NTL::ZZ，用于签名。
     * @param message 字符串消息。
     * @return 哈希值。
     */
    NTL::ZZ hashFunction(const std::string& message) const;
};

#endif // CRYPTODLL_ELGAMAL_H



