//
// Created by PaperPlane on 2025/6/8.
//
/**
 * @file person.h
 * @brief 定义 person 类，表示拥有 RSA 和 ElGamal 密钥对的用户。
 *
 * 包含用户身份信息（姓名）、RSA 密钥、ElGamal 密钥。
 * 提供通过姓名或证书初始化用户对象，并支持访问公钥和密钥信息。
 *
 * 依赖库:
 * - NTL（Number Theory Library），用于大数处理。
 * - RSA、ElGamal 类。
 * - certificate 类。
 */
#ifndef CRYPTOMESSAGESYSTEM_PERSON_H
#define CRYPTOMESSAGESYSTEM_PERSON_H
#pragma once
class certificate;
#include <crypto/Rsa.h>
#include <crypto/ElGamal.h>

// 定义加密块的长度
#define CRYPT_BIE_LENGTH 50

/**
 * @brief RSA 密钥结构体
 */
struct RsaKey {
    NTL::ZZ n; ///< 模数
    NTL::ZZ e; ///< 公钥指数
    NTL::ZZ d; ///< 私钥指数
};

/**
 * @brief ElGamal 密钥结构体
 */
struct ElGamalKey {
    NTL::ZZ p; ///< 素数
    NTL::ZZ g; ///< 生成元
    NTL::ZZ h; ///< 公钥 h = g^x mod p
    NTL::ZZ x; ///< 私钥
};

/**
 * @brief 表示拥有 RSA 和 ElGamal 密钥对的用户。
 */
class person {
    RSA rsa;           ///< RSA 算法对象
    ElGamal elGamal;   ///< ElGamal 算法对象

    std::string name;  ///< 用户姓名
    RsaKey rsaKey;     ///< 用户的 RSA 密钥对
    ElGamalKey elGamalKey; ///< 用户的 ElGamal 密钥对

public:
    /**
     * @brief 通过姓名创建新的用户对象，自动生成 RSA 和 ElGamal 密钥。
     * @param name 用户姓名。
     */
    person(std::string name);

    /**
     * @brief 通过证书创建用户对象，提取证书中的公钥信息。
     * @param cer 用户的数字证书。
     */
    person(certificate cer);

    /**
     * @brief 获取 RSA 公钥指数 e。
     * @return RSA 公钥指数 e。
     */
    NTL::ZZ getRsaPubKey() const { return rsaKey.e; }

    /**
     * @brief 获取 RSA 模数 n。
     * @return RSA 模数 n。
     */
    NTL::ZZ getRsaMoudle() const { return rsaKey.n; }

    /**
     * @brief 获取 ElGamal 公钥 h。
     * @return ElGamal 公钥 h。
     */
    NTL::ZZ getEgPubKey() const { return elGamalKey.h; }

    /**
     * @brief 获取 ElGamal 素数 p。
     * @return ElGamal 素数 p。
     */
    NTL::ZZ getEgPrime() const { return elGamalKey.p; }

    /**
     * @brief 获取 ElGamal 生成元 g。
     * @return ElGamal 生成元 g。
     */
    NTL::ZZ getEgGenerator() const { return elGamalKey.g; }

    /**
     * @brief 获取用户姓名。
     * @return 用户姓名。
     */
    std::string getName() { return name; }

    /**
     * @brief 获取 RSA 算法对象（包含完整密钥）。
     * @return RSA 算法对象。
     */
    RSA getRSA() const { return rsa; }

    /**
     * @brief 获取 ElGamal 算法对象（包含完整密钥）。
     * @return ElGamal 算法对象。
     */
    ElGamal getElGamal() { return elGamal; }
};

#endif //CRYPTOMESSAGESYSTEM_PERSON_H
