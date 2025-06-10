//
// Created by PaperPlane  on 2025/6/8.
//
/**
 * @file certificate.h
 * @brief 定义了 certificate 类，表示数字证书，包括公钥信息、签名结果及序列化功能。
 *
 * 该类主要用于存储用户的 RSA 和 ElGamal 公钥，签名信息，并提供序列化和反序列化支持，
 * 以便证书可以通过网络传输或持久化存储。
 *
 * 依赖库:
 * - NTL（Number Theory Library），用于大数操作。
 */

#ifndef CRYPTOMESSAGESYSTEM_CERTIFICATE_H
#define CRYPTOMESSAGESYSTEM_CERTIFICATE_H
#pragma once
class person;
#include <string>
#include <vector>
#include <sstream>
#include <crypto/sha256.h>
#include <crypto/ElGamal.h>
#include <NTL/ZZ.h>

class certificate {
    // 证书的 Hash 结果，通常用于保证证书内容的完整性
    std::string HashRes;

    // 持证人姓名
    std::string name;

    // 证书签发者
    std::string Issuer;

    // RSA 公钥，通常包含模数 n 和公钥指数 e
    std::vector<NTL::ZZ> RSA_pub_key;

    // ElGamal 公钥，通常包含素数 p、生成元 g 和公钥 y
    std::vector<NTL::ZZ> EL_pub_key;

    // ElGamal 签名结果，(r, s) 对
    std::pair<NTL::ZZ, NTL::ZZ> EL_sign_res;

public:
    /**
     * @brief 使用 person 对象初始化证书。
     * @param p 包含证书持有者信息的 person 对象。
     */
    certificate(person p);

    /**
     * @brief 默认构造函数。
     */
    certificate() {};

    /**
     * @brief 将证书序列化为字节数组，便于存储或传输。
     * @return 包含证书序列化结果的字节数组。
     */
    std::vector<unsigned char> serialize() const;

    /**
     * @brief 从字节数组中反序列化证书，恢复证书对象状态。
     * @param buffer 包含序列化数据的字节数组。
     */
    void deserialize(const std::vector<unsigned char>& buffer);

    /**
     * @brief 使用 ElGamal 签名算法对证书进行签名。
     * @param elGamal ElGamal 签名算法对象。
     */
    void cerSignIn(ElGamal elGamal);

    /**
     * @brief 验证证书的 ElGamal 签名是否有效。
     * @param elGamal ElGamal 签名算法对象。
     * @return 如果签名有效返回 true，否则返回 false。
     */
    bool cerVerify(ElGamal elGamal);

    /**
     * @brief 获取证书持有者姓名。
     * @return 持有者姓名。
     */
    std::string getName() { return name; }

    /**
     * @brief 获取证书的 Hash 结果。
     * @return Hash 字符串。
     */
    std::string getHashRes() { return HashRes; }

    /**
     * @brief 获取证书中的 RSA 公钥。
     * @return 包含 RSA 公钥的大数向量。
     */
    std::vector<NTL::ZZ> getRSA_pub_key() { return RSA_pub_key; }

    /**
     * @brief 获取证书中的 ElGamal 公钥。
     * @return 包含 ElGamal 公钥的大数向量。
     */
    std::vector<NTL::ZZ> getEL_pub_key() { return EL_pub_key; }

    /**
     * @brief 获取证书的 ElGamal 签名结果。
     * @return 包含 (r, s) 的签名对。
     */
    std::pair<NTL::ZZ, NTL::ZZ> getEL_sign_res() { return EL_sign_res; }
};
#endif //CRYPTOMESSAGESYSTEM_CERTIFICATE_H
