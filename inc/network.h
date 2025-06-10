//
// Created by PaperPlane on 2025/6/9.
//
/**
 * @file netMessage.h
 * @brief 定义网络传输消息封装类 netMessage，支持加密传输和序列化/反序列化。
 *
 * 该类实现了：
 * - 将消息通过 AES 加密
 * - AES 密钥通过 RSA 加密
 * - 包含消息哈希值用于完整性校验
 * - 支持网络传输序列化 / 反序列化
 * - 提供解包接口 unPack
 *
 * 依赖库:
 * - RSA
 * - AES
 * - <vector>, <string>
 */

#ifndef CRYPTOMESSAGESYSTEM_NETWORK_H
#define CRYPTOMESSAGESYSTEM_NETWORK_H
#include <certificate/person.h>
#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <thread>
#include <atomic>
#include <cstring>
#include <certificate/certificate.h>
#include <random>
#include <crypto/AES.h>
#include <crypto/sha256.h>
/**
 * @brief 向 socket 发送证书（证书字节流）。
 * @param sock Socket 句柄。
 * @param certBytes 证书字节流。
 * @return 是否发送成功。
 */
bool sendCertificate(SOCKET sock, const std::vector<unsigned char>& certBytes);

/**
 * @brief 从 socket 接收证书（证书字节流）。
 * @param sock Socket 句柄。
 * @param certBytes 接收缓冲区，存放证书字节流。
 * @return 是否接收成功。
 */
bool receiveCertificate(SOCKET sock, std::vector<unsigned char>& certBytes);

/**
 * @brief 网络传输消息封装类。
 */
class netMessage {
private:
    std::string AESkey; ///< AES 对称加密密钥（通常被 RSA 加密后传输）。
    std::string msg;    ///< AES 加密后的消息。
    std::string HashRes;///< 消息哈希值（完整性校验）。

public:
    /**
     * @brief 构造函数，使用 RSA 加密 AES 密钥并封装消息。
     * @param msg 明文消息。
     * @param rsa 用于加密 AES 密钥的 RSA 公钥。
     */
    netMessage(std::string msg, RSA rsa);

    /**
     * @brief 默认构造函数。
     */
    netMessage() {}

    /**
     * @brief 将 netMessage 对象序列化为字节流，便于通过网络传输。
     * @return 序列化后的字节流。
     */
    std::vector<unsigned char> serialize();

    /**
     * @brief 从字节流反序列化，恢复 netMessage 对象。
     * @param buffer 输入的字节流。
     */
    void deserialize(const std::vector<unsigned char>& buffer);

    /**
     * @brief 解包消息：使用 RSA 解密 AES 密钥，再用 AES 解密消息。
     * @param rsa RSA 私钥对象（需要私钥 d）。
     * @return 解密后的明文消息。
     */
    std::string unPack(RSA rsa);
};
#endif //CRYPTOMESSAGESYSTEM_NETWORK_H
