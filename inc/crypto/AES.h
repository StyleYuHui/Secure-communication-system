//
// Created by PaperPlane on 2025/6/9.
//
/**
 * @file AES.h
 * @brief 定义 AES 对称加密算法类，支持字符串加密和解密。
 *
 * 该类实现了 AES 算法的核心流程，包括:
 * - 密钥扩展
 * - 字节代换
 * - 行移位
 * - 列混淆
 * - 轮密钥加
 *
 * 并提供了完整的加密/解密接口，可直接对字符串进行加密和解密。
 * 内部支持 PKCS#7 填充。
 *
 * 依赖标准库: <vector>, <string>
 */

#ifndef CRYPTOMESSAGESYSTEM_AES_H
#define CRYPTOMESSAGESYSTEM_AES_H
#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <stdexcept>
#include <cstring>
#include <algorithm>
class AES {
private:
    // AES S盒（SubBytes 操作使用）
    static const unsigned char sbox[256];

    // AES 逆S盒（invSubBytes 操作使用）
    static const unsigned char inv_sbox[256];

    // AES Rcon 常量，用于密钥扩展
    static const unsigned char Rcon[11];

    /**
     * @brief 对输入密钥进行密钥扩展，生成轮密钥。
     * @param key 初始密钥（16字节）。
     * @return 扩展后的轮密钥。
     */
    std::vector<unsigned char> keyExpansion(const std::vector<unsigned char>& key);

    /**
     * @brief 字节代换（SubBytes）操作。
     * @param state 状态矩阵。
     */
    void subBytes(unsigned char state[4][4]);

    /**
     * @brief 行移位（ShiftRows）操作。
     * @param state 状态矩阵。
     */
    void shiftRows(unsigned char state[4][4]);

    /**
     * @brief 有限域乘法，用于 MixColumns。
     * @param a 操作数。
     * @param b 操作数。
     * @return 结果。
     */
    unsigned char gmul(unsigned char a, unsigned char b);

    /**
     * @brief 列混淆（MixColumns）操作。
     * @param state 状态矩阵。
     */
    void mixColumns(unsigned char state[4][4]);

    /**
     * @brief 添加轮密钥（AddRoundKey）操作。
     * @param state 状态矩阵。
     * @param roundKey 当前轮使用的轮密钥。
     */
    void addRoundKey(unsigned char state[4][4], const unsigned char* roundKey);

    /**
     * @brief 逆字节代换（InvSubBytes）操作。
     * @param state 状态矩阵。
     */
    void invSubBytes(unsigned char state[4][4]);

    /**
     * @brief 逆行移位（InvShiftRows）操作。
     * @param state 状态矩阵。
     */
    void invShiftRows(unsigned char state[4][4]);

    /**
     * @brief 逆列混淆（InvMixColumns）操作。
     * @param state 状态矩阵。
     */
    void invMixColumns(unsigned char state[4][4]);

    /**
     * @brief 对数据进行 PKCS#7 填充。
     * @param data 原始数据。
     * @return 填充后的数据。
     */
    std::vector<unsigned char> pad(const std::string& data);

    /**
     * @brief 去除 PKCS#7 填充。
     * @param data 填充数据。
     * @return 去除填充后的字符串。
     */
    std::string unpad(const std::vector<unsigned char>& data);

    /**
     * @brief 加密单个块（16字节）。
     * @param state 状态矩阵。
     * @param roundKeys 密钥扩展结果。
     */
    void encryptBlock(unsigned char state[4][4], const unsigned char* roundKeys);

    /**
     * @brief 解密单个块（16字节）。
     * @param state 状态矩阵。
     * @param roundKeys 密钥扩展结果。
     */
    void decryptBlock(unsigned char state[4][4], const unsigned char* roundKeys);
public:
    /**
     * @brief 加密字符串。
     * @param msg 明文字符串。
     * @param key 密钥字符串（16字节）。
     * @return 密文字符串（二进制数据以字符串返回）。
     */
    std::string encrypt(const std::string& msg, const std::string& key);

    /**
     * @brief 解密字符串。
     * @param ciphertext 密文字符串（二进制数据以字符串传入）。
     * @param key 密钥字符串（16字节）。
     * @return 明文字符串。
     */
    std::string decrypt(const std::string& ciphertext, const std::string& key);
};

#endif //CRYPTOMESSAGESYSTEM_AES_H
