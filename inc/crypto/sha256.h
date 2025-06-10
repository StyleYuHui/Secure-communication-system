//
// Created by PaperPlane on 2025/6/7.
//
/**
 * @file sha256.h
 * @brief SHA-256 哈希算法接口声明
 *
 * 提供 sha256 函数用于计算输入字符串的 SHA-256 哈希值。
 *
 * 参考标准：FIPS PUB 180-4 "Secure Hash Standard (SHS)"
 */
#ifndef CRYPTOWEBSYS_SHA256_H
#define CRYPTOWEBSYS_SHA256_H
#include <string>
/**
 * @brief 计算输入字符串的 SHA-256 哈希值。
 *
 * @param input 输入字符串（可以为任意长度的ASCII或二进制数据，按字节处理）。
 * @return std::string 返回对应的 64 个十六进制字符（即 256 bit 哈希值）的字符串。
 *
 * @note 示例用法：
 * @code
 * std::string hash = sha256("abc");
 * std::cout << hash << std::endl;
 * @endcode
 */
std::string sha256(const std::string& input);
#endif //CRYPTOWEBSYS_SHA256_H
