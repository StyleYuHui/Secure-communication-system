//
// Created by 31007 on 2025/6/9.
//

#ifndef CRYPTOMESSAGESYSTEM_AES_H
#define CRYPTOMESSAGESYSTEM_AES_H
#include <iostream>
#include <vector>
#include <stdexcept>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <algorithm>
class AES {
private:
    static const unsigned char sbox[256];
    static const unsigned char inv_sbox[256];
    static const unsigned char Rcon[11];
    std::vector<unsigned char> keyExpansion(const std::vector<unsigned char>& key);
    void subBytes(unsigned char state[4][4]);
    void shiftRows(unsigned char state[4][4]);
    unsigned char gmul(unsigned char a, unsigned char b);
    void mixColumns(unsigned char state[4][4]);
    void addRoundKey(unsigned char state[4][4], const unsigned char* roundKey);
    void invSubBytes(unsigned char state[4][4]);
    void invShiftRows(unsigned char state[4][4]);
    void invMixColumns(unsigned char state[4][4]);
    std::vector<unsigned char> pad(const std::string& data);
    std::string unpad(const std::vector<unsigned char>& data);
    void encryptBlock(unsigned char state[4][4], const unsigned char* roundKeys);
    void decryptBlock(unsigned char state[4][4], const unsigned char* roundKeys);
public:
    std::string encrypt(const std::string& msg, const std::string& key);
    std::string decrypt(const std::string& ciphertext, const std::string& key);
};

#endif //CRYPTOMESSAGESYSTEM_AES_H
