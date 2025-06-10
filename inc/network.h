//
// Created by 31007 on 2025/6/9.
//

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
bool sendCertificate(SOCKET sock, const std::vector<unsigned char>& certBytes);
bool receiveCertificate(SOCKET sock, std::vector<unsigned char>& certBytes);

class netMessage{
    std::string AESkey;
    std::string msg;
    std::string HashRes;
public:
    netMessage(std::string msg,RSA rsa);
    netMessage(){}
    std::vector<unsigned char> serialize() ;
    void deserialize(const std::vector<unsigned char>& buffer);
    std::string unPack(RSA rsa);
};
#endif //CRYPTOMESSAGESYSTEM_NETWORK_H
