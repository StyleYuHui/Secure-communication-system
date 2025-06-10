//
// Created by PaperPlane  on 2025/6/8.
//

#ifndef CRYPTOMESSAGESYSTEM_CERTIFICATE_H
#define CRYPTOMESSAGESYSTEM_CERTIFICATE_H
#pragma once
class person;
#include <string>
#include <crypto/sha256.h>
#include <NTL/ZZ.h>
#include <vector>
#include <sstream>
#include "crypto/ElGamal.h"

class certificate{
    std::string HashRes;
    std::string name;
    std::string Issuer;
    std::vector<NTL::ZZ> RSA_pub_key;
    std::vector<NTL::ZZ> EL_pub_key;
    std::pair<NTL::ZZ, NTL::ZZ> EL_sign_res;
public:
    certificate(person p);
    certificate(){};
    std::vector<unsigned char> serialize() const;
    void deserialize(const std::vector<unsigned char>& buffer);
    void cerSignIn(ElGamal elGamal);
    bool cerVerify(ElGamal elGamal);

    std::string getName(){return name;}
    std::string getHashRes(){ return HashRes;}
    std::vector<NTL::ZZ> getRSA_pub_key(){return RSA_pub_key;}
    std::vector<NTL::ZZ> getEL_pub_key(){return EL_pub_key;}
    std::pair<NTL::ZZ, NTL::ZZ> getEL_sign_res(){return EL_sign_res;}
};
#endif //CRYPTOMESSAGESYSTEM_CERTIFICATE_H
