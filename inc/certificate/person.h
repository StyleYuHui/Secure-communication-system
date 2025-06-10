//
// Created by 31007 on 2025/6/8.
//

#ifndef CRYPTOMESSAGESYSTEM_PERSON_H
#define CRYPTOMESSAGESYSTEM_PERSON_H
#pragma once
class certificate;
#include <crypto/Rsa.h>
#include <crypto/ElGamal.h>
#define CRYPT_BIE_LENGTH 50
struct RsaKey{
    NTL::ZZ n;
    NTL::ZZ e;
    NTL::ZZ d;
};
struct ElGamalKey{
    NTL::ZZ p;
    NTL::ZZ g;
    NTL::ZZ h;
    NTL::ZZ x;
};
class person {
    RSA rsa;
    ElGamal elGamal;

    std::string name;
    RsaKey rsaKey;
    ElGamalKey elGamalKey;
public:
    person(std::string name);
    person(certificate cer);
    NTL::ZZ getRsaPubKey() const{ return rsaKey.e; }
    NTL::ZZ getRsaMoudle() const{ return rsaKey.n; }
    NTL::ZZ getEgPubKey() const{ return elGamalKey.h; }
    NTL::ZZ getEgPrime() const{ return elGamalKey.p; }
    NTL::ZZ getEgGenerator() const{ return elGamalKey.g; }

    std::string getName(){ return name; }


    RSA getRSA() const {return rsa;}
    ElGamal getElGamal(){return elGamal;}
};



#endif //CRYPTOMESSAGESYSTEM_PERSON_H
