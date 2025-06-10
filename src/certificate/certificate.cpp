//
// Created by PaperPlane on 2025/6/8.
//
#include <certificate/certificate.h>
#include "certificate/person.h"

certificate::certificate(person p):RSA_pub_key(2), EL_pub_key(3), name(p.getName()), Issuer("Admin"){

    RSA_pub_key.push_back(p.getRsaPubKey()); // e
    RSA_pub_key.push_back(p.getRsaMoudle()); // n

    EL_pub_key.push_back(p.getEgPrime()); // p
    EL_pub_key.push_back(p.getEgGenerator()); // g
    EL_pub_key.push_back(p.getEgPubKey()); // h

    std::ostringstream oss;
    for(NTL::ZZ z : RSA_pub_key){
        oss << z;
        oss<<" ";
    }
    oss<<" ";
    for (NTL::ZZ z : EL_pub_key){
        oss << z;
        oss<<" ";
    }
    std::string s = oss.str();

    std::string hString = name + Issuer + s;


    HashRes = sha256(hString);

}
void certificate::cerSignIn(ElGamal elGamal){
    EL_sign_res=elGamal.signHash(HashRes);
}
bool certificate::cerVerify(ElGamal elGamal){
    return elGamal.verifyHash(HashRes,EL_sign_res);
}
std::vector<unsigned char> certificate::serialize() const {
    std::vector<unsigned char> buffer;

    auto append_string = [&](const std::string& s) {
        uint32_t len = s.size();
        buffer.insert(buffer.end(), (unsigned char*)&len, (unsigned char*)&len + sizeof(len));
        buffer.insert(buffer.end(), s.begin(), s.end());
    };

    auto ZZToString= []  (const NTL::ZZ& x)->std::string {
        std::ostringstream oss;
        oss << x;
        return oss.str();
    };


    append_string(HashRes);
    append_string(name);
    append_string(Issuer);
    for(NTL::ZZ z : RSA_pub_key){
        append_string(ZZToString(z));
    }
    for(NTL::ZZ z :EL_pub_key){
        append_string(ZZToString(z));
    }
    append_string(ZZToString(EL_sign_res.first));
    append_string(ZZToString(EL_sign_res.second));

    return buffer;
}

// Deserialize
void certificate::deserialize(const std::vector<unsigned char>& buffer) {
    size_t offset = 0;

    auto read_string = [&](std::string& s) {
        uint32_t len;
        std::memcpy(&len, buffer.data() + offset, sizeof(len));
        offset += sizeof(len);
        s.assign((const char*)(buffer.data() + offset), len);
        offset += len;
    };
    auto StringToZZ=[](const std::string& s)->NTL::ZZ {
        std::istringstream iss(s);
        NTL::ZZ x;
        iss >> x;
        return x;
    };


    read_string(HashRes);
    read_string(name);
    read_string(Issuer);

    RSA_pub_key.clear();
    for (int i = 0; i < 2; ++i) {
        std::string s;
        read_string(s);
    }
    for (int i = 0; i < 2; ++i) {
        std::string s;
        read_string(s);
        RSA_pub_key.push_back(StringToZZ(s));
    }

    // 读 EL_pub_key (vector[3])
    EL_pub_key.clear();
    for (int i = 0; i < 3; ++i) {
        std::string s;
        read_string(s);
    }
    EL_pub_key.clear();
    for (int i = 0; i < 3; ++i) {
        std::string s;
        read_string(s);
        EL_pub_key.push_back(StringToZZ(s));
    }

    // 读 EL_sign_res (pair)
    {
        std::string s;
        read_string(s);
        EL_sign_res.first = StringToZZ(s);

        read_string(s);
        EL_sign_res.second = StringToZZ(s);
    }

}


