#include "certificate/person.h"
#include "certificate/certificate.h"

person::person(std::string name) : rsa(CRYPT_BIE_LENGTH),elGamal(CRYPT_BIE_LENGTH){

    this->name = name;

    rsaKey.d=rsa.getPrivateKey();
    rsaKey.e=rsa.getPublicKey();
    rsaKey.n=rsa.getModulus();

    elGamalKey.p=elGamal.getPublicKey().first;
    elGamalKey.h=elGamal.getPublicKey().second;
    elGamalKey.g=elGamal.getGenerator();
    elGamalKey.x=elGamal.getPrivateKey();

}
person::person(certificate cer): rsa(cer.getRSA_pub_key()[1],cer.getRSA_pub_key()[0],"encrypt"), elGamal(cer.getEL_pub_key()[0],std::pair<NTL::ZZ,NTL::ZZ>(cer.getEL_pub_key()[1],cer.getEL_pub_key()[2]),"encrypt"){
    this->name = cer.getName();

    rsaKey.d=0;
    rsaKey.e=rsa.getPublicKey();
    rsaKey.n=rsa.getModulus();

    elGamalKey.p=elGamal.getPublicKey().first;
    elGamalKey.h=elGamal.getPublicKey().second;
    elGamalKey.g=elGamal.getGenerator();
    elGamalKey.x=0;

}