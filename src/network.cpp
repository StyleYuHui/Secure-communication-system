//
// Created by 31007 on 2025/6/9.
//

#include "network.h"
bool sendCertificate(SOCKET sock, const std::vector<unsigned char>& certBytes) {
    // 先发送 4 字节证书长度
    uint32_t cert_len = static_cast<uint32_t>(certBytes.size());
    int sendResult = send(sock, reinterpret_cast<const char*>(&cert_len), sizeof(cert_len), 0);
    if (sendResult == SOCKET_ERROR) {
        std::cerr << "send(证书长度)失败: " << WSAGetLastError() << std::endl;
        return false;
    }

    // 再发送证书内容
    size_t totalSent = 0;
    while (totalSent < certBytes.size()) {
        int sent = send(sock, reinterpret_cast<const char*>(certBytes.data()) + totalSent,
                        static_cast<int>(certBytes.size() - totalSent), 0);
        if (sent == SOCKET_ERROR) {
            std::cerr << "send(证书内容)失败: " << WSAGetLastError() << std::endl;
            return false;
        }
        totalSent += sent;
    }

    return true;
}
bool receiveCertificate(SOCKET sock, std::vector<unsigned char>& certBytes) {
    // 先接收 4 字节证书长度
    uint32_t cert_len = 0;
    int recvResult = recv(sock, reinterpret_cast<char*>(&cert_len), sizeof(cert_len), 0);
    if (recvResult != sizeof(cert_len)) {
        std::cerr << "recv(证书长度)失败: " << WSAGetLastError() << std::endl;
        return false;
    }


    // 接收证书内容
    certBytes.resize(cert_len);
    size_t totalReceived = 0;
    while (totalReceived < cert_len) {
        int received = recv(sock, reinterpret_cast<char*>(certBytes.data()) + totalReceived,
                            static_cast<int>(cert_len - totalReceived), 0);
        if (received <= 0) {
            std::cerr << "recv(证书内容)失败: " << WSAGetLastError() << std::endl;
            return false;
        }
        totalReceived += received;
    }

    return true;
}

std::string generate_random_string(size_t length = 16) {
    const std::string characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    std::random_device rd;
    std::mt19937 generator(rd());  // Mersenne Twister 伪随机数生成器
    std::uniform_int_distribution<> distribution(0, characters.size() - 1);

    std::string random_string;
    for (size_t i = 0; i < length; ++i) {
        random_string += characters[distribution(generator)];
    }

    return random_string;
}

netMessage::netMessage(std::string msg,RSA rsa) {
    std::string key = generate_random_string();
    AES aes;
    this->msg=aes.encrypt(msg,key);


    auto ZZToString= []  (const NTL::ZZ& x)->std::string {
        std::ostringstream oss;
        oss << x;
        return oss.str();
    };

    auto aesk=rsa.encryptString(key);



    for(auto z : aesk){
        std::string tmp = ZZToString(z);
        this->AESkey+= tmp+" ";
    }

    HashRes = sha256(msg);
}
std::vector<unsigned char> netMessage::serialize(){
    std::vector<unsigned char> buffer;

    auto append_string = [&](const std::string& s) {
        uint32_t len = s.size();
        buffer.insert(buffer.end(), (unsigned char*)&len, (unsigned char*)&len + sizeof(len));
        buffer.insert(buffer.end(), s.begin(), s.end());
    };

    append_string(this->AESkey);
    append_string(this->msg);
    append_string(this->HashRes);
    return buffer;
}

void netMessage::deserialize(const std::vector<unsigned char>& buffer) {
    size_t offset = 0;

    auto read_string = [&](std::string& s) {
        uint32_t len;
        std::memcpy(&len, buffer.data() + offset, sizeof(len));
        offset += sizeof(len);
        s.assign((const char*)(buffer.data() + offset), len);
        offset += len;
    };

    read_string(this->AESkey);
    read_string(this->msg);
    read_string(this->HashRes);

}


std::string netMessage::unPack(RSA rsa){
    auto StringToZZ=[](const std::string& s)->NTL::ZZ {
        std::istringstream iss(s);
        NTL::ZZ x;
        iss >> x;
        return x;
    };
    std::vector<NTL::ZZ> ciphertext;
    std::string subStr;
    for(auto c : AESkey){
        if (c !=' ')
            subStr+=c;
        else {
            ciphertext.push_back(StringToZZ(subStr));
            subStr.clear();
        }
    }


    std::string aeskey=rsa.decryptString(ciphertext);
    AES aes;
    auto revMsg= aes.decrypt(this->msg,aeskey);
    if(sha256(revMsg)==HashRes)
        return revMsg;
    else {
        std::cerr << "哈希验证消息失败" << std::endl;
        return "";
    }
}
