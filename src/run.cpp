//
// Created by PaperPlane on 2025/6/8.
//

#include "run.h"


std::atomic<bool> g_running(true);

// 初始化Winsock
bool initializeWinsock() {
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        std::cerr << "WSAStartup失败: " << result << std::endl;
        return false;
    }
    return true;
}

// 清理Winsock
void cleanupWinsock() {
    WSACleanup();
}

// 服务器端实现
void runServer(std::string username) {

    std::cout << "正在初始化..." << std::endl;

    // 生成个人信息
    person Server(username);

    //签发证书
    certificate severCer(Server);
    severCer.cerSignIn(Server.getElGamal());
    std::cout << username+"的证书哈希结果:"<<severCer.getHashRes() << std::endl;

    //字节化证书
    std::vector<unsigned char> serialize = severCer.serialize();


    std::cout << "启动服务器..." << std::endl;

    // 初始化Winsock
    if (!initializeWinsock()) {
        return;
    }

    // 创建监听socket
    struct addrinfo hints = {0};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    struct addrinfo* result = nullptr;
    int iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result);
    if (iResult != 0) {
        std::cerr << "getaddrinfo失败: " << iResult << std::endl;
        cleanupWinsock();
        return;
    }

    // 创建监听socket
    SOCKET listenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (listenSocket == INVALID_SOCKET) {
        std::cerr << "socket失败: " << WSAGetLastError() << std::endl;
        freeaddrinfo(result);
        cleanupWinsock();
        return;
    }

    // 绑定socket
    iResult = bind(listenSocket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        std::cerr << "bind失败: " << WSAGetLastError() << std::endl;
        freeaddrinfo(result);
        closesocket(listenSocket);
        cleanupWinsock();
        return;
    }

    freeaddrinfo(result);

    // 开始监听
    iResult = listen(listenSocket, SOMAXCONN);
    if (iResult == SOCKET_ERROR) {
        std::cerr << "listen失败: " << WSAGetLastError() << std::endl;
        closesocket(listenSocket);
        cleanupWinsock();
        return;
    }

    std::cout << "服务器启动成功，监听端口: " << DEFAULT_PORT << std::endl;
    std::cout << "等待客户端连接..." << std::endl;

    // 接受客户端连接
    SOCKET clientSocket = accept(listenSocket, NULL, NULL);
    if (clientSocket == INVALID_SOCKET) {
        std::cerr << "accept失败: " << WSAGetLastError() << std::endl;
        closesocket(listenSocket);
        cleanupWinsock();
        return;
    }

    std::cout << "客户端已连接！" << std::endl;

    // 发送证书
    if (!sendCertificate(clientSocket, serialize)) {
        closesocket(clientSocket);
        closesocket(listenSocket);
        cleanupWinsock();
        std::cerr<<"证书发送失败，终止服务端"<<std::endl;
        return;
    }


    // 接收证书
    std::vector<unsigned char> clientCertBytes;
    if (!receiveCertificate(clientSocket, clientCertBytes)) {
        closesocket(clientSocket);
        closesocket(listenSocket);
        cleanupWinsock();
        return;
    }

    certificate clientCert;
    clientCert.deserialize(clientCertBytes);
    std::cout << "客户端证书哈希: " << clientCert.getHashRes() << std::endl;



    person client(clientCert);
    std::string clientName=client.getName();
    if(!clientCert.cerVerify(client.getElGamal())){
        std::cerr<<"证书验证错误，断开连接"<<std::endl;
        return;
    } else{
        std::cout<<"CA证书校验成功！"<<std::endl<<std::endl;
    }


    // 接收和发送数据的线程
    std::thread receiveThread([&clientSocket, clientName,Server]() {
        std::vector<unsigned char> recv_buffer(DEFAULT_BUFLEN);
        int recvbuflen = DEFAULT_BUFLEN;
        int iResult;

        while (g_running) {
            // 接收数据
            iResult = recv(clientSocket, reinterpret_cast<char*>(recv_buffer.data()), static_cast<int>(recv_buffer.size()), 0);
            if (iResult > 0) {
                std::time_t now = std::time(nullptr);         //
                std::tm* local_time = std::localtime(&now);   // 转换为本地时间
                char buffer[100];
                std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", local_time);
                netMessage msg;
                msg.deserialize(recv_buffer);
                std::string revMsg= msg.unPack(Server.getRSA());
                std::cout <<"["<<buffer <<"]"<<clientName << ": " <<revMsg << std::endl;
            }
            else if (iResult == 0) {
                std::cout << "连接关闭" << std::endl;
                g_running = false;
                break;
            }
            else {
                std::cerr << "recv失败: " << WSAGetLastError() << std::endl;
                g_running = false;
                break;
            }
        }
    });

    // 发送消息
    std::string message;
    while (g_running) {
        std::getline(std::cin, message);
        if (message == "exit") {
            g_running = false;
            break;
        }

        netMessage msg(message,client.getRSA());
        auto sendMsg=msg.serialize();

        int iSendResult = send(clientSocket, reinterpret_cast<const char*>(sendMsg.data()), (int)sendMsg.size() + 1, 0);
        if (iSendResult == SOCKET_ERROR) {
            std::cerr << "send失败: " << WSAGetLastError() << std::endl;
            g_running = false;
            break;
        }
    }

    if (receiveThread.joinable()) {
        receiveThread.join();
    }

    // 关闭连接
    closesocket(clientSocket);
    closesocket(listenSocket);
    cleanupWinsock();
    std::cout << "服务器已关闭" << std::endl;
}

// 客户端实现
void runClient(std::string username) {

    std::cout << "正在初始化..." << std::endl;

    // 生成个人信息
    person Client(username);

    //签发证书
    certificate clientCer(Client);
    clientCer.cerSignIn(Client.getElGamal());
    std::cout << username+"的证书哈希结果:"<<clientCer.getHashRes() << std::endl;


    //字节化证书
    std::vector<unsigned char> serialize = clientCer.serialize();


    std::cout << "启动客户端..." << std::endl;

    // 初始化Winsock
    if (!initializeWinsock()) {
        return;
    }

    // 创建socket
    struct addrinfo hints = {0};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    struct addrinfo* result = nullptr;
    int iResult = getaddrinfo(SERVER_IP, DEFAULT_PORT, &hints, &result);
    if (iResult != 0) {
        std::cerr << "getaddrinfo失败: " << iResult << std::endl;
        cleanupWinsock();
        return;
    }

    // 尝试连接到服务器
    SOCKET connectSocket = INVALID_SOCKET;
    struct addrinfo* ptr = result;

    connectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
    if (connectSocket == INVALID_SOCKET) {
        std::cerr << "socket失败: " << WSAGetLastError() << std::endl;
        freeaddrinfo(result);
        cleanupWinsock();
        return;
    }

    // 连接到服务器
    iResult = connect(connectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        closesocket(connectSocket);
        connectSocket = INVALID_SOCKET;
        std::cerr << "无法连接到服务器！" << std::endl;
        freeaddrinfo(result);
        cleanupWinsock();
        return;
    }

    freeaddrinfo(result);

    if (connectSocket == INVALID_SOCKET) {
        std::cerr << "无法连接到服务器！" << std::endl;
        cleanupWinsock();
        return;
    }

    std::cout << "已连接到服务器 " << SERVER_IP << ":" << DEFAULT_PORT << std::endl;

    // 发送证书
    if (!sendCertificate(connectSocket, serialize)) {
        closesocket(connectSocket);
        closesocket(connectSocket);
        cleanupWinsock();
        std::cerr<<"证书发送失败，终止服务端"<<std::endl;
        return;
    }


    // 接收证书
    std::vector<unsigned char> clientCertBytes;
    if (!receiveCertificate(connectSocket, clientCertBytes)) {
        closesocket(connectSocket);
        closesocket(connectSocket);
        cleanupWinsock();
        return;
    }

    certificate severCert;
    severCert.deserialize(clientCertBytes);
    std::cout << "服务端证书哈希: " << severCert.getHashRes() << std::endl;
    std::string severName =severCert.getName();

    person server(severCert);
    std::string clientName=server.getName();
    if(!severCert.cerVerify(server.getElGamal())){
        std::cerr<<"证书验证错误，断开连接"<<std::endl;
        return;
    } else{
        std::cout<<"CA证书校验成功！"<<std::endl<<std::endl;
    }

    // 接收数据的线程
    std::thread receiveThread([&connectSocket,severName,Client]() {
        std::vector<unsigned char> recv_buffer(DEFAULT_BUFLEN);
        int recvbuflen = DEFAULT_BUFLEN;
        int iResult;

        while (g_running) {
            // 接收数据
            iResult = recv(connectSocket, reinterpret_cast<char*>(recv_buffer.data()), static_cast<int>(recv_buffer.size()), 0);
            if (iResult > 0) {
                std::time_t now = std::time(nullptr);
                std::tm* local_time = std::localtime(&now);   // 转换为本地时间
                char buffer[100];
                std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", local_time);
                netMessage msg;
                msg.deserialize(recv_buffer);
                std::string revMsg= msg.unPack(Client.getRSA());
                std::cout <<"["<<buffer <<"]"<<severName << ": " <<revMsg << std::endl;
            }
            else if (iResult == 0) {
                std::cout << "连接关闭" << std::endl;
                g_running = false;
                break;
            }
            else {
                std::cerr << "recv失败: " << WSAGetLastError() << std::endl;
                g_running = false;
                break;
            }
        }
    });

    // 发送消息
    std::string message;
    while (g_running) {
        std::getline(std::cin, message);
        if (message == "exit") {
            g_running = false;
            break;
        }

        netMessage msg(message,server.getRSA());
        auto sendMsg=msg.serialize();

        int iSendResult = send(connectSocket, reinterpret_cast<const char*>(sendMsg.data()), (int)sendMsg.size() + 1, 0);
        if (iSendResult == SOCKET_ERROR) {
            std::cerr << "send失败: " << WSAGetLastError() << std::endl;
            g_running = false;
            break;
        }
    }

    if (receiveThread.joinable()) {
        receiveThread.join();
    }

    // 关闭连接
    closesocket(connectSocket);
    cleanupWinsock();
    std::cout << "客户端已关闭" << std::endl;
}

