//
// Created by 31007 on 2025/6/8.
//

/**
 * @file run.h
 * @brief 定义客户端 / 服务器运行接口。
 *
 * 该头文件定义了启动服务器端和客户端的运行函数。
 *
 * 功能包含：
 * - 启动 TCP 服务器，监听端口，处理证书交换、消息通信。
 * - 启动 TCP 客户端，连接服务器，完成认证、消息通信。
 *
 * 依赖：
 * - Winsock2
 * - network.h
 * - certificate/person.h
 * - certificate/certificate.h
 */

#ifndef CRYPTOMESSAGESYSTEM_RUN_H
#define CRYPTOMESSAGESYSTEM_RUN_H

// C++ 标准库
#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <cstring>

// Windows 网络库
#include <winsock2.h>
#pragma comment(lib, "Ws2_32.lib")

// 自定义模块
#include <network.h>
#include <certificate/person.h>
#include <certificate/certificate.h>

// 常量定义
#define DEFAULT_PORT "8888"          ///< 默认服务器监听端口
#define DEFAULT_BUFLEN 4096          ///< 默认缓冲区大小
#define SERVER_IP "127.0.0.1"        ///< 默认服务器 IP 地址

/**
 * @brief 启动服务器模式。
 * @param username 服务器用户名称，用于生成/加载证书。
 */
void runServer(std::string username);

/**
 * @brief 启动客户端模式。
 * @param username 客户端用户名称，用于生成/加载证书。
 */
void runClient(std::string username);

#endif // CRYPTOMESSAGESYSTEM_RUN_H
