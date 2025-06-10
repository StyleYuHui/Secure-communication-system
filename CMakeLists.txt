
cmake_minimum_required(VERSION 3.28)


project(CryptoMessageSystem)


set(CMAKE_CXX_STANDARD 20)


if(WIN32)
    # 链接 Winsock2 网络库
    link_libraries(ws2_32)
endif()

# 包含头文件路径
include_directories(
        D:/Project/C++/WinNTL-11_5_1/include        # NTL 库头文件
        ${PROJECT_SOURCE_DIR}/inc                   # 自定义项目头文件
)

# NTL 库源码文件
file(GLOB NTL_SOURCES
        "D:/Project/C++/WinNTL-11_5_1/src/*.cpp"
)

# 项目源文件
set(SOURCES
        src/run.cpp
        src/crypto/ElGamal.cpp
        src/crypto/Rsa.cpp
        src/crypto/sha2.cpp
        src/crypto/AES.cpp
        src/certificate/certificate.cpp
        src/certificate/person.cpp
        src/network.cpp
)

# 生成可执行文件
add_executable(CryptoMessageSystem
        ${SOURCES}           # 项目源文件
        ${NTL_SOURCES}       # NTL 源码
        main.cpp             # 主程序入口
)

# 强制静态链接（可选）
set(CMAKE_EXE_LINKER_FLAGS "-static")


if(WIN32)
    # 额外链接 gdi32（图形库，某些 NTL + WinSock 依赖可能需要）
    target_link_libraries(CryptoMessageSystem gdi32)
endif()