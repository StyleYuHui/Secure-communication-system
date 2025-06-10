cmake_minimum_required(VERSION 3.28)
project(CryptoMessageSystem)
if(WIN32)
    link_libraries(ws2_32)
endif()
set(CMAKE_CXX_STANDARD 20)
include_directories(D:/Project/C++/WinNTL-11_5_1/include)
include_directories(${PROJECT_SOURCE_DIR}/inc)

file(GLOB NTL_SOURCES
        "D:/Users/31007/Desktop/WinNTL-11_5_1/src/*.cpp"
)
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
add_executable(CryptoMessageSystem
        ${SOURCES}
        ${NTL_SOURCES}
        main.cpp
)
set(CMAKE_EXE_LINKER_FLAGS "-static")
if(WIN32)
    target_link_libraries(CryptoMessageSystem gdi32)
endif()