#include <iostream>
#include <run.h>

// 主函数
int main(int argc, char* argv[]) {
    system("chcp 65001");
    if (argc < 3) {
        std::cerr << "用法: " << argv[0] << " --server [username] 或 " << argv[0] << " --client [username]" << std::endl;
        return 1;
    }

    std::string mode = argv[1];
    std::string username =argv[2];
    if (mode == "--server") {
        runServer(username);
    }
    else if (mode == "--client") {
        runClient(username);
    }
    else {
        std::cerr << "未知参数: " << mode << std::endl;
        std::cerr << "用法: " << argv[0] << " --server 或 " << argv[0] << " --client" << std::endl;
        return 1;
    }

    return 0;
}
