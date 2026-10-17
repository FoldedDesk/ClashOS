#pragma once
#include <string>
namespace clahsos {
bool startTunnel(int fd, int port, const std::string& address = "127.0.0.1",
    const std::string& username = "", const std::string& password = "");
void stopTunnel();
std::string tunnelStatus();
}
