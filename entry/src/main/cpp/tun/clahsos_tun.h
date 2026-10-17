#pragma once
#include <string>
namespace clahsos {
bool startTunnel(int fd, int port);
void stopTunnel();
std::string tunnelStatus();
}
