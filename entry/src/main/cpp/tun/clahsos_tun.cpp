#include "clahsos_tun.h"
#include <unistd.h>
#include <fcntl.h>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <algorithm>
#include <array>
#include <arpa/inet.h>
extern "C" {
#include "hev-main.h"
}

namespace {
std::mutex controlMutex;
std::mutex stateMutex;
std::condition_variable changed;
std::thread worker;
bool ready = false;
bool finished = true;
bool stopping = false;
std::string failure;

void stopWorker()
{
    if (!worker.joinable()) return;
    bool active;
    {
        std::lock_guard<std::mutex> guard(stateMutex);
        active = !finished;
        stopping = true;
    }
    if (active) hev_socks5_tunnel_quit();
    worker.join();
}
}

extern "C" void clahsos_tun_ready(void)
{
    std::lock_guard<std::mutex> guard(stateMutex);
    ready = true;
    changed.notify_all();
}

namespace clahsos {
bool startTunnel(int fd, int port, const std::string& address, const std::string& username, const std::string& password)
{
    std::lock_guard<std::mutex> serialized(controlMutex);
    if (fd < 0 || port < 1 || port > 65535 || fcntl(fd, F_GETFD) < 0) return false;
    std::array<unsigned char, 16> ip{};
    const auto valid = [](const std::string& value) {
        return value.size() <= 255 && std::none_of(value.begin(), value.end(), [](unsigned char ch) { return ch < 32 || ch == 127; });
    };
    if ((inet_pton(AF_INET, address.c_str(), ip.data()) != 1 && inet_pton(AF_INET6, address.c_str(), ip.data()) != 1) ||
        !valid(username) || !valid(password) || username.empty() != password.empty()) return false;
    const auto quoted = [](const std::string& value) {
        std::string result = "'";
        for (char ch : value) { result += ch; if (ch == '\'') result += '\''; }
        return result + "'";
    };
    {
        std::lock_guard<std::mutex> guard(stateMutex);
        if (!finished) return false;
    }
    if (worker.joinable()) worker.join();
    const int owned = dup(fd);
    if (owned < 0) return false;
    {
        std::lock_guard<std::mutex> guard(stateMutex);
        ready = false;
        finished = false;
        stopping = false;
        failure.clear();
    }
    const std::string config = "tunnel:\n  mtu: 1500\n  ipv4: 198.18.0.1\n  ipv6: 'fdfe:dcba:9876::1'\n"
        "socks5:\n  address: " + quoted(address) + "\n  port: " + std::to_string(port) + "\n  udp: udp\n" +
        (username.empty() ? "" : "  username: " + quoted(username) + "\n  password: " + quoted(password) + "\n") +
        "mapdns:\n  address: 198.18.0.2\n  port: 53\n  network: 198.19.0.0\n  netmask: 255.255.0.0\n  cache-size: 4096\n"
        "misc:\n  task-stack-size: 86016\n  tcp-buffer-size: 65536\n  max-session-count: 256\n"
        "  connect-timeout: 6000\n  tcp-read-write-timeout: 300000\n  log-level: warn\n  log-file: stderr\n";
    try {
        worker = std::thread([owned, config]() {
            const int result = hev_socks5_tunnel_main_from_str(
                reinterpret_cast<const unsigned char*>(config.data()), config.size(), owned);
            close(owned);
            std::lock_guard<std::mutex> guard(stateMutex);
            if (!stopping) failure = result == 0 ? "TUN event loop stopped unexpectedly" : "TUN initialization failed";
            finished = true;
            ready = false;
            changed.notify_all();
        });
    } catch (...) {
        close(owned);
        std::lock_guard<std::mutex> guard(stateMutex);
        finished = true;
        failure = "Cannot create TUN worker";
        return false;
    }
    std::unique_lock<std::mutex> state(stateMutex);
    const bool initialized = changed.wait_for(state, std::chrono::seconds(5), [] { return ready || finished; });
    const bool success = initialized && ready && !finished;
    if (!initialized) failure = "TUN initialization timed out";
    state.unlock();
    if (!success) stopWorker();
    return success;
}

void stopTunnel()
{
    std::lock_guard<std::mutex> serialized(controlMutex);
    stopWorker();
}

std::string tunnelStatus()
{
    std::lock_guard<std::mutex> guard(stateMutex);
    return std::string("{\"running\":") + (ready && !finished && !stopping ? "true" : "false") +
        ",\"error\":\"" + failure + "\"}";
}
}
