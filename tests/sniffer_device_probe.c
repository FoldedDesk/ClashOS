// Independent device SOCKS5 UDP probe. Only exchanges public QUIC vectors with
// a fixed TLS reference peer; never invokes any production sniffer code.
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define CHECK(condition) do { if (!(condition)) { fprintf(stderr, "check failed at line %d\n", __LINE__); return 1; } } while (0)

static int exact(int fd, unsigned char* bytes, size_t size)
{
    size_t offset = 0;
    while (offset < size) { ssize_t n = recv(fd, bytes + offset, size - offset, 0); if (n <= 0) return 0; offset += n; }
    return 1;
}

static int endpoint(int type, int port)
{
    int fd = socket(AF_INET, type, 0);
    if (fd < 0) { fprintf(stderr, "socket type=%d errno=%d\n", type, errno); return -1; }
    struct timeval timeout = {8, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET; address.sin_port = htons(port); address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int result = connect(fd, (struct sockaddr*)&address, sizeof(address));
    if (result) { fprintf(stderr, "connect type=%d port=%d errno=%d\n", type, port, errno); close(fd); return -1; }
    return fd;
}

int main(int argc, char** argv)
{
    CHECK(argc >= 4 && argc <= 11);
    int proxy = atoi(argv[1]), target = atoi(argv[2]);
    CHECK(proxy > 0 && proxy <= 65535 && target > 0 && target <= 65535);
    const int tcp = endpoint(SOCK_STREAM, proxy); CHECK(tcp >= 0);
    unsigned char response[65536];
    CHECK(send(tcp, "\5\1\0", 3, 0) == 3 && exact(tcp, response, 2) && response[0] == 5 && response[1] == 0);
    CHECK(send(tcp, "\5\3\0\1\0\0\0\0\0\0", 10, 0) == 10 && exact(tcp, response, 10) && response[1] == 0 && response[3] == 1);
    const int udp = endpoint(SOCK_DGRAM, response[8] * 256 + response[9]); CHECK(udp >= 0);
    unsigned char expected[8][16384]; size_t sizes[8] = {0}; const int count = argc - 3;
    const unsigned char address[] = {0, 0, 0, 1, 203, 0, 113, 10, (unsigned char)(target >> 8), (unsigned char)target};
    for (int i = 0; i < count; ++i) {
        FILE* file = fopen(argv[i + 3], "rb"); CHECK(file);
        sizes[i] = fread(expected[i], 1, sizeof(expected[i]), file);
        CHECK(sizes[i] > 0 && sizes[i] < sizeof(expected[i]) && feof(file)); fclose(file);
        memcpy(response, address, sizeof(address)); memcpy(response + sizeof(address), expected[i], sizes[i]);
        CHECK(send(udp, response, sizes[i] + sizeof(address), 0) == (ssize_t)(sizes[i] + sizeof(address)));
    }
    size_t bytes = 0;
    for (int i = 0; i < count; ++i) {
        ssize_t received = recv(udp, response, sizeof(response), 0);
        CHECK(received == (ssize_t)(sizes[i] + sizeof(address)) && memcmp(response, address, sizeof(address)) == 0 &&
            memcmp(response + sizeof(address), expected[i], sizes[i]) == 0);
        bytes += sizes[i];
    }
    printf("QUIC echoed packets=%d bytes=%zu original_endpoint=203.0.113.10:%d\n", count, bytes, target);
    close(udp); close(tcp); return 0;
}
