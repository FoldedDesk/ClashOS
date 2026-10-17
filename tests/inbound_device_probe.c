// Device-only ingress probe. Uses a public test account and a fixed Google 204
// endpoint; prints status and socket addresses, never authorization headers.
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static int exact(int fd, unsigned char* bytes, size_t size)
{
    size_t offset = 0;
    while (offset < size) { ssize_t n = recv(fd, bytes + offset, size - offset, 0); if (n <= 0) return 0; offset += n; }
    return 1;
}

int main(int argc, char** argv)
{
    if (argc != 4) return 2;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct timeval timeout = {15, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    struct sockaddr_in address = {0}; address.sin_family = AF_INET; address.sin_port = htons(atoi(argv[2]));
    if (inet_pton(AF_INET, argv[1], &address.sin_addr) != 1) return 2;
    if (connect(fd, (struct sockaddr*)&address, sizeof(address)) != 0) { printf("connect_failed errno=%d\n", errno); close(fd); return 0; }
    struct sockaddr_in local = {0}; socklen_t size = sizeof(local); char source[INET_ADDRSTRLEN] = {0};
    getsockname(fd, (struct sockaddr*)&local, &size); inet_ntop(AF_INET, &local.sin_addr, source, sizeof(source));
    printf("source=%s ", source);
    unsigned char bytes[4096] = {0};
    if (strncmp(argv[3], "http-", 5) == 0) {
        const char* auth = strcmp(argv[3], "http-good") == 0 ? "Proxy-Authorization: Basic ZGV2aWNlLXB1YmxpYzpwdWJsaWMtcHJveHktc2VjcmV0\r\n" :
            strcmp(argv[3], "http-bad") == 0 ? "Proxy-Authorization: Basic ZGV2aWNlLXB1YmxpYzp3cm9uZw==\r\n" : "";
        char request[1024]; snprintf(request, sizeof(request), "GET http://www.gstatic.com/generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\n%sConnection: close\r\n\r\n", auth);
        send(fd, request, strlen(request), 0);
        const ssize_t n = recv(fd, bytes, sizeof(bytes) - 1, 0); const int receiveError = n < 0 ? errno : 0; int status = 0;
        if (n > 0) sscanf((const char*)bytes, "HTTP/%*s %d", &status);
        printf("http=%d closed=%d recv_errno=%d\n", status, n == 0, receiveError); close(fd); return 0;
    }
    const int password = strcmp(argv[3], "socks-none") != 0;
    const unsigned char greeting[] = {5, 2, 0, 2}, anonymous[] = {5, 1, 0};
    send(fd, password ? greeting : anonymous, password ? sizeof(greeting) : sizeof(anonymous), 0);
    if (!exact(fd, bytes, 2)) { printf("closed\n"); close(fd); return 0; }
    printf("method=%u ", bytes[1]);
    if (bytes[1] == 2) {
        const char* user = "device-public";
        const char* secret = strcmp(argv[3], "socks-good") == 0 ? "public-proxy-secret" : "wrong";
        size_t used = 0; bytes[used++] = 1; bytes[used++] = strlen(user); memcpy(bytes + used, user, strlen(user)); used += strlen(user);
        bytes[used++] = strlen(secret); memcpy(bytes + used, secret, strlen(secret)); used += strlen(secret); send(fd, bytes, used, 0);
        if (!exact(fd, bytes, 2)) { printf("closed\n"); close(fd); return 0; }
        printf("auth=%u ", bytes[1]);
        if (bytes[1] != 0) { printf("\n"); close(fd); return 0; }
    } else if (bytes[1] != 0) { printf("\n"); close(fd); return 0; }
    const char* host = "www.gstatic.com"; size_t used = 0;
    bytes[used++] = 5; bytes[used++] = 1; bytes[used++] = 0; bytes[used++] = 3; bytes[used++] = strlen(host);
    memcpy(bytes + used, host, strlen(host)); used += strlen(host); bytes[used++] = 1; bytes[used++] = 187;
    send(fd, bytes, used, 0);
    printf("connect=%d\n", exact(fd, bytes, 10) ? bytes[1] : -1); close(fd); return 0;
}
