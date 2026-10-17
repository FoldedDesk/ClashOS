#define CLAHSOS_HOST_TEST
#include "../entry/src/main/cpp/clash_core.cpp"
#include "ss_vectors.h"
#include <iostream>
#include <stdexcept>
#include <csignal>
#include <future>

std::atomic<int> checks{0};
void require(bool condition, const char* label) {
    if (!condition) throw std::runtime_error(label);
    ++checks;
}
std::vector<unsigned char> hex(const std::string& source) {
    std::vector<unsigned char> result;
    for (size_t i = 0; i < source.size(); i += 2) result.push_back(static_cast<unsigned char>(std::stoul(source.substr(i, 2), nullptr, 16)));
    return result;
}
std::string text(const std::vector<unsigned char>& bytes) { return {bytes.begin(), bytes.end()}; }
void makePair(int (&pair)[2]) { require(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0, "Unix stream pair unavailable"); }

void protocolTests() {
    const auto master = evpBytesToKey(GOLDEN_PASSWORD, 32);
    require(master == hex(GOLDEN_MASTER), "EVP password derivation differs from reference");
    const auto key = hkdfSha1(hex(GOLDEN_SALT), master, "ss-subkey", 32);
    require(key == hex(GOLDEN_KEY), "HKDF-SHA1 differs from reference");
    std::vector<unsigned char> nonce(12, 0);
    for (int i = 0; i < 256; ++i) incrementNonce(nonce);
    require(nonce[0] == 0 && nonce[1] == 1 && nonce[11] == 0, "SS nonce must increment little endian");
    int pair[2]; makePair(pair);
    nonce.assign(12, 0);
    require(shadowsocksSendChunk(pair[0], key, nonce, {'h','e','l','l','o',' ','w','o','r','l','d'}), "First outbound frame failed");
    require(shadowsocksSendChunk(pair[0], key, nonce, {'n','e','x','t',' ','f','r','a','m','e'}), "Second outbound frame failed");
    const auto expected = hex(GOLDEN_CLIENT_PACKET);
    std::vector<unsigned char> wire(expected.size());
    require(readExact(pair[1], reinterpret_cast<char*>(wire.data()), wire.size()), "Outbound wire read failed");
    require(wire == expected, "SS wire bytes do not match independent AES-GCM reference");
    require(nonce[0] == 4 && nonce[11] == 0, "Each chunk must advance nonce twice");
    close(pair[0]); close(pair[1]);

    makePair(pair);
    const auto response = hex(GOLDEN_SERVER_PACKET);
    std::thread peer([&]() {
        for (unsigned char byte : response) if (!sendAll(pair[1], reinterpret_cast<const char*>(&byte), 1)) break;
        shutdown(pair[1], SHUT_WR);
    });
    bool receivedSalt = false;
    std::vector<unsigned char> receiveKey, plain;
    nonce.assign(12, 0);
    require(shadowsocksReceive(pair[0], master, receivedSalt, receiveKey, nonce, plain), "Inbound server salt and fragmented frame failed");
    require(text(plain) == "HTTP/1.1 204 No Content\r\n\r\n", "Server plaintext differs from reference");
    require(receiveKey == hex(GOLDEN_REMOTE_KEY) && receiveKey != key, "Inbound key must derive from server salt");
    require(shadowsocksReceive(pair[0], master, receivedSalt, receiveKey, nonce, plain), "Second inbound frame failed");
    require(text(plain) == "server data", "Inbound nonce continuation is incorrect");
    peer.join(); close(pair[0]); close(pair[1]);

    makePair(pair);
    auto corrupt = hex(GOLDEN_CLIENT_PACKET); corrupt[20] ^= 1;
    sendAll(pair[1], corrupt); shutdown(pair[1], SHUT_WR); nonce.assign(12, 0); plain.clear();
    require(!shadowsocksReadChunk(pair[0], key, nonce, plain), "Tampered payload must fail authentication");
    require(plain.empty(), "Unauthenticated plaintext must not be released");
    close(pair[0]); close(pair[1]);
    require(shadowsocksAddress("www.google.com",443) == hex("030e7777772e676f6f676c652e636f6d01bb"), "SS domain address encoding");
    require(shadowsocksAddress("127.0.0.1",80) == hex("017f0000010050"), "SS IPv4 address encoding");
    require(shadowsocksAddress(std::string(256, 'x'),443).empty(), "Oversize SS host must be rejected");
    require(!shadowsocksSendChunk(-1, key, nonce, std::vector<unsigned char>(0x4000)), "Oversize SS frame must be rejected");
}

void configurationTests(const std::string& original, const std::string& directory) {
    ParsedConfig config;
    std::string error;
    const std::string sample = R"(port: 7890
socks-port: 7891
proxies:
  - name: "节点, quoted"
    server: test.invalid
    port: 443
    type: ss
    cipher: aes-256-gcm
    password: "dummy, value:#"
proxy-groups:
  - name: "测试 分组"
    type: select
    proxies: ["节点, quoted", DIRECT, REJECT]
rules:
  - 'DOMAIN-SUFFIX,google.com,测试 分组'
  - 'DOMAIN,blocked.test,REJECT'
  - 'MATCH,DIRECT'
)";
    require(parseConfigText(sample, config, error), "Block YAML or quoted scalars failed");
    require(config.nodes.size() == 1 && config.nodes[0].password == "dummy, value:#", "Quoted credentials must be preserved");
    require(config.groups.size() == 1 && config.groups[0].proxies.size() == 3, "Flow group list failed");
    require(config.rules.size() == 3 && config.rules.back().target == "DIRECT", "MATCH rule parsing failed");
    ParsedConfig json;
    require(parseConfigText(R"({"mixed-port":9000,"proxies":[{"port":443,"name":"node","type":"ss","server":"test.invalid","cipher":"aes-256-gcm","password":"x"}],"proxy-groups":[{"name":"group","type":"select","proxies":["node","DIRECT"]}],"rules":["MATCH,group"]})", json, error), "JSON configurations must be supported");
    require(json.httpPort == 9000 && json.socksPort == 9000, "Mixed port parsing failed");
    ParsedConfig invalid;
    require(!parseConfigText("proxies: [", invalid, error) && error.find("YAML line") != std::string::npos, "Malformed YAML needs a location");
    require(!parseConfigText("proxies: []\nproxy-groups: [{name: g, proxies: [missing]}]", invalid, error), "Unknown group target must fail");
    require(!parseConfigText("proxies: [{name: a, type: ss, server: x, port: 10}, {name: a, type: ss, server: x, port: 20}]", invalid, error), "Duplicate nodes must fail");
    require(!parseConfigText("port: 70000", invalid, error), "Invalid listening port must fail");
    require(!parseConfigText("port: 7890\n---\nport: 7891", invalid, error), "Multiple YAML documents must fail");
    const std::string path = directory + "/profile.yaml";
    { std::ofstream out(path); out << sample; }
    require(loadConfigLocked(path, error), "Configuration activation failed");
    require(activeProxyNode("www.google.com").name == "节点, quoted", "DOMAIN-SUFFIX routing failed");
    require(activeProxyNode("notgoogle.com").type == "direct", "DOMAIN-SUFFIX boundary must be respected");
    require(activeProxyNode("blocked.test").type == "reject", "REJECT must not fall through to direct");
    const std::string route = "/proxies/" + urlEncode("测试 分组");
    require(responseFor("PUT", route, R"({"name":"DIRECT"})") == "{}", "Unicode group selection failed");
    require(loadConfigLocked(path, error) && g_state.groups[0].now == "DIRECT", "Node selection must survive reload");
    require(responseFor("PUT", route, R"({"name":"missing"})").find("error") != std::string::npos, "Nonmember node selection must fail");
    { std::ofstream out(path); out << "proxies: ["; }
    require(!loadConfigLocked(path, error) && g_state.groups[0].now == "DIRECT", "Invalid reload must preserve active state");
    require(rulesJson().find("google.com") != std::string::npos, "Rules endpoint must contain real rules");
    require(!startCore("", 0) && !startCore("", 65536), "Invalid controller port must fail before opening a listener");
    require(responseFor("GET", "/configs", "").find(jsonEscape(path)) != std::string::npos, "Controller exposes active configuration path for UI reattachment");
    require(setRuntimeMode("Global"), "Background handoff can restore the actual runtime mode");
    const std::string runtime = runtimeInfo();
    require(runtime.find("\"configPath\":\"" + jsonEscape(path)) != std::string::npos &&
        runtime.find("\"mode\":\"Global\"") != std::string::npos && runtime.find("\"socksPort\":7891") != std::string::npos,
        "Background owner metadata contains path, mode and listening port");
    require(!setRuntimeMode("invalid") && g_state.mode == "Global", "Bad mode must preserve existing background state");
    std::ifstream input(original);
    require(input.good(), "Requested configuration fixture must exist and be readable");
    {
        std::string content((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
        ParsedConfig user;
        if (!parseConfigText(content, user, error)) throw std::runtime_error("Configuration fixture: " + error);
        require(true, "Configuration fixture is compatible");
        std::cout << "Configuration fixture: " << user.nodes.size() << " nodes, " << user.groups.size() << " groups, " << user.rules.size() << " rules\n";
    }
}
std::mutex connectorMutex;
std::map<std::string, int> connectorSockets;
std::vector<std::pair<std::string, int>> dials;

void setupRuntime() {
    std::lock_guard<std::mutex> guard(g_state.mutex);
    g_state.mode = "Direct";
    g_state.groups.clear(); g_state.nodes.clear(); g_state.rules.clear();
    g_state.running.store(true);
    g_testConnector = [](const std::string& host, int port, int) {
        std::lock_guard<std::mutex> lock(connectorMutex);
        dials.push_back({host, port});
        const auto found = connectorSockets.find(host);
        if (found == connectorSockets.end()) return -1;
        const int fd = found->second; connectorSockets.erase(found); return fd;
    };
}
void pairFor(int (&pair)[2]) { makePair(pair); socketTimeout(pair[0], 2000); socketTimeout(pair[1], 2000); }
void connector(const std::string& host, int fd) {
    std::lock_guard<std::mutex> guard(connectorMutex); connectorSockets[host] = fd;
}
void awaitCondition(const std::function<bool()>& condition, const char* error) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (!condition() && std::chrono::steady_clock::now() < deadline) std::this_thread::sleep_for(std::chrono::milliseconds(2));
    require(condition(), error);
}
void workersIdle() {
    std::unique_lock<std::mutex> lock(g_state.sessionsMutex);
    const bool idle = g_state.workersDone.wait_for(lock, std::chrono::seconds(3), [] { return g_state.workers.load() == 0; });
    require(idle, "Workers did not finish after socket shutdown");
}
std::string receiveN(int fd, size_t length) {
    std::string result(length, '\0');
    require(readExact(fd, result.data(), length), "Expected payload did not arrive");
    return result;
}
std::string controlRequest(const std::string& method, const std::string& path) {
    int control[2]; pairFor(control);
    dispatchWorker(control[0], 3);
    sendAll(control[1], method + " " + path + " HTTP/1.1\r\nHost: localhost\r\n\r\n");
    std::string response;
    char buffer[2048];
    ssize_t count;
    while ((count = recv(control[1], buffer, sizeof(buffer), 0)) > 0) response.append(buffer, static_cast<size_t>(count));
    close(control[1]);
    if (method == "DELETE" && path.rfind("/connections", 0) == 0) {
        require(response.rfind("HTTP/1.1 204", 0) == 0 && response.substr(response.find("\r\n\r\n") + 4).empty(), "Connection disconnect must return 204 without a body");
    } else require(response.rfind("HTTP/1.1 200", 0) == 0, "Controller endpoint failed");
    return response;
}
std::string connectionId(const std::string& host) {
    std::lock_guard<std::mutex> guard(g_state.sessionsMutex);
    for (const auto& entry : g_state.connections) if (entry.second.host == host) return entry.second.id;
    return "";
}

void forwardingTests() {
    setupRuntime();
    const std::string response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello";
    {
        int client[2], origin[2]; pairFor(client); pairFor(origin);
        connector("http.test", origin[0]);
        const uint64_t up = g_state.uploadTotal.load(), down = g_state.downloadTotal.load();
        dispatchWorker(client[0], 0);
        const std::string request = "POST http://http.test/upload?q=1 HTTP/1.1\r\nHost: http.test\r\nContent-Length: 11\r\nProxy-Authorization: dummy-test\r\nProxy-Connection: keep-alive\r\n\r\nhello-world";
        require(sendAll(client[1], request), "Send HTTP POST to proxy");
        std::string forwarded = readUntilHeaders(origin[1]);
        const size_t header = forwarded.find("\r\n\r\n");
        require(header != std::string::npos, "Origin did not receive HTTP headers");
        if (forwarded.size() < header + 4 + 11) forwarded += receiveN(origin[1], header + 4 + 11 - forwarded.size());
        require(forwarded.rfind("POST /upload?q=1 HTTP/1.1", 0) == 0, "Absolute-form URL must become origin-form");
        require(forwarded.substr(header + 4) == "hello-world", "HTTP body in the initial read must not be dropped");
        require(forwarded.find("Proxy-Authorization") == std::string::npos && forwarded.find("Proxy-Connection") == std::string::npos, "Proxy credentials must not reach origin");
        {
            std::lock_guard<std::mutex> lock(connectorMutex);
            require(dials.back() == std::make_pair(std::string("http.test"),80), "Plain HTTP must default to port 80");
        }
        require(sendAll(origin[1], response), "Origin response write");
        require(receiveN(client[1], response.size()) == response, "HTTP response must be forwarded intact");
        awaitCondition([&] { return g_state.downloadTotal.load() >= down + response.size(); }, "Download accounting missed forwarded bytes");
        require(g_state.uploadTotal.load() - up == forwarded.size(), "Upload accounting must reflect actual origin bytes");
        const std::string snapshot = controlRequest("GET", "/connections");
        require(snapshot.find("http.test") != std::string::npos && snapshot.find("\"destinationPort\":\"80\"") != std::string::npos, "Connections endpoint needs actual target metadata");
        require(snapshot.find("\"download\":" + std::to_string(response.size())) != std::string::npos, "Per-connection byte accounting is missing");
        shutdown(client[1], SHUT_WR); shutdown(origin[1], SHUT_WR);
        close(client[1]); close(origin[1]); workersIdle();
        require(connectionId("http.test").empty(), "Completed HTTP connection must leave active table");
        require(g_state.downloadTotal.load() >= down + response.size(), "Totals must survive completed connections");
    }
    {
        int client[2], origin[2]; pairFor(client); pairFor(origin);
        connector("tunnel.test", origin[0]);
        dispatchWorker(client[0], 2);
        sendAll(client[1], "CONNECT tunnel.test:443 HTTP/1.1\r\nHost: tunnel.test:443\r\n\r\nearly-payload");
        require(readUntilHeaders(client[1]).find("200 Connection Established") != std::string::npos, "CONNECT handshake missing");
        require(receiveN(origin[1], 13) == "early-payload", "CONNECT payload coalesced with headers must be retained");
        sendAll(client[1], "tail"); shutdown(client[1], SHUT_WR);
        require(receiveN(origin[1], 4) == "tail", "CONNECT continuation dropped");
        char byte;
        require(recv(origin[1], &byte, 1, 0) == 0, "Client half-close must reach upstream");
        sendAll(origin[1], "after-half-close"); shutdown(origin[1], SHUT_WR);
        require(receiveN(client[1], 16) == "after-half-close", "Half-closed client must still receive response");
        close(client[1]); close(origin[1]); workersIdle();
    }
    {
        int client[2], origin[2]; pairFor(client); pairFor(origin);
        connector("socks.test", origin[0]);
        dispatchWorker(client[0], 2);
        const std::string host = "socks.test";
        std::vector<unsigned char> handshake = {5,1,0,5,1,0,3,static_cast<unsigned char>(host.size())};
        handshake.insert(handshake.end(),host.begin(),host.end()); handshake.push_back(0x20); handshake.push_back(0xfb);
        sendAll(client[1],handshake);
        require(receiveN(client[1],2) == std::string("\5\0",2), "SOCKS anonymous negotiation failed");
        const std::string accepted = receiveN(client[1],10);
        require(accepted[1] == 0, "SOCKS CONNECT failed");
        sendAll(client[1],"socks-data");
        require(receiveN(origin[1],10) == "socks-data", "SOCKS target payload not forwarded");
        const std::string id = connectionId("socks.test");
        require(!id.empty(), "SOCKS connection must have cancellable identifier");
        controlRequest("DELETE","/connections/"+id);
        char byte;
        require(recv(client[1],&byte,1,0) == 0, "Deleting a connection must close client socket");
        require(recv(origin[1],&byte,1,0) == 0, "Deleting a connection must close origin socket");
        close(client[1]); close(origin[1]); workersIdle();
        require(connectionId("socks.test").empty(), "Deleted SOCKS connection remained active");
    }
    {
        int client[2]; pairFor(client); dispatchWorker(client[0],1);
        const char onlyPassword[] = {5,1,2}; sendAll(client[1],onlyPassword,3);
        require(receiveN(client[1],2) == std::string("\5\xff",2), "SOCKS must reject unavailable authentication methods");
        close(client[1]); workersIdle();
    }
    {
        int a[2], b[2], left[2], right[2]; pairFor(a); pairFor(b); pairFor(left); pairFor(right);
        connector("first.test",left[0]); connector("second.test",right[0]);
        dispatchWorker(a[0],0); dispatchWorker(b[0],0);
        sendAll(a[1],"CONNECT first.test:443 HTTP/1.1\r\nHost: first.test\r\n\r\n");
        sendAll(b[1],"CONNECT second.test:443 HTTP/1.1\r\nHost: second.test\r\n\r\n");
        require(readUntilHeaders(a[1]).find("200") != std::string::npos && readUntilHeaders(b[1]).find("200") != std::string::npos, "Parallel proxy sessions failed");
        require(!connectionId("first.test").empty() && !connectionId("second.test").empty(), "Two sessions must coexist");
        controlRequest("DELETE","/connections/"+connectionId("first.test"));
        sendAll(right[1],"still-open");
        require(receiveN(b[1],10) == "still-open", "Cancelling one session must preserve other sessions");
        controlRequest("DELETE","/connections");
        char byte;
        require(recv(b[1],&byte,1,0) == 0, "DELETE all must shut down remaining sessions");
        close(a[1]); close(b[1]); close(left[1]); close(right[1]); workersIdle();
    }
    {
        int client[2], encrypted[2]; pairFor(client); pairFor(encrypted);
        connector("ss-server.test",encrypted[0]);
        ProxyNode node; node.name="SS test"; node.type="ss"; node.server="ss-server.test"; node.port=9001;
        node.cipher="aes-256-gcm"; node.password=GOLDEN_PASSWORD;
        {
            std::lock_guard<std::mutex> lock(g_state.mutex);
            g_state.mode="Rule"; g_state.nodes={node};
            ProxyGroup group; group.name="PROXY"; group.now=node.name; group.proxies={node.name,"DIRECT"};
            g_state.groups={group}; g_state.rules={{"match","","PROXY"}};
        }
        const uint64_t up=g_state.uploadTotal.load(),down=g_state.downloadTotal.load();
        dispatchWorker(client[0],0);
        sendAll(client[1],"CONNECT www.google.com:443 HTTP/1.1\r\nHost: www.google.com\r\n\r\nclient-data");
        const std::string salt=receiveN(encrypted[1],32);
        const auto key=hkdfSha1({salt.begin(),salt.end()},evpBytesToKey(GOLDEN_PASSWORD,32),"ss-subkey",32);
        std::vector<unsigned char> nonce(12,0),plain;
        require(shadowsocksReadChunk(encrypted[1],key,nonce,plain),"SS outbound target header missing");
        require(plain==shadowsocksAddress("www.google.com",443),"SS route must carry actual destination");
        require(readUntilHeaders(client[1]).find("200") != std::string::npos,"SS CONNECT handshake failed");
        require(shadowsocksReadChunk(encrypted[1],key,nonce,plain) && text(plain)=="client-data","TLS tunnel bytes must be encrypted through selected SS node");
        const auto packet=hex(GOLDEN_SERVER_PACKET);
        for (unsigned char byte:packet) sendAll(encrypted[1],reinterpret_cast<const char*>(&byte),1);
        const std::string expected="HTTP/1.1 204 No Content\r\n\r\nserver data";
        require(receiveN(client[1],expected.size())==expected,"SS reference response must reach HTTP tunnel intact");
        awaitCondition([&]{return g_state.downloadTotal.load()>=down+expected.size();},"Encrypted download accounting failed");
        require(g_state.uploadTotal.load()-up==11,"SS accounting must exclude salt and encrypted framing");
        const std::string snapshot=controlRequest("GET","/connections");
        require(snapshot.find("SS test")!=std::string::npos && snapshot.find("PROXY")!=std::string::npos,"Connection must show resolved node and original proxy group");
        shutdown(client[1],SHUT_WR); shutdown(encrypted[1],SHUT_WR);
        close(client[1]); close(encrypted[1]); workersIdle();
    }
    require(controlRequest("GET","/clahsos/logs?since=0").find("socks.test")!=std::string::npos,"Native request logs must expose actual proxy activity");
    workersIdle();
    {
        std::lock_guard<std::mutex> lock(g_state.sessionsMutex);
        require(g_state.connections.empty() && g_state.sockets.empty(),"Completed workers must not leak tracked sockets or sessions");
    }
}

void latencyAndRuleTests() {
    TestTarget target;
    require(parseTestUrl("http://probe.test:8080/generate_204?a=1#fragment",target) && target.host=="probe.test" && target.port==8080 && target.path=="/generate_204?a=1","Test URL parsing");
    require(!parseTestUrl("http://probe.test:80junk/",target),"Invalid URL port must be rejected");
    require(parseTestUrl("https://probe.test/",target)&&target.tls&&target.port==443,"HTTPS probe URL parsing");
    require(!parseTestUrl("http://probe.test/\r\nInjected",target),"HTTP test URL must reject injected headers");
    require(cidrMatches("10.1.2.3","10.0.0.0/8",AF_INET) && !cidrMatches("11.1.2.3","10.0.0.0/8",AF_INET),"IPv4 CIDR matching");
    require(cidrMatches("2001:db8::1","2001:db8::/32",AF_INET6) && !cidrMatches("2001:db9::1","2001:db8::/32",AF_INET6),"IPv6 CIDR matching");
    require(!cidrMatches("10.1.2.3","10.0.0.0/8garbage",AF_INET),"Invalid CIDR prefix must fail");
    require(ruleMatches({"dst-port","25","DIRECT"},"mail.test",25) && !ruleMatches({"dst-port","25","DIRECT"},"mail.test",443),"Destination port routing");
    require(ruleMatches({"domain-suffix","example.com","DIRECT"},"WWW.EXAMPLE.COM.",443),"Domain canonicalization");
    const std::string path="/proxies/DIRECT/delay?timeout=1000&url="+urlEncode("http://probe.test:8080/generate_204");
    for (const int code:{204,503}) {
        int peer[2]; pairFor(peer); connector("probe.test",peer[0]);
        auto remote=std::async(std::launch::async,[&,code]() {
            const std::string request=readUntilHeaders(peer[1]);
            sendAll(peer[1],"HTTP/1.1 "+std::to_string(code)+" Result\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            close(peer[1]); return request;
        });
        const std::string result=delayResponse(path);
        const std::string request=remote.get();
        require(request.rfind("GET /generate_204 HTTP/1.1",0)==0,"Delay endpoint must send an actual HTTP request");
        require((result.find("\"delay\":")!=std::string::npos)==(code==204),"Latency success must depend on a successful response");
        require(g_state.delays["DIRECT"]>=0 && ((g_state.delays["DIRECT"]>0)==(code==204)),"Delay history must record success or failure truthfully");
    }
    {
        int peer[2]; pairFor(peer); connector("ss-server.test",peer[0]);
        auto remote=std::async(std::launch::async,[&]() {
            const std::string salt=receiveN(peer[1],32);
            const auto key=hkdfSha1({salt.begin(),salt.end()},evpBytesToKey(GOLDEN_PASSWORD,32),"ss-subkey",32);
            std::vector<unsigned char> nonce(12,0),address,request;
            const bool decoded=shadowsocksReadChunk(peer[1],key,nonce,address) && shadowsocksReadChunk(peer[1],key,nonce,request);
            sendAll(peer[1],hex(GOLDEN_SERVER_PACKET)); close(peer[1]);
            return decoded && address==shadowsocksAddress("probe.test",80) && text(request).rfind("GET /generate_204 HTTP/1.1",0)==0;
        });
        const std::string result=delayResponse("/proxies/PROXY/delay?timeout=1000&url="+urlEncode("http://probe.test/generate_204"));
        require(remote.get(),"Group latency test must use the selected encrypted node");
        require(result.find("\"delay\":")!=std::string::npos,"Encrypted HTTP probe must validate a server response");
    }
    require(delayResponse("/proxies/REJECT/delay?url="+urlEncode("http://probe.test/")).find("error")!=std::string::npos,"REJECT cannot appear as a working proxy");
    const std::string diagnostic=diagnosticsJson();
    require(diagnostic.find("\"aesEncrypt\":true")!=std::string::npos,"AES-GCM short-block known answer self-test");
    require(diagnostic.find("\"aesDecrypt\":true")!=std::string::npos,"AES-GCM device decryption self-test");
    require(diagnostic.find("\"authentication\":true")!=std::string::npos,"AES-GCM self-test must reject a corrupt tag");
    require(diagnostic.find("\"listeners\":false")!=std::string::npos && diagnostic.find("\"passed\":false")!=std::string::npos,"Self-test must not invent active TCP listeners in host harness");
    {
        int pair[2];pairFor(pair);
        ProxyStream stream;stream.fd=pair[0];stream.encrypted=true;stream.sendKey=hex(GOLDEN_KEY);stream.sendNonce.assign(12,0);
        std::string large(35000,'x');for(size_t i=0;i<large.size();++i)large[i]=static_cast<char>(i%256);
        auto writer=std::async(std::launch::async,[&]{return streamWrite(stream,large.data(),large.size());});
        std::vector<unsigned char> nonce(12,0),part;
        std::string rebuilt;
        for(int i=0;i<3;++i){require(shadowsocksReadChunk(pair[1],stream.sendKey,nonce,part),"Large encrypted stream chunk failed");rebuilt.append(part.begin(),part.end());}
        require(writer.get() && rebuilt==large,"Large payload must survive SS 0x3fff framing boundary");
        require(stream.sendNonce[0]==6,"Multi-chunk stream nonce progression");
        close(pair[1]);
    }
    {
        int client[2],peer[2];pairFor(client);pairFor(peer);connector("shutdown.test",peer[0]);
        {std::lock_guard<std::mutex> lock(g_state.mutex);g_state.mode="Direct";}
        dispatchWorker(client[0],0);
        sendAll(client[1],"CONNECT shutdown.test:443 HTTP/1.1\r\nHost: shutdown.test\r\n\r\n");
        require(readUntilHeaders(client[1]).find("200 Connection Established")!=std::string::npos,"Prepare live connection for shutdown audit");
        require(!connectionId("shutdown.test").empty(),"Shutdown test requires an actual live worker");
        stopCore();
        char byte;
        require(recv(client[1],&byte,1,0)==0 && recv(peer[1],&byte,1,0)==0,"Stopping core must cancel both sides of live sessions");
        close(client[1]);close(peer[1]);
    }
    stopCore();
    require(g_state.workers.load()==0,"Core shutdown must finish active workers");
    g_testConnector=nullptr;
}

#include "udp_core_test.inc"
#include "vmess_core_test.inc"
#include "group_health_test.inc"
#include "provider_core_test.inc"
#include "load_balance_test.inc"
#include "ss_aead_test.inc"
#include "trojan_core_test.inc"
#include "rule_provider_test.inc"
#include "dns_core_test.inc"
#include "dns_hosts_test.inc"
#include "dns_listener_test.inc"
#include "geo_core_test.inc"
#include "port_settings_test.inc"
#include "rule_edits_test.inc"
#include "object_edits_test.inc"
#include "share_links_test.inc"
#include "config_merges_test.inc"
#include "config_scripts_test.inc"
#include "controller_api_test.inc"
#include "controller_state_test.inc"
#include "backup_codec_test.inc"
#include "controller_configs_test.inc"
#include "inbound_test.inc"
#include "sniffer_forward_test.inc"
#include "sniffer_test.inc"
#include "vless_core_test.inc"
#include "forward_proxy_test.inc"
#include "yaml_merges_test.inc"
#include "ss_duplex_test.inc"
#include "dialer_proxy_test.inc"
#include "tls_failure_test.inc"

int main(int argc, char** argv) {
    std::signal(SIGPIPE, SIG_IGN);
    try {
        if (argc == 3 && std::string(argv[1]) == "archive-yaml") {
            std::ifstream input(argv[2], std::ios::binary); std::string source((std::istreambuf_iterator<char>(input)), {}), output, error;
            if (!backupYamlText(source, output, error)) throw std::runtime_error(error);
            std::cout << output; return 0;
        }
        if (argc == 4 && std::string(argv[3]) == "archive") { backupCodecTests(argv[2]); std::cout << "PASS " << checks << " archive assertions\n"; return 0; }
        if (argc == 4 && std::string(argv[3]) == "vless") { vlessTests(argv[2]); shareLinkTests(); objectEditsTests(argv[2]); std::cout << "PASS " << checks << " VLESS assertions (independent OpenSSL protocol peer, ingress, UDP, HTTPS, imports and editing)\n"; return 0; }
        if (argc == 4 && std::string(argv[3]) == "forward") { forwardProxyTests(argv[2]); shareLinkTests(); objectEditsTests(argv[2]); std::cout << "PASS " << checks << " forward proxy assertions (independent HTTP/SOCKS/OpenSSL/UDP peers)\n"; return 0; }
        if (argc == 4 && std::string(argv[3]) == "providers") { providerTests(argv[2]); std::cout << "PASS " << checks << " provider assertions (independent OpenSSL peers and real cache lifecycle)\n"; return 0; }
        if (argc == 4 && std::string(argv[3]) == "dialer") { dialerProxyTests(argv[2]); std::cout << "PASS " << checks << " dialer-proxy assertions\n"; return 0; }
        if (argc == 4 && std::string(argv[3]) == "tls") { tlsFailureTests(); std::cout << "PASS " << checks << " independent TLS failure assertions\n"; return 0; }
        if (argc == 4 && std::string(argv[3]) == "groups") { groupHealthTests(argv[2]); loadBalanceTests(argv[2]); std::cout << "PASS " << checks << " health/load-balance assertions\n"; return 0; }
        if (argc == 4 && std::string(argv[3]) == "yaml") { yamlMergeTests(argv[2]); std::cout << "PASS " << checks << " YAML template assertions (configuration, scripts, providers, editing, export and independent protocol peers)\n"; return 0; }
        if (argc == 4 && std::string(argv[3]) == "ss-duplex") { ssIncrementalTests(); ssDuplexTests(argv[2]); ssAeadTests(); std::cout << "PASS " << checks << " SS duplex assertions (independent AEAD peers, every vector split/EOF, actual ingress, UDP and HTTPS)\n"; return 0; }
        if (argc == 4 && std::string(argv[3]) == "hosts") { dnsHostsTests(argv[2]); vmessDuplexTests(argv[2]); vmessTests(argv[2]); dnsTests(argv[2]); ssAeadTests(); std::cout << "PASS " << checks << " hosts assertions (independent SS/VMess/Trojan peers)\n"; return 0; }
        require(argc == 3 || (argc == 4 && (std::string(argv[3]) == "api"||std::string(argv[3]) == "rules"||std::string(argv[3])=="dns"||std::string(argv[3])=="geo"||std::string(argv[3])=="ports"||std::string(argv[3])=="rule-edits"||std::string(argv[3])=="object-edits"||std::string(argv[3])=="share-links"||std::string(argv[3])=="merges"||std::string(argv[3])=="scripts"||std::string(argv[3])=="configs"||std::string(argv[3])=="inbound"||std::string(argv[3])=="sniffer")), "Expected configuration and temp directory, optionally api/rules/dns/geo/ports/rule-edits/object-edits/share-links/merges/scripts suite");
        if (argc == 4 && std::string(argv[3]) == "sniffer") { snifferTests(argv[2]); std::cout << "PASS " << checks << " sniffer assertions\n"; return 0; }
        if (argc == 4 && std::string(argv[3]) == "inbound") { inboundTests(argv[2]); std::cout << "PASS " << checks << " inbound assertions\n"; return 0; }
        if (argc == 4) {
            if(std::string(argv[3])=="configs")controllerConfigTests(argv[2]);else if(std::string(argv[3])=="api"){controllerApiTests(argv[2]);controllerAuthTests(argv[2]);controllerStateTests(argv[2]);}else if(std::string(argv[3])=="scripts")configScriptTests(argv[2]);else if(std::string(argv[3])=="merges")configMergeTests(argv[2]);else if(std::string(argv[3])=="share-links")shareLinkTests();else if(std::string(argv[3])=="object-edits")objectEditsTests(argv[2]);else if(std::string(argv[3])=="rule-edits")ruleEditsTests(argv[2]);else if(std::string(argv[3])=="dns"){dnsTests(argv[2]);dnsListenerTests(argv[2]);}else if(std::string(argv[3])=="geo")geoTests(argv[2]);else if(std::string(argv[3])=="ports")proxyPortTests(argv[2]);else ruleProviderTests(argv[2]);
            std::cout << "PASS " << checks << " " << argv[3] << " assertions (shipping YAML/Zstandard/Mbed TLS backends)\n";
            return 0;
        }
        ssIncrementalTests(); ssDuplexTests(argv[2]); yamlMergeTests(argv[2]); snifferTests(argv[2]); inboundTests(argv[2]); controllerConfigTests(argv[2]); backupCodecTests(argv[2]); controllerApiTests(argv[2]); controllerAuthTests(argv[2]);controllerStateTests(argv[2]); configScriptTests(argv[2]); configMergeTests(argv[2]); shareLinkTests(); objectEditsTests(argv[2]); ruleEditsTests(argv[2]); protocolTests(); configurationTests(argv[1], argv[2]); forwardingTests(); latencyAndRuleTests();
        udpProtocolTests(); udpForwardingTests(); vlessTests(argv[2]); forwardProxyTests(argv[2]); dialerProxyTests(argv[2]); tlsFailureTests();
        vmessTests(argv[2]);httpsProbeTests();groupHealthTests(argv[2]);providerTests(argv[2]);loadBalanceTests(argv[2]);ssAeadTests();trojanTests(argv[2]);ruleProviderTests(argv[2]);dnsHostsTests(argv[2]);vmessDuplexTests(argv[2]);dnsTests(argv[2]);dnsListenerTests(argv[2]);geoTests(argv[2]);proxyPortTests(argv[2]);
        std::cout << "PASS " << checks << " assertions (shipping Mbed TLS backend; Harmony networking still requires device verification)\n";
        return 0;
    } catch (const std::exception& error) {
        stopCore();
        std::cerr << "FAIL: " << error.what() << '\n'; return 1;
    }
}
