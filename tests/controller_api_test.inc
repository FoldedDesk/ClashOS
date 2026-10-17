// Real shipping controller, JSON parser and socket workers; no TCP bind or API shim.
std::string apiReadLine(int fd)
{
    std::string line;
    while (line.size() < 4096) { const std::string ch = receiveN(fd, 1); if (ch == "\n") return line; line += ch; }
    throw std::runtime_error("Controller JSON line exceeded limit");
}
uint64_t apiNumber(const std::string& text, const char* field)
{
    EditorYaml parsed; std::string error;
    require(parsed.parse(text, 65536, error), "Controller must emit valid JSON");
    const std::string number = yamlText(yamlValue(parsed.document, yaml_document_get_root_node(&parsed.document), field));
    require(!number.empty() && number.find_first_not_of("0123456789") == std::string::npos, "Traffic fields must be unsigned integers");
    return std::stoull(number);
}
std::string apiMasked(unsigned char opcode, const std::string& payload, bool final = true)
{
    require(payload.size() <= 125, "Test control frame too large");
    std::string frame{static_cast<char>((final ? 0x80 : 0) | opcode), static_cast<char>(0x80 | payload.size()), 1, 2, 3, 4};
    for (size_t i = 0; i < payload.size(); ++i) frame += static_cast<char>(payload[i] ^ (1 + i % 4));
    return frame;
}
std::pair<unsigned char, std::string> apiFrame(int fd)
{
    const std::string first = receiveN(fd, 2);
    require((static_cast<unsigned char>(first[0]) & 0xf0) == 0x80 && !(static_cast<unsigned char>(first[1]) & 0x80), "Server WebSocket frames must be final, unmasked and have no RSV flags");
    uint64_t size = static_cast<unsigned char>(first[1]);
    if (size == 126 || size == 127) {
        const std::string bytes = receiveN(fd, size == 126 ? 2 : 8); size = 0;
        for (unsigned char ch : bytes) size = (size << 8) | ch;
    }
    require(size <= 1024 * 1024, "Unexpected oversized controller frame");
    return {static_cast<unsigned char>(first[0] & 15), receiveN(fd, size)};
}
const std::string API_WS = "GET /traffic HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive, Upgrade\r\nUpgrade: WebSocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n";
std::string apiHeaders(int fd)
{
    std::string header; char byte;
    while (header.size() < 65536) {
        if (!readExact(fd, &byte, 1)) throw std::runtime_error("Controller headers were interrupted");
        header += byte;
        if (header.size() >= 4 && header.compare(header.size() - 4, 4, "\r\n\r\n") == 0) return header;
    }
    throw std::runtime_error("Controller headers exceeded limit");
}
std::string apiHttp(const std::string& request)
{
    int pair[2]; pairFor(pair); dispatchWorker(pair[0], 3); require(sendAll(pair[1], request), "Controller request write failed");
    std::string response; char bytes[2048]; ssize_t size;
    while ((size = recv(pair[1], bytes, sizeof(bytes), 0)) > 0) response.append(bytes, size);
    close(pair[1]); return response;
}
int apiSubscribe(const std::string& request, bool websocket = false, const std::string& early = "")
{
    int pair[2]; pairFor(pair); socketTimeout(pair[1], 4000); dispatchWorker(pair[0], 3);
    require(sendAll(pair[1], request + "\r\n" + early), "Traffic subscription write failed");
    const std::string header = apiHeaders(pair[1]);
    require(header.rfind(websocket ? "HTTP/1.1 101" : "HTTP/1.1 200", 0) == 0, "Traffic subscription failed");
    if (websocket) require(header.find("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") != std::string::npos, "WebSocket acceptance must match the independent RFC 6455 vector");
    else require(header.find("Content-Type: application/json") != std::string::npos && header.find("Content-Length:") == std::string::npos, "HTTP traffic must remain a streaming JSON response");
    return pair[1];
}

void controllerApiTests(const std::string& directory)
{
    stopCore(); workersIdle();
    const std::string profile = directory + "/controller-api.yaml";
    const std::string source = R"(port: 0
socks-port: 0
proxies:
  - {name: 节点😀, type: ss, server: private-server.invalid, port: 443, cipher: aes-128-gcm, password: SYNTHETIC-API-SECRET, udp: true}
  - {name: 'a+b /?%"尾', type: direct}
proxy-groups:
  - {name: '分组+空 格/测试', type: select, proxies: [DIRECT, 节点😀, REJECT]}
  - {name: 'a+b', type: select, proxies: [DIRECT, REJECT]}
  - {name: no-udp, type: select, proxies: [DIRECT], disable-udp: true}
proxy-providers:
  inline-test:
    type: inline
    payload: [{name: provider-node, type: direct}]
rules: ['MATCH,DIRECT']
)";
    { std::ofstream file(profile); file << source; }
    std::string error; require(loadConfigLocked(profile, error), "Public controller fixture must load without opening listeners");
    const std::string escaped = urlEncode("分组+空 格/测试"), nodePath = "/proxies/" + urlEncode("节点😀");
    auto detail = [&](const std::string& name) { return responseFor("GET", "/proxies/" + urlEncode(name), ""); };
    for (const std::string& name : {std::string("DIRECT"), std::string("REJECT"), std::string("节点😀"), std::string("a+b /?%\"尾"), std::string("分组+空 格/测试"), std::string("provider-node")}) {
        const std::string value = detail(name); require(value.find("\"name\":\"" + jsonEscape(name) + '"') != std::string::npos,
            ("Proxy detail failed for public fixture " + name + ": " + value).c_str());
        require(value.find("private-server.invalid") == std::string::npos && value.find("SYNTHETIC-API-SECRET") == std::string::npos, "Proxy detail must not reveal node connection credentials");
        require(proxiesJson().find(value) != std::string::npos, "List and detail must use the same runtime representation");
    }
    require(detail("DIRECT").find("\"type\":\"DIRECT\"") != std::string::npos && detail("节点😀").find("\"type\":\"Shadowsocks\"") != std::string::npos, "Types must use standard controller names");
    require(detail("provider-node").find("\"provider-name\":\"inline-test\"") != std::string::npos, "Provider membership must be included without credentials");
    require(responseFor("GET", "/proxies/a+b?ignored=1", "").find("\"name\":\"a+b\"") != std::string::npos, "Literal plus signs in paths must not become spaces");
    require(responseFor("GET", "/proxies/" + escaped + "/?ignored=1", "") == detail("分组+空 格/测试"), "Trailing slashes and query strings must not alter encoded names");
    for (const std::string& raw : {"%", "%0", "%GG", "%00", "%0a", "%7F", ""}) require(responseFor("GET", "/proxies/" + raw, "").find("Invalid proxy path") != std::string::npos, "Invalid path encoding must fail rather than target another proxy");
    const std::string route = "/proxies/" + escaped;
    require(responseFor("PUT", route, R"({"name":"\u8282\u70b9\ud83d\ude00"})") == "{}" && detail("分组+空 格/测试").find("\"now\":\"节点😀\"") != std::string::npos, "JSON Unicode escapes and surrogate pairs must select the actual node");
    for (const std::string& invalid : {std::string("{}"), std::string(R"({"other":"DIRECT"})"), std::string(R"({"name":42})"), std::string(R"(["DIRECT"])"), std::string(R"({"name":"DIRECT"}junk)"), std::string(65537, ' ')}) {
        require(responseFor("PUT", route, invalid).find("error") != std::string::npos, "Invalid selection JSON must be rejected");
        require(detail("分组+空 格/测试").find("\"now\":\"节点😀\"") != std::string::npos, "Rejected selections must preserve runtime state");
    }
    g_state.delays["节点😀"] = 123;
    require(detail("节点😀").find("\"alive\":true") != std::string::npos && detail("节点😀").find("\"delay\":123") != std::string::npos, "Detail must expose real latest health results");
    require(detail("no-udp").find("\"udp\":false") != std::string::npos && detail("分组+空 格/测试").find("\"udp\":true") != std::string::npos, "Group UDP capability must follow actual selection and disable-udp");
    require(readTestFile(profile) == source, "Controller selections must not rewrite source configurations");
    g_state.running.store(true);
    require(apiHttp("GET /proxies/missing HTTP/1.1\r\nHost: localhost\r\n\r\n").rfind("HTTP/1.1 404", 0) == 0, "Missing proxies need a real HTTP 404");
    require(apiHttp("GET " + nodePath + " HTTP/1.1\r\nHost: localhost\r\n\r\n").rfind("HTTP/1.1 200", 0) == 0, "Proxy detail must work through the actual HTTP worker");
    for (const std::string& invalid : {"GET /traffic HTTP/2.0", "GET /traffic HTTP/1.1 extra", "GET /version", "PUT /proxies/a+b wrong HTTP/1.1"})
        require(apiHttp(invalid + "\r\nHost: localhost\r\n\r\n").rfind("HTTP/1.1 400", 0) == 0, "Malformed request lines must not resolve a different resource or create a subscriber");
    const std::string selectedBody = R"({"name":"\u8282\u70b9\ud83d\ude00"})";
    require(apiHttp("PUT " + route + " HTTP/1.1\r\nHost: localhost\r\nContent-Length: " + std::to_string(selectedBody.size()) + "\r\n\r\n" + selectedBody).rfind("HTTP/1.1 204", 0) == 0, "Successful proxy selections return standard HTTP 204");

    const auto at = HealthClock::now(); ControllerTrafficSample exact(10, 20, at);
    const std::string averaged = exact.sample(110, 220, at + std::chrono::seconds(2));
    require(apiNumber(averaged, "up") == 50 && apiNumber(averaged, "down") == 100 && apiNumber(averaged, "upTotal") == 110, "Rates must be bytes per second while totals remain bytes");
    require(apiNumber(exact.sample(0, 0, at + std::chrono::seconds(3)), "up") == 0, "Counter reset must not underflow into a false huge rate");
    g_state.uploadTotal.store(100); g_state.downloadTotal.store(200);
    const std::string httpRequest = "GET /traffic HTTP/1.1\r\nHost: localhost\r\n";
    int http = apiSubscribe(httpRequest);
    const std::string first = apiReadLine(http); require(apiNumber(first, "up") == 0 && apiNumber(first, "upTotal") == 100, "First idle stream sample must report actual counters");
    int ws = apiSubscribe(API_WS, true, apiMasked(9, std::string("p\0ng", 4)));
    auto frame = apiFrame(ws); require(frame.first == 10 && frame.second == std::string("p\0ng", 4),
        ("Coalesced ping response: opcode=" + std::to_string(frame.first) + " size=" + std::to_string(frame.second.size()) + " payload=" + jsonEscape(frame.second)).c_str());
    frame = apiFrame(ws); require(frame.first == 1 && apiNumber(frame.second, "downTotal") == 200, "WebSocket text frames carry actual traffic JSON");
    g_state.uploadTotal.fetch_add(5000); g_state.downloadTotal.fetch_add(6000);
    frame = apiFrame(ws); require(frame.first == 1 && apiNumber(frame.second, "up") > 0 && apiNumber(frame.second, "upTotal") == 5100 && apiNumber(frame.second, "downTotal") == 6200, "Live traffic must update WebSocket rates and totals");
    std::string httpValue;
    for (int i = 0; i < 4; ++i) { httpValue = apiReadLine(http); if (apiNumber(httpValue, "upTotal") == 5100) break; }
    require(apiNumber(httpValue, "upTotal") == 5100 && apiNumber(httpValue, "downTotal") == 6200, "Independent HTTP and WS subscribers observe the same real counters");
    const std::string ping = apiMasked(9, "fragmented-wire"); require(sendAll(ws, ping.substr(0, 1)), "Write partial WebSocket header");
    frame = apiFrame(ws); require(frame.first == 1 && apiNumber(frame.second, "up") == 0, "Incomplete client control frames must not block outbound traffic ticks");
    require(sendAll(ws, ping.substr(1)), "Complete partial WebSocket frame"); frame = apiFrame(ws); require(frame.first == 10 && frame.second == "fragmented-wire", "Partial control frames must resume exactly");
    require(sendAll(ws, apiMasked(10, "")), "Client pong write");
    const std::string closeBody = std::string("\3\350", 2) + "再见"; require(sendAll(ws, apiMasked(8, closeBody)), "Client close write");
    frame = apiFrame(ws); require(frame.first == 8 && frame.second == closeBody, "Valid close status and UTF-8 reason must be echoed"); close(ws);
    awaitCondition([] { return g_state.controllerStreams.load() == 1; }, "Closed WebSocket must release its subscriber slot");

    auto replace = [](std::string text, const std::string& from, const std::string& to) { const auto i = text.find(from); require(i != std::string::npos, "Bad handshake test fixture"); text.replace(i, from.size(), to); return text; };
    for (const auto& bad : std::vector<std::pair<std::string, std::string>>{
        {replace(API_WS,"HTTP/1.1","HTTP/1.0"),"400"}, {replace(API_WS,"keep-alive, Upgrade","close"),"400"},
        {replace(API_WS,"dGhlIHNhbXBsZSBub25jZQ==","invalid"),"400"}, {replace(API_WS,"dGhlIHNhbXBsZSBub25jZQ==","YQ=="),"400"},
        {replace(API_WS,"Version: 13","Version: 12"),"426"}, {replace(API_WS,"Host: localhost\r\n",""),"400"},
        {API_WS+"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n","400"}, {API_WS+"Content-Length: 1\r\n\r\nx","400"},
        {API_WS+"Transfer-Encoding: chunked\r\n","400"}}) {
        const std::string response = apiHttp(bad.first + "\r\n"); require(response.rfind("HTTP/1.1 " + bad.second, 0) == 0, "Invalid WebSocket handshake must fail with an HTTP error");
    }
    for (const auto& bad : std::vector<std::pair<std::string, unsigned>>{
        {std::string("\211\0",2),1002}, {apiMasked(9,"",false),1002}, {std::string("\311\200\1\2\3\4",6),1002},
        {std::string("\211\376",2),1002}, {apiMasked(3,""),1002}, {apiMasked(8,"x"),1002},
        {apiMasked(8,std::string("\3\355",2)),1002}, {apiMasked(8,std::string("\3\350\377",3)),1007}, {apiMasked(1,"unsupported"),1003}}) {
        int fd = apiSubscribe(API_WS, true, bad.first); const auto closed = apiFrame(fd);
        require(closed.first == 8 && closed.second.size() == 2 && ((static_cast<unsigned char>(closed.second[0]) << 8) | static_cast<unsigned char>(closed.second[1])) == bad.second, "Invalid WS frames need the appropriate protocol close, not a stalled worker"); close(fd);
        awaitCondition([] { return g_state.controllerStreams.load() == 1; }, "Rejected WebSocket must release resources");
    }
    int incomplete = apiSubscribe(API_WS, true, std::string("\211",1));
    const auto began = HealthClock::now(); unsigned ticks = 0;
    for (;;) {
        const auto value = apiFrame(incomplete);
        if (value.first == 8) { require(value.second == std::string("\3\352",2), "Unfinished control frames need a protocol close"); break; }
        require(value.first == 1 && ++ticks <= 6, "Traffic must continue while a partial frame waits for its bounded deadline");
    }
    close(incomplete);
    require(HealthClock::now()-began < std::chrono::seconds(7), "A stalled frame must release its subscriber within its deadline");
    awaitCondition([] { return g_state.controllerStreams.load() == 1; }, "Timed-out control frames must release resources");
    std::vector<int> subscribers;
    for (int i = 0; i < 15; ++i) subscribers.push_back(apiSubscribe(httpRequest));
    require(g_state.controllerStreams.load() == 16, "Traffic streams must have a bounded subscriber budget");
    // Inspect the rejection without waiting for the other live subscriptions.
    int limit[2]; pairFor(limit); dispatchWorker(limit[0],3); sendAll(limit[1],httpRequest+"\r\n");
    require(apiHeaders(limit[1]).rfind("HTTP/1.1 429",0)==0,"Excess subscribers must be rejected while normal API capacity is reserved");close(limit[1]);
    int control[2];pairFor(control);dispatchWorker(control[0],3);sendAll(control[1],"GET /version HTTP/1.1\r\nHost: localhost\r\n\r\n");
    require(apiHeaders(control[1]).rfind("HTTP/1.1 200",0)==0,"Saturated streams must not block normal controller requests");close(control[1]);
    for(int fd:subscribers)close(fd);close(http);workersIdle();
    require(g_state.controllerStreams.load()==0,"Disconnected subscribers must release all slots");
    http=apiSubscribe(httpRequest);ws=apiSubscribe(API_WS,true);sendAll(ws,apiMasked(9,"pending").substr(0,3));
    stopCore();close(http);close(ws);
    require(g_state.controllerStreams.load()==0&&g_state.workers.load()==0&&g_state.sockets.empty(),"Core shutdown must cancel HTTP, WebSocket and incomplete frame workers without leaked sockets");
}

void controllerAuthTests(const std::string& directory)
{
    stopCore(); workersIdle();
    const std::string first = "public+auth/%?fixture", second = "public-next-auth-fixture";
    require(setControllerSecret(first) && controllerSecret() == first, "Trusted application must be able to configure its own controller credential");
    const auto initialEpoch = g_state.controllerAuthEpoch.load();
    require(setControllerSecret(first) && initialEpoch == g_state.controllerAuthEpoch.load(), "Reapplying an unchanged key must not invalidate existing clients");
    for (const std::string& invalid : {std::string("with space"), std::string("with\r\nheader"), std::string("中文"), std::string(257, 'x')})
        require(!setControllerSecret(invalid) && controllerSecret() == first, "Invalid controller keys must never modify live authentication");
    g_state.running.store(true);
    auto credential = [](const std::string& secret) { return "Authorization: Bearer " + secret + "\r\n"; };
    auto get = [&](const std::string& path, const std::string& headers = "") { return apiHttp("GET " + path + " HTTP/1.1\r\nHost: localhost\r\n" + headers + "\r\n"); };
    require(get("/version").rfind("HTTP/1.1 401", 0) == 0, "Controller reads require a key when enabled");
    require(get("/version", credential(first)).rfind("HTTP/1.1 200", 0) == 0, "Bearer authorization must permit ordinary controller reads");
    require(get("/version", "Authorization: bearer " + first + "\r\n").rfind("HTTP/1.1 200", 0) == 0, "HTTP authentication scheme matching is case insensitive");
    for (const std::string& headers : {credential("wrong"), std::string("Authorization: Basic ") + first + "\r\n", credential(first)+credential(first), credential(first+"x")})
        require(get("/proxies", headers).rfind("HTTP/1.1 401", 0) == 0, "Wrong, malformed and duplicate credentials must fail closed");
    require(get("/version?token="+urlEncode(first)).rfind("HTTP/1.1 401", 0) == 0, "Query credentials must not authorize ordinary HTTP requests");
    const std::string patch = "{\"mode\":\"Global\"}"; g_state.mode = "Rule";
    require(apiHttp("PATCH /configs HTTP/1.1\r\nHost: localhost\r\nContent-Length: " + std::to_string(patch.size()) + "\r\n\r\n" + patch).rfind("HTTP/1.1 401",0)==0 && g_state.mode=="Rule", "Unauthorized mutations must not change runtime state");
    require(apiHttp("PUT /configs HTTP/1.1\r\nHost: localhost\r\nContent-Length: 9000000\r\n\r\n").rfind("HTTP/1.1 401",0)==0, "Authorization must happen before reading a request body");
    std::string wsQuery = API_WS; wsQuery.replace(wsQuery.find("/traffic"),8,"/traffic?token="+urlEncode(first));
    int data[2],origin[2];pairFor(data);pairFor(origin);
    g_testConnector=[fd=origin[0]](const std::string&,int,int){return fd;};
    dispatchWorker(data[0],0);sendAll(data[1],"CONNECT auth-data.test:443 HTTP/1.1\r\nHost: auth-data.test:443\r\n\r\n");
    require(readUntilHeaders(data[1]).find("200 Connection Established")!=std::string::npos,"Prepare a live data-plane connection before key rotation");
    sendAll(data[1],"before");require(receiveN(origin[1],6)=="before","Data-plane connection must work before controller key update");
    int ws = apiSubscribe(wsQuery,true), http = apiSubscribe("GET /traffic HTTP/1.1\r\nHost: localhost\r\n"+credential(first));
    require(setControllerSecret(second),"Key rotation must apply atomically");
    auto closed=apiFrame(ws);require(closed.first==8&&closed.second==std::string("\3\360",2),"Key rotation must close old WebSockets with policy status 1008");close(ws);
    char bytes[256];ssize_t received;do{received=recv(http,bytes,sizeof(bytes),0);}while(received>0);require(received==0,"Key rotation must end old HTTP streams");close(http);
    sendAll(data[1],"after");require(receiveN(origin[1],5)=="after","Updating controller credentials must preserve existing proxy connections");
    sendAll(origin[1],"reply");require(receiveN(data[1],5)=="reply","Existing proxy connections must still transfer both directions after rotation");
    shutdown(data[1],SHUT_RDWR);shutdown(origin[1],SHUT_RDWR);close(data[1]);close(origin[1]);g_testConnector=nullptr;workersIdle();
    require(g_state.controllerStreams.load()==0,"Rotated subscriptions must release all resources");
    require(get("/version",credential(first)).rfind("HTTP/1.1 401",0)==0&&get("/version",credential(second)).rfind("HTTP/1.1 200",0)==0,"Only the new key may authorize new requests after rotation");
    auto wsDenied=[&](const std::string& query,const std::string& headers=""){
        std::string value=API_WS;value.replace(value.find("/traffic"),8,"/traffic"+query);return apiHttp(value+headers+"\r\n");
    };
    for(const std::string& query:std::vector<std::string>{"?token=wrong","?token=%GG","?token="+urlEncode(second)+"&token="+urlEncode(second)})
        require(wsDenied(query,credential(second)).rfind("HTTP/1.1 401",0)==0,"Invalid or ambiguous WebSocket tokens must not fall back to a bearer key");
    ws=apiSubscribe(API_WS+credential(second),true);sendAll(ws,apiMasked(8,std::string("\3\350",2)));closed=apiFrame(ws);require(closed.first==8,"Bearer-authorized WS must retain the normal close protocol");close(ws);workersIdle();
    const std::string profile=directory+"/auth-profile-switch.yaml";{std::ofstream out(profile);out<<"port: 0\nsocks-port: 0\nrules: ['MATCH,DIRECT']\n";}
    std::string error;require(loadConfigLocked(profile,error)&&controllerSecret()==second,"Profile replacement must not alter application-scoped credentials");
    require(runtimeInfo().find(second)==std::string::npos&&responseFor("GET","/configs","").find(second)==std::string::npos&&logsJson(0).find(first)==std::string::npos,"Credentials must never appear in runtime/config metadata or request logs");
    require(setControllerSecret(""),"Users must be able to disable optional authentication");
    require(get("/version").rfind("HTTP/1.1 200",0)==0,"Disabling authentication restores unauthenticated controller access");
    stopCore();require(g_state.controllerStreams.load()==0&&g_state.workers.load()==0,"Authentication tests must leave no active workers");
}
