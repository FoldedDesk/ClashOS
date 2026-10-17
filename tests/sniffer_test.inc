void snifferTests(const std::string& directory)
{
    ControllerConfigJson vectors; std::string error;
    require(vectors.parse(readTestFile(std::string(CLAHSOS_TEST_ROOT) + "/fixtures/sniffer/vectors.json"), error), "Read independent public sniffer vectors");
    const auto bytes = [&](const char* name) { std::string value; require(vectors.string(name, value, error) && !value.empty(), "Sniffer vector exists"); return text(hex(value)); };
    const auto ch = bytes("client_hello"), tls = bytes("tls_record"), split = bytes("tls_records_split");
    require(sniffClientHello(ch).host == "sniff.fixture.test" && sniffTls(tls).host == "sniff.fixture.test" && sniffTls(split).host == "sniff.fixture.test", "TLS SNI survives multiple TLS records and handshake fragments");
    for (size_t size = 0; size < tls.size(); ++size) require(sniffTls(std::string_view(tls).substr(0, size)).status != SniffStatus::Found, "No truncated ClientHello may produce a domain");
    for (const auto& source : {std::string("GET / HTTP/1.1\r\nHost: SNIFF.FIXTURE.TEST:8080\r\n\r\n"), std::string("POST / HTTP/1.0\r\nhost: sniff.fixture.test\r\n\r\nbody")})
        require(sniffHttp(source).host == "sniff.fixture.test", "HTTP Host parsing is case-insensitive and removes its port");
    for (const auto& source : {"GET / HTTP/1.1\r\nHost: one.test\r\nHost: two.test\r\n\r\n", "GET / HTTP/2.0\r\nHost: one.test\r\n\r\n", "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", "GET / HTTP/1.1\r\nHost: bad/name.test\r\n\r\n", "GET / HTTP/1.1\r\n Host: bad.test\r\n\r\n"})
        require(sniffHttp(source).status == SniffStatus::No, "Malformed, ambiguous or non-domain HTTP hosts are ignored");
    require(sniffValidDomain("-bad.test").empty() && sniffValidDomain("bad..test").empty() && sniffValidDomain("bad\n.test").empty() && sniffValidDomain("Good.Example.") == "good.example", "Sniffed domains are validated before routing");
    for (const auto* name : {"quic_v1", "quic_v2"}) {
        const auto packet = bytes(name); QuicSniffState state;
        require(sniffQuic(packet, state).host == "sniff.fixture.test", "Independent QUIC v1/v2 Initial decrypts to its ClientHello SNI");
        require(sniffQuic(packet, state).host == "sniff.fixture.test", "A retransmitted identical Initial is idempotent");
        for (size_t size = 0; size < packet.size(); ++size) {
            QuicSniffState shortState;
            require(sniffQuic(std::string_view(packet).substr(0, size), shortState).status == SniffStatus::No && shortState.bytes.empty(), "Truncated Initial datagrams cannot mutate reassembly state");
        }
        auto damaged = packet; damaged[damaged.size() - 19] ^= 1; QuicSniffState rejected;
        require(sniffQuic(damaged, rejected).status == SniffStatus::No && rejected.bytes.empty(), "Unauthenticated QUIC payload cannot yield SNI or retained fragments");
    }
    const auto head = bytes("quic_fragment_head"), tail = bytes("quic_fragment_tail");
    QuicSniffState coalesced;
    require(sniffQuicDatagram(head + tail, coalesced).host == "sniff.fixture.test", "Multiple coalesced Initial packets share a single CRYPTO reassembly");
    QuicSniffState forward, reverse;
    require(sniffQuic(head, forward).status == SniffStatus::Need && sniffQuic(tail, forward).host == "sniff.fixture.test", "QUIC CRYPTO fragments reassemble across Initial datagrams");
    require(sniffQuic(tail, reverse).status == SniffStatus::Need && sniffQuic(head, reverse).host == "sniff.fixture.test", "Out-of-order CRYPTO fragments and ACK frames are handled");
    const auto previous = reverse.bytes;
    require(sniffQuic(bytes("quic_conflicting_head"), reverse).status == SniffStatus::No && reverse.bytes == previous, "Conflicting overlaps cannot replace authenticated fragment state");
    QuicSniffState wrap;
    require(sniffQuic(bytes("quic_pn255"), wrap).status == SniffStatus::Need && sniffQuic(bytes("quic_pn256"), wrap).host == "sniff.fixture.test", "Truncated QUIC packet numbers reconstruct across a one-byte wrap");
    QuicSniffState oversize;
    require(sniffQuic(bytes("quic_oversized_offset"), oversize).status == SniffStatus::No && oversize.bytes.empty(), "CRYPTO offsets are bounded before allocating reassembly buffers");
    ParsedConfig parsed;
    const std::string source = "sniffer:\n  enable: true\n  parse-pure-ip: true\n  override-destination: false\n  sniff:\n    HTTP: {ports: [80, 8080-8880]}\n    TLS: {ports: [443], override-destination: true}\n    QUIC: {ports: [443]}\n  force-domain: ['+.example.test']\n  skip-domain: [Mijia Cloud, '*.skip.test']\n  skip-src-address: ['192.0.2.0/24']\n  skip-dst-address: ['2001:db8::/32']\n";
    require(parseConfigText(source, parsed, error) && parsed.sniffer.protocols.size() == 3 && !parsed.sniffer.protocols["HTTP"].overrideDestination && parsed.sniffer.protocols["TLS"].overrideDestination,
        "Parse protocol port ranges and per-protocol overrides from actual YAML");
    require(sniffProtocolPort(parsed.sniffer, "HTTP", 8088) && !sniffProtocolPort(parsed.sniffer, "HTTP", 443) && parsed.sniffer.forceIndex.matches("www.example.test"), "Compiled sniff port and domain policies actually match");
    for (const auto& bad : {"sniffer: true", "sniffer: {enable: yes}", "sniffer: {unknown: true}", "sniffer: {sniff: {SSH: {ports: [22]}}}",
        "sniffer: {sniff: {TLS: {ports: [65536]}}}", "sniffer: {sniff: {TLS: {ports: [443-80]}}}", "sniffer: {skip-src-address: [bad]}",
        "sniffer: {force-domain: ['bad..name']}", "sniffer: {sniff: {TLS: {ports: [443]}, tls: {ports: [443]}}}"})
        require(!parseConfigText(bad, parsed, error), "Unsupported or malformed sniffer settings fail before replacing runtime state");
    for (const auto* draft : {R"({"sniffer":{}})", R"({"sniffer":{"enable":false}})",
        R"({"sniffer":{"enable":true,"sniff":{"HTTP":{"ports":[80,"8080-8880"]},"QUIC":{"ports":[443],"override-destination":false}}}})"})
        require(snifferDraftError(draft).empty(), "Offline GUI validation accepts the same typed schema as the real controller");
    const auto before = runtimeInfo();
    for (const auto* draft : {"", "[", "[]", "{}", R"({"sniffer":null})", R"({"sniffer":[]})", R"({"sniffer":{},"mode":"direct"})",
        R"({"sniffer":{"enable":"true"}})", R"({"sniffer":{"sniff":{"TLS":{"override-destination":1}}}})",
        R"({"sniffer":{"force-domain":[false]}})", R"({"sniffer":{"sniff":{"TLS":{"ports":[443.5]}}}})",
        R"({"sniffer":{"skip-src-address":["invalid"]}})"})
        require(!snifferDraftError(draft).empty(), "Offline validation rejects missing objects, wrong JSON types and semantic errors before applying");
    require(!snifferDraftError(std::string(128 * 1024 + 1, ' ')).empty() && runtimeInfo() == before,
        "Offline validation bounds its input and cannot change the live core");
    snifferForwardTests(directory);
}
