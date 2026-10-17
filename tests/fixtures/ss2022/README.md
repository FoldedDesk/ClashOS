Public Shadowsocks 2022 interoperability fixtures. Keys are deterministic test
bytes, never real credentials. `device-client.yaml` and `device-server.yaml` are
JSON documents (valid YAML) for native client and independent Mihomo respectively.

`tests/ss2022_reference_peer.py` uses Rust BLAKE3 (`blake3==1.0.8`) and PyCryptodome,
independently of the production portable C BLAKE3/Mbed TLS implementation. Install
those reference dependencies plus `cryptography` in `CLAHSOS_REFERENCE_PYTHON`.
The `ss2022` suite needs Unix socket pairs, not loopback listeners; it verifies
all three methods, SIP023 identity chains, large TCP frames, every response split
and EOF, HTTP/SOCKS duplex, UDP authentication/replay/reordering/session bounds,
and OpenSSL HTTPS validation. The normal `all` suite includes these scenarios.

`tests/ss2022_network_test.py --native PATH/native_tests --mihomo PATH/mihomo`
uses actual TCP/UDP sockets and a separately supplied official Mihomo v1.19.32.
It needs ordinary listener permissions, and is run by the Linux GitHub workflow.
The workflow checks the official release SHA before execution. It covers actual
HTTP/SOCKS forwarding, target CA/hostname validation and UDP DNS through each
of the three ciphers; it does not use an injected connector or the reference codec.
It starts and stops only its own processes and uses temporary public profiles.

Ports: client HTTP18890/SOCKS18891/controller19090; independent SS18894–18896,
HTTP controller19094, HTTPS controller19095 and UDP DNS18553. TLS certificates
come from `tests/fixtures/vmess`. The only DNS fixture answer is
`udp-fixture.test → 192.0.2.44`; no public DNS or real subscription is required.

On the HarmonyOS PC emulator, shell processes cannot bind network sockets and
the app sandbox rejects executing external Go binaries. Neither restriction is
disabled by these tests. The production HAP continues to use its own native core.
