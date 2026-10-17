# 主机回归测试

应用通过 DevEco Studio 构建；这里的主机测试适用于 macOS / Linux。
需要 CMake、C/C++17 编译器、zlib 开发文件、Python 3 和 Node.js。
原生依赖源码随工程提供。独立协议参考端使用 Python cryptography：

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r tests/requirements.txt
CLAHSOS_REFERENCE_PYTHON="$PWD/.venv/bin/python" python3 tests/run_native_tests.py --build-dir .host-build/native
python3 tests/run_tun_tests.py
```

默认读取公开的 `tests/fixtures/core/public.yaml`。个人配置兼容性检查需显式指定：

```sh
python3 tests/run_native_tests.py --build-dir .host-build/native --config /path/to/private-clash.yaml
```

`CMAKE_COMMAND` 可指定 CMake 可执行文件；没有设置时依次查找 PATH 和
`DEVECO_SDK_HOME`，并兼容 macOS 上 DevEco Studio 的默认安装位置。
`CLAHSOS_REFERENCE_PYTHON` 可指定已安装 cryptography 的 Python。
原生测试会绑定本机回环端口；限制 socket 绑定的沙箱无法完成这些检查。

ArkTS 服务测试通过 TypeScript 转译执行，不需要运行 ArkUI。
可使用 DevEco Studio 随附的 TypeScript，或安装经过验证的标准版本：

```sh
npm install --prefix /tmp/clashos-test-tools --ignore-scripts --no-audit --no-fund typescript@4.9.5
export CLAHSOS_TYPESCRIPT=/tmp/clashos-test-tools/node_modules/typescript
node tests/controller_access_test.cjs
node tests/session_lifecycle_test.cjs
node tests/profile_files_test.cjs
node tests/appearance_test.cjs
node tests/backup_migration_test.cjs
node tests/backup_archive_test.cjs
node tests/webdav_client_test.cjs
node tests/config_editor_controller_test.cjs
```

归档测试需要先完成上述原生构建；`CLASHOS_NATIVE_TESTS` 可覆盖原生测试程序路径。
其余服务测试使用临时文件与系统接口替身，设备验证与主机回归分开进行，临时截图和逐次记录不纳入源码仓库。
TUN 主机测试采用真实 lwIP 与数据包，但不能替代真机 VPN 授权与保活验证。

局域网专项使用实际 IPv4 / IPv6 监听、HTTP Basic、SOCKS5 RFC1929 和 UDP 关联：

```sh
python3 tests/run_native_tests.py --suite inbound --build-dir .host-build/native
```

`inbound_device_probe.c` 可用 HarmonyOS SDK 的 clang 交叉编译后通过 HDC 在模拟器执行，
检查非回环源地址的 HTTP / SOCKS5 认证。它使用固定公开测试账号和 Google 204 地址，
不会读取个人配置或打印认证头；测试结束应恢复应用设置并删除设备上的探针。
TUN 数据包回归另包含认证账号中的 UTF-8、引号和冒号、IPv6 SOCKS 地址及真实双向 TCP/UDP。

离线编辑器的测试及重新打包：

```sh
npm ci --prefix scripts/config-editor --ignore-scripts
npm test --prefix scripts/config-editor
npm run build --prefix scripts/config-editor
```

`fixtures` 内的域名、账户和密码是公开测试数据。`fixtures/vmess/server-key.pem`
是独立 TLS 参考端的公开测试私钥，只用于本地测试。应用不会默认加载这些配置。

域名嗅探专项回归：

```sh
python3 tests/run_native_tests.py --suite sniffer --build-dir .host-build/native
CLAHSOS_REFERENCE_PYTHON="$PWD/.venv/bin/python" .venv/bin/python tests/generate_sniffer_vectors.py
```

向量由独立 Python cryptography 生成，覆盖 HTTP Host、分段 TLS SNI、
QUIC v1/v2 Initial、CRYPTO 分片/乱序/重叠、认证失败和包号回绕。
转发测试使用真实 HTTP/SOCKS TCP 和 UDP 入站，检查路由域名、目标改写、
原始报文保留、超时及设置的原子回滚；不需要主机 VPN 权限。

模拟器独立验证使用 `fixtures/sniffer/device.yaml`、`sniffer_device_peer.py`、
`sniffer_device_client.py` 和 SDK clang 编译的 `sniffer_device_probe.c`。
参考端只在宿主机回环监听 18089 / 18090 / 18092，经 HDC `rport` 暴露给模拟器。
HTTP/TLS 客户端通过 HDC 转发的代理端口请求不可达 IP `203.0.113.10`，
只有嗅探域名并改写目标才能到达固定 204 服务。客户端验证公开 CA、有效期和 `vmess.test` 主机名。
QUIC 探针直接在设备访问 SOCKS5 UDP；参考端通过 Trojan TLS 接收，
严格检查目标已改写为 `sniff.fixture.test:18091`，只回显公开向量。
这个 UDP 参考节点仅为公开测试证书设置 `skip-cert-verify`，不提供任意转发。
设备检查后应恢复原配置，删除探针与输入文件，并移除三个反向端口。
这些检查验证独立客户端、实际设备内核和数据面，不等同于真机 VPN 验证。
