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

网络设置备份专项不需要主机监听权限：

```sh
python3 tests/run_native_tests.py --suite network-backup --build-dir .host-build/native
CLASHOS_NATIVE_TESTS="$PWD/.host-build/native/native_tests" node tests/backup_migration_test.cjs
CLASHOS_NATIVE_TESTS="$PWD/.host-build/native/native_tests" node tests/backup_archive_test.cjs
```

原生检查覆盖严格备份格式、端口/来源规则/认证、默认跟随语义、私有文件、目录与链接边界、
过期预览及无监听时的状态提交。生产恢复协调器配合真实原生文件读写，检查网络设置独立迁移、
凭据不出现在预览、后续外观失败时撤回网络文件，以及并发的新设置不能被旧预览覆盖。
模拟器另行验证系统选择器导入、默认未勾选、实际 HTTP 407/认证后 204 与 SOCKS5 204，
使用独立测试应用占用 18097 端口检查监听失败回滚，并验证过期预览和原网络/配置恢复。
公开归档见 `fixtures/backup/network-settings.json`，账号 `network-fixture` / `PUBLIC-p@ss` 仅供回环测试。
先保存原网络设置，再加载 `fixtures/probes/device.yaml` 与设备独立对端；导入归档并单独勾选网络恢复。
将归档的 HTTP 端口改为独立对端占用的 18097 可验证冲突，结束后从原备份恢复网络设置、原配置和选择，
删除测试配置/备份/公共文件、额外转发及测试应用。

HTTP 入站消息、持续连接与升级专项使用独立 Python 标准库对端和 Unix socket：

```sh
python3 tests/run_native_tests.py --suite http --build-dir .host-build/native
```

检查跨目标流水请求、每条请求鉴权、代理凭据及逐跳字段隔离、URI Host/IPv6 端口、
分片定长及分块上传、二进制响应和 trailer、HEAD、100/103、HTTP/1.0 解块、
非法长度/分块/升级响应、取消后的请求隔离，以及原有 HTTP/SOCKS 转发和流量计数。
旧内核的负向对照可分别指定 `CLAHSOS_HTTP_CASE=pipeline` 或 `upgrade`。
`CLAHSOS_HTTP_CASE=closed-response` 让独立 TLS 对端写完响应并退出，再同时排队客户端 FIN，
稳定检查上传结束通知失败时仍须读取有效响应；无需网络监听或依靠重复运行碰到竞态。
原生解析依据 [HTTP/1.1 消息边界](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3)、
[逐跳字段](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6.1) 和
[WebSocket 握手](https://www.rfc-editor.org/rfc/rfc6455.html#section-4.1)。

模拟器验证使用可移除的 `webdav_device_server` 测试应用：启动后向 18088 端口的
`POST /test-admin/http/start` 开启固定 18105 端口，再通过 `GET /test-admin/http/state` 检查独立计数。
`fixtures/http/device.yaml` 只允许公开测试域名，其余请求拒绝；可用控制器的临时 payload 加载。
使用 SDK clang 将 `http_ingress_device_probe.c` 编译为 ARM64 并通过 HDC 执行，
检查实际 TCP 持续连接、64 KB 上传、分块、HTTP/1.0、Continue、WebSocket 首帧及歧义请求拒绝。
探针要求代理端口 7890。完成后恢复原配置、移除测试应用、额外 HDC 转发和设备上的探针。

TLS 故障分类专项使用继承的 Unix socket，无需监听权限：

```sh
python3 tests/run_native_tests.py --suite tls --build-dir .host-build/native
CLAHSOS_TYPESCRIPT=/path/to/typescript node tests/probe_series_test.cjs
```

独立 OpenSSL 对端分别模拟握手前关闭、超时、TLS alert、非 TLS 响应、错误 CA 和错误服务器名称，
并验证受信任 TLS 正常收发。未完成证书校验时的网络失败不能被归类为证书错误。
连续检测服务检查混合结果、统计、报告、停止、关闭及配置变化后的请求隔离。
模拟器公开配置与独立对端见 [节点检测设备验证](webdav_device_server/README.md#connection-probe-device-verification)。

`node tests/system_network_check_test.cjs` 检查生产系统联网检测服务：实际系统代理选项、
缓存与系统 TLS 策略、HTTP 状态/网络错误分类、自定义地址、代理凭据不进入报告、
停止/关闭释放请求，以及代理认证/排除项/内核状态变化时隔离未完成结果。
模拟器中可使用同一个独立对端验证交替 204/503、TLS 提前关闭、慢请求停止/关闭、
检测期间切换配置，并在系统设置中关闭/恢复代理检查实际提示和排除项行为。

同一可移除应用还提供 [独立 Shadowsocks HTTPS 对照](webdav_device_server/README.md#independent-shadowsocks-https-reference)：
通过系统加密库和套接字实现 AES-GCM，先检查公开 Python 向量，再用同一个系统 HTTP/TLS 客户端
交替访问内核及独立参考路径。参考路径只接受三个固定公开 HTTPS 目标，私有节点参数只留在内存；
统计区分连接关闭、认证失败和已完成的 HTTP 错误响应，并检查参考请求不会增加内核流量。

链式代理专项使用继承的 Unix socket，无需主机监听权限：

```sh
python3 tests/run_native_tests.py --suite dialer --build-dir .host-build/native
python3 tests/run_native_tests.py --suite groups --build-dir .host-build/native
```

独立 Python/OpenSSL 对端检查 HTTP/SOCKS/SS 中转下的加密 TCP、HTTPS、三跳实际入站、
不完整响应时的继续上传及半关闭；UDP 覆盖 VLESS 流式封装、三种 SS 加密嵌套、SOCKS 控制连接和直连别名。
检查空包、最大包、超限丢弃、来源地址、认证失败过滤、单次计数、连接取消、工作线程上限与清理。
配置检查覆盖本地和集合节点的循环、引用、深度、覆盖、缓存恢复、失败回退、选择快照及测速路径。
`groups` 专项检查自动健康组和负载均衡。模拟器公开配置位于 `fixtures/dialer/device.yaml`，
设备独立对端与步骤见 [链式代理设备验证](webdav_device_server/README.md#dialer-proxy-device-verification)。

YAML 模板专项不需要主机监听权限：

```sh
python3 tests/run_native_tests.py --suite yaml --build-dir .host-build/native
```

检查锚点/别名、`<<` 单映射和映射列表、显式字段与模板列表的优先级、浅合并、
显式 merge/string 标签及字面量 `"<<"` 的独立导出。
覆盖脚本类型、可视化编辑隔离、文件集合导入/缓存/失败回退、实际规则匹配、
原始文件保留，以及循环/复杂度拒绝和不回显配置值的错误位置。
独立 Python/OpenSSL 对端验证继承的认证、请求头和 TLS 设置用于实际收发。
合并规则参照 [YAML merge 类型规范](https://yaml.org/type/merge.html)。
公开设备配置位于 `fixtures/yaml/device-templates.yaml`，使用独立设备测试应用的
[HTTP/SOCKS 参考服务](webdav_device_server/README.md#http--socks-device-verification)。

hosts 与加密转发专项使用继承的 Unix socket，不需要绑定回环端口：

```sh
python3 tests/run_native_tests.py --suite hosts --build-dir .host-build/native
```

它通过独立 Python cryptography / OpenSSL 参考端检查 SS、VMess、Trojan 的实际 TCP / UDP
目的地址、TLS / WebSocket、HTTPS Host / SNI、原生规则与配置切换快照。
VMess 双向转发检查会先发送不完整的响应头、长度或负载，确认此时既不泄露应用数据，
也不阻塞后续客户端写入；覆盖 AEAD / 旧版响应头、AES-GCM、ChaCha20-Poly1305 和 none。
专项不能替代真实设备的网络、VPN 授权和后台运行验证。

Shadowsocks 增量接收与双向传输专项：

```sh
python3 tests/run_native_tests.py --suite ss-duplex --build-dir .host-build/native
```

独立 Python cryptography/OpenSSL 对端先发送不完整的 salt、长度、负载或认证标签，
等待实际 HTTP/SOCKS 客户端的后续请求后才完成响应；覆盖三种加密、服务器先发数据、
连续认证空帧、多个分帧及 TCP 半关闭。数据作为连续字节流检查，不依赖 TCP/AEAD 分帧边界一致。
独立已知向量另检查每个分片/EOF 位置、阻塞与非阻塞读取交接、认证失败、长度保留位和 nonce 上限，
并运行现有 SS TCP/UDP/HTTPS 互通检查。旧 Core 0.34 的首个 salt 分片场景会阻塞后续请求；
Core 0.35 必须在相同独立对端上完成收发。
设备“内核自检”使用同源公开向量，逐字节验证本机 `MSG_DONTWAIT` 接收、完整分帧输出、
截断与认证失败；不读取个人配置、不连接测试服务器。完整分帧规则见
[Shadowsocks AEAD TCP 规范](https://shadowsocks.org/doc/aead.html#tcp)。

VLESS 专项同样使用继承的 Unix socket，无需主机监听权限：

```sh
python3 tests/run_native_tests.py --suite vless --build-dir .host-build/native
```

独立 Python / OpenSSL 对端检查 VLESS v0 的 UUID、命令、域名 / IPv4 / IPv6、
TCP / TLS / WebSocket / WebSocket + TLS、双向分片、服务器先发数据与 TCP 半关闭。
包含实际 HTTP / SOCKS5 入站、空包和大 UDP 包、HTTPS 证书与状态检查、hosts 映射、
分享链接和节点编辑；错误响应头、Vision / Reality / XUDP 等不支持的配置必须明确失败。
模拟器专项使用 [独立设备测试应用](webdav_device_server/README.md#vless-device-verification)，
验证实际数据面；TLS 参考证书属于公开测试 CA，设备正向控制显式跳过该测试证书校验，
关闭跳过选项的负向控制必须失败。主机专项另验证受信任 CA 和主机名。

HTTP/HTTPS 与 SOCKS5 出站专项：

```sh
python3 tests/run_native_tests.py --suite forward --build-dir .host-build/native
python3 tests/run_native_tests.py --suite providers --build-dir .host-build/native
```

独立 Python/OpenSSL 参考端通过继承的 Unix socket 验证认证协商、IPv4 / IPv6 / 域名、
CONNECT 临时响应及任意 2xx、握手同包负载、半关闭、实际 HTTP/SOCKS 入站与 HTTPS 测速。
UDP 检查匿名/认证/TLS 控制连接、服务器指定的中继地址、通配地址回退、真实回复来源、
空包/大包/最大包、无效分片丢弃、控制连接关闭及关闭后的回复屏蔽。
文件集合仅更新用户名或自定义请求头时，必须替换实际路由节点，并以新值完成独立对端握手；
随后检查缓存重载及 API 凭据隐藏。集合专项另覆盖下载、校验、缓存、更新失败及恢复。
设备测试入口见 [HTTP/SOCKS 设备验证](webdav_device_server/README.md#http--socks-device-verification)。

ArkTS 服务测试通过 TypeScript 转译执行，不需要运行 ArkUI。
可使用 DevEco Studio 随附的 TypeScript，或安装经过验证的标准版本：

```sh
npm install --prefix /tmp/clashos-test-tools --ignore-scripts --no-audit --no-fund typescript@4.9.5
export CLAHSOS_TYPESCRIPT=/tmp/clashos-test-tools/node_modules/typescript
node tests/controller_access_test.cjs
node tests/session_lifecycle_test.cjs
node tests/profile_files_test.cjs
node tests/subscription_import_test.cjs
CLASHOS_NATIVE_TESTS="$PWD/.host-build/native/native_tests" node tests/subscription_test.cjs
node tests/appearance_test.cjs
node tests/backup_migration_test.cjs
node tests/backup_archive_test.cjs
node tests/webdav_client_test.cjs
node tests/config_editor_controller_test.cjs
node tests/group_icons_test.cjs
```

归档测试需要先完成上述原生构建；`CLASHOS_NATIVE_TESTS` 可覆盖原生测试程序路径。
订阅专项执行生产请求/解析/存储/ZIP 转换代码及实际原生配置校验，检查 UA、下载路径、总超时、
流量单位与到期时间、UTF-8 名称、服务端/手动更新间隔、新修改保护、文件失败与运行配置应用失败撤回。
其 HTTP SDK 接口由可控响应替代；实际代理认证、端口、系统浏览器和设备生命周期验证见独立设备测试应用说明。
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

下载/导入集合的编辑器引用与缓存校验使用真实原生解析器及独立生成的公开缓存，不需要主机监听权限：

```sh
python3 tests/run_native_tests.py --suite editor-providers --build-dir .host-build/native
CLASHOS_NATIVE_TESTS="$PWD/.host-build/native/native_tests" npm run test:native --prefix scripts/config-editor
CLASHOS_NATIVE_TESTS="$PWD/.host-build/native/native_tests" node tests/profile_provider_cache_test.cjs
```

覆盖来源指纹、RE2 过滤与名称前后缀、链式循环、目录/文件边界、异步取消和过期结果，
以及实际 CodeMirror YAML/JSON 补全插入到原生保存、冷加载、规则/节点编辑和归档校验的链路。
配置存储专项还检查扩展/脚本、订阅更新、复制时缓存刷新、写入失败撤回，以及无本机缓存的新目录恢复。
设备验证可导入公开的文件集合，再在配置右键菜单中编辑成员；确认补全、撤销/重做、校验、
保存重开、冷启动、右键创建副本和备份恢复都保留同一名称，并通过独立代理对端检查实际转发。
结束后恢复原配置及选择，删除本次公开配置、缓存、备份、测试应用和转发规则。

编辑器回归包含 YAML 锚点、标量/列表/映射别名、根级合并、合并优先级、显式空值、
共享模板的重复及循环过滤、协议选项、转义名称、无效草稿、缓存更新和 CRLF 撤销。
`fixtures/yaml/editor-templates.yaml` 同时供编辑器与原生 `--suite yaml` 使用，
核对实际节点名称、内联 Provider 前缀、组成员及规则目标。
设备检查可导入该公开配置，在“编辑配置文件”中将 `default-selected` 的别名改为空值后点击“补全”，
候选应为 `Template HTTP`、`DIRECT` 和 `[T] Pool`；
在 `&members` 列表末尾新增成员时，已有别名成员与当前组应被排除。
保存、冷启动并重新打开时应保留锚点结构；此配置的端口是公开测试服务，不是可用的互联网节点。

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

代理组图标测试使用真实临时文件，覆盖偏好事务、过期编辑、私有图片的引用与清理、
系统选择器路径回退及图片资源释放；主机上的 ImageKit 编解码使用替身。
设备上的实际编解码、图片加载和界面需另行检查：

```sh
python3 tests/group_icons_device_server.py --ready-file /tmp/clashos-icon-peer.json
hdc rport tcp:18095 tcp:18095
hdc file send tests/fixtures/icons/quadrants.png /storage/media/100/local/files/Docs/Download/clashos-icon-test.png
```

临时加载 `fixtures/icons/device.yaml`，检查配置 PNG、隐藏组、右键菜单、内置图标、
`http://127.0.0.1:18095/check.svg` 预览和不存在的 `/broken.svg` 加载回退。
从系统文件选择器导入四象限图片，保存后删除公共目录原图、停止图片参考端并重启应用，
确认本机图片仍显示；切换配置后同名组应继续使用覆盖图标。
四个可见组用于检查宽窗口分组导航，并分别检查深色、浅色和窄窗口布局。
结束后恢复图标、原配置及外观，删除公共目录测试图片，并移除 18095 反向端口。
该参考端只提供两张固定公开图片，其余路径返回 404。

图标备份回归检查共享资源去重、跨目录恢复、PNG 尺寸和编码限制、过期预览、
恢复期间的并发修改，以及图片/索引写入失败时的完整回滚。
`backup_migration_test.cjs` 执行真实生产恢复协调器，验证配置、全局扩展、外观和图标一起撤回；
`backup_archive_test.cjs` 检查 ZIP 中的原生数据保留。
设备验证可仅选“包含外观”创建备份，清除图标后单独恢复外观；
再从备份右键导出 ZIP，检查图片字节、通过系统选择器重新导入，删除导出文件后重启确认。
测试结束应清除临时图标和测试新建的备份，保留设备原有备份与配置。

编辑器引用补全回归覆盖 YAML / JSON 的节点和集合名称、规则目标及 `RULE-SET`，
并检查重复成员和循环引用过滤、Provider 名称覆盖、特殊字符引用、CRLF 撤销、
大文件异步解析取消及旧补全结果的并发保护。字段提示按当前原生支持范围提供，
不将未知或尚未下载的远程 Provider 内容当作可用节点。
模拟器可使用 `fixtures/config-editor/references.yaml` 导入、编辑和导出，
检查“补全”菜单、原生校验、保存重开和导出字节；结束后恢复原配置并删除测试配置。

原生样式回归包含独立 sRGB 对比度检查、类型/范围校验、模式切换与持久化、
原生主题/磁盘/界面发布失败回滚，以及样式字段的备份兼容和并发保护。
编辑器还验证基于旧内容生成的修改无法覆盖新草稿，匹配 CRLF 的修改可撤销。
设备验证需检查字体选择、双模式实时预览、最大字号及窄窗口、校验失败和撤销、
右键恢复默认、冷启动及外观备份恢复；最后恢复原外观和窗口位置。
