# ClashOS

HarmonyOS PC 代理客户端，使用 ArkUI 和 C++ 内置内核，采用顶部导航。

支持配置文件及订阅导入、节点切换与测速、规则分流、连接与日志查看、备份恢复，
也可连接兼容 Clash REST API 的外部内核。内置协议包括 Shadowsocks AEAD、VMess、VLESS、
Trojan、HTTP/HTTPS 与 SOCKS5 出站，并提供 HTTP / SOCKS5 入站；
支持代理/规则集合、地理数据库、DNS、YAML 扩展与 JavaScript 脚本。
配置编辑器离线打包，提供语法高亮、查找替换、撤销重做与常用字段补全。

支持 YAML 锚点、别名及 `<<: *模板` / `<<: [*模板1, *模板2]` 合并。
显式字段优先，模板列表中靠前的值优先，嵌套字段按 YAML 规则整体替换。
文件、订阅、代理/规则集合、扩展脚本和可视化节点编辑共用解析结果；
导入的原始文本保留，生效配置可独立导出。循环引用、错误的合并类型和超限展开会明确报错。

编辑配置时点击“补全”，可按当前文档选择节点、代理组、代理集合、规则集合和规则目标。
代理组候选会过滤重复成员和循环引用，VMess 的加密方式按协议提示。
支持 YAML 与 JSON，插入包含空格、Emoji 或特殊字符的名称时自动处理引号，并可撤销。
尚未下载的远程 Provider 节点不会作为已知名称提示，仍可手动填写并通过原生校验确认。
名称提示读取当前文档的锚点、别名及合并模板，包含根级继承和内联 Provider 的名称前后缀；
节点继承的 `type` 也用于协议选项提示。编辑共享模板中的成员或 `dialer-proxy` 时，
会同时检查所有使用者的重复项和循环引用。显式字段、合并顺序及浅合并语义与内核一致。
补全保留原始模板结构，错误或超限草稿不会展开成大量对象；最终配置仍需通过原生校验。

这是独立实现的内核，配置兼容范围尚未覆盖 Mihomo 的全部协议和选项。
功能范围及待完成事项见 [功能状态](docs/feature-coverage.json)。

VLESS 支持标准 TCP、TLS、WebSocket、WebSocket + TLS 和长度分帧 UDP，
可从 `vless://` 链接、本地配置或订阅导入，并使用节点表单编辑、切换及测速。
Reality、Vision、XUDP、额外 VLESS 加密、gRPC / XHTTP 等传输尚不支持；
配置这些选项时会明确报错，不会自动改为直连。TLS 默认校验证书和服务器名称。

HTTP/HTTPS 节点使用 CONNECT 隧道，支持 Basic 认证及自定义请求头；托管的 CONNECT 请求头不允许覆盖。
SOCKS5 节点支持匿名或用户名密码认证，以及 TCP / UDP；控制连接关闭后停止对应 UDP 转发。
两者均可配置 TLS；SOCKS5 的 TLS 只保护 TCP 控制连接，UDP 仍使用原生数据报。
可在“节点链接”入口导入 `http://`、`https://`、`socks5://` 链接，或通过文件和订阅导入。

节点的 `dialer-proxy` 可填写中转节点或代理组的精确名称；也可在“订阅 → 编辑节点”表单中选择。
例如为落地节点填写 `dialer-proxy: 中转组`，连接会先经过中转组当前选中的节点。
代理集合支持 `override: {dialer-proxy: 中转组}`。切换中转组后，新连接使用新选择，已有连接保持原路径。
支持 TCP 链路及可承载的 UDP 链路；HTTP 中转不能承载原生 SS/SOCKS UDP，VLESS/VMess/Trojan 的流式 UDP 可经过 TCP 中转。
配置校验拒绝循环及超过八个出站节点的链路；中转不可用时连接失败。链路内的封装不重复计入流量或连接列表。
UDP 单包上限随各层封装收紧，超限数据包会被丢弃。用法参照 [Mihomo dialer-proxy](https://wiki.metacubex.one/config/proxies/dialer-proxy/)。

Shadowsocks TCP 在节点响应尚未收全时仍可继续上传，保留分片解码进度及半关闭语义。
“测试 → 内核自检”包含当前设备上的三种 SS 加密分帧检查，使用公开测试数据，
检查本地接收行为；节点服务器和系统代理连通性需另行检测。

“测试 → 连续检测”可对当前节点及自填 HTTP(S) 地址检测 3 / 5 / 10 次，
查看每次结果、成功和失败数、中位及最低/最高延迟，并复制报告。
节点与集合节点的右键菜单也提供入口；可停止后续检测，关闭窗口后不会继续发起检测。
内置内核的配置或连接状态变化后会结束当前检测，避免混用切换前后的结果。
TLS 握手提前关闭、超时、对端拒绝和证书问题分别报告，证书及服务器名称校验仍按原设置执行。

## 构建与运行

使用 DevEco Studio 打开项目根目录，安装 HarmonyOS SDK 和 Native 工具链，
选择 `entry` 模块运行 PC 模拟器或 2in1 设备。项目兼容及目标版本为 API 12，
编译使用本机已安装的 SDK；原生模块构建 ARM64 和 x86_64 两种架构。
设备安装和 VPN 扩展需按 DevEco Studio 的要求配置本地签名。

仓库包含构建所需的原生依赖源码和离线编辑器资源，无需下载 Mihomo 二进制。
修改编辑器源码后先重新打包：

```sh
npm ci --prefix scripts/config-editor --ignore-scripts
npm run build --prefix scripts/config-editor
```

## 使用

1. 在“订阅”页导入 YAML/JSON 文件、添加订阅，或新建配置。导入后默认加载，重启恢复最近配置。
2. 在“代理”页选择节点，按需调整规则模式、端口及其他设置。
3. 在系统网络设置中启用 HTTP 代理，填写应用显示的监听地址与端口；停止使用前关闭系统代理。

系统代理按钮用于打开系统设置，实际开关以系统设置为准。
HTTP 代理模式需要保持应用运行。TUN 数据包转发已有主机回归，
当前 PC 模拟器缺少系统 VPN 授权组件，真机授权和后台保活仍待验证。

模拟器导入本机配置可使用 DevEco Studio 的 Device File Browser，将文件放入设备的
`Docs/Download` 或 `Download` 公共目录，再从应用的系统文件选择器导入。
也可使用 SDK 的 `hdc`：

```sh
hdc list targets
hdc file send /path/to/clash.yaml /storage/media/100/local/files/Docs/Download/clash.yaml
```

公共目录以设备实际路径为准。连接宿主机上的外部控制器时，模拟器的 `127.0.0.1`
指向模拟器本身，可使用 `hdc rport tcp:9090 tcp:9090` 转发到宿主机控制器。
控制器的地址和 Secret 在应用设置中填写。

## 开发与测试

- `entry/src/main/ets/`：ArkUI 页面、服务和 VPN 扩展。
- `entry/src/main/cpp/`：代理内核、协议实现和 TUN 转发。
- `scripts/config-editor/`：离线编辑器源码及依赖锁文件。
- `tests/`：主机回归、公开配置与独立协议参考端。

```sh
python3 tests/run_native_tests.py --build-dir .host-build/native
python3 tests/run_tun_tests.py
npm test --prefix scripts/config-editor
```

依赖安装、ArkTS 服务测试及专项测试见 [测试说明](tests/README.md)。
测试默认使用公开夹具，不需要个人 `clash.yaml`。

仓库只维护源码、构建资源、测试和必要文档；构建产物、缓存、签名、个人配置、
临时设备记录和验证截图不纳入版本控制。第三方来源与精简范围见
[依赖说明](docs/DEPENDENCIES.md)，许可证保留在各依赖目录和应用的开源许可页面。
项目代码采用 [Apache-2.0](LICENSE)，第三方代码遵循其各自许可证。

## 局域网共享

“设置 → 代理设置 → 共享设置”可配置监听地址、来源允许/拒绝网段、
HTTP / SOCKS5 账号及免认证网段。关闭共享时仅接受本机连接，
拒绝网段优先于允许项。账号密码不回显，已有账号的密码留空则保留原值。
共享设置独立保存，重启与配置切换后保留；“恢复当前配置”可恢复 YAML 中的设置。

## 域名嗅探

“设置 → 代理设置”提供域名嗅探开关、配置编辑和右键菜单。
HTTP Host、TLS SNI 和 QUIC v1/v2 Initial 可用于域名规则匹配；
可分别指定协议端口、域名及来源/目标地址排除项，以及是否改写实际连接目标。
关闭 `override-destination` 后仍按识别的域名匹配规则，连接原来的地址。

界面修改作用于当前内核，重载或重启后恢复配置中的设置。
需要长期保留时，将配置写入原文件或“订阅 → 全局扩展配置”，例如：

```yaml
sniffer:
  enable: true
  sniff:
    HTTP: {ports: [80, 8080-8880]}
    TLS: {ports: [443, 8443]}
    QUIC: {ports: [443, 8443]}
```

嗅探只读取握手中可见的域名，不解密应用内容；无法读取 ECH 隐藏的内层域名。
未知协议、超时或无效握手保留原始数据并按原目标处理。
详细排除项使用 `force-domain`、`skip-domain`、`skip-src-address` 和 `skip-dst-address`。

## hosts 映射

配置中的 `hosts` 同时用于 DNS 查询、直连及受支持代理协议的 TCP / UDP 目标。
支持域名别名链、通配域名和多个 IPv4 / IPv6 地址，具体域名优先于较宽的匹配。
例如以下测试地址需替换为实际服务地址：

```yaml
dns:
  use-hosts: true
hosts:
  service.example: 192.0.2.10
  alias.example: service.example
```

映射保留 HTTP Host 和客户端 TLS 证书校验使用的域名；别名与已配置 IP 也参与分流规则。
别名循环、空映射及不可用地址族会报错，不会自动绕过映射。
`use-hosts: false` 可关闭此行为；未匹配的代理目标继续使用远端 DNS。
配置切换后新连接使用新映射；握手时保留原有映射快照，避免混用新旧配置。

## 代理组图标

在“代理”页右键代理组，选择“自定义图标”，可使用内置图标、HTTP / HTTPS 图片链接，
或通过系统文件选择器导入本地图片。支持 PNG、JPEG、WebP、GIF、BMP，最大 2 MB；
导入后缩放并保存本机 PNG 副本，原文件移走或删除后仍可显示。
图标同时用于代理组卡片和宽窗口中的分组导航。

自定义图标按代理组名称保存在本机，同名组共用，配置切换、订阅更新和重启后保留。
右键“恢复配置图标”可清除本机覆盖，随后优先显示配置中的 `icon` 图片链接，
其次使用名称 Emoji 或组类型图标；图片加载失败时回退到默认显示。
配置中的 `hidden: true` 会隐藏代理页上的组，规则和其他组仍可引用它。
订阅页的代理组编辑器也可修改这两个字段。

创建备份时勾选“包含外观”，会打包本机图标覆盖及导入的 PNG 图片，支持本地 JSON、
ZIP 和 WebDAV 备份。恢复时需单独勾选“恢复外观”，图标覆盖会整体替换；
未勾选时保留本机设置，旧备份未包含图标时也会保留。
图片编码及尺寸在写入前校验，共用图片只打包一份，图标部分最大 16 MB，整份备份最大 32 MB。
ClashOS 的 ZIP 恢复可保留本地图标；Clash Verge 仅使用兼容的配置部分。
写在配置里的 `icon` 和 `hidden` 随配置导出与备份保留。

## 自定义样式

“设置 → 外观 → 自定义样式”提供默认、紧凑、大字易读和柔和配色预设，
可在 JSON 编辑器中调整字体、字号比例、圆角、页面边距和浅色/深色配色。
预览不会修改应用设置；应用后自动保存，切换模式、主题色和重启后保留。
外观卡片的右键菜单提供编辑和恢复默认样式，预设替换支持撤销。

```json
{
  "version": 1,
  "fontFamily": "",
  "fontScale": 1.15,
  "cardRadius": 10,
  "contentGap": 16,
  "light": {"canvas": "#EDF2F8", "surface": "#FFFFFF"},
  "dark": {"canvas": "#151B27", "surface": "#202C40"}
}
```

`fontFamily` 留空跟随默认字体，缺失字体由系统替代；代码保持等宽字体，字号跟随比例。
`fontScale` 范围为 0.85–1.3，圆角为 0–24，页面边距为 8–24。
配色支持 `canvas`、`chrome`、`surface`、`field`、`text`、`textSecondary`、
`textMuted`、`border`、`divider`，颜色使用 `#RRGGBB`。
低对比度文字会自动调整，无法保证可读性的背景组合会拒绝应用。

样式随外观备份恢复；旧备份没有样式字段时保留当前样式。
此功能使用 ArkUI 样式设置，不执行 CSS 选择器、网页脚本或远程字体。
