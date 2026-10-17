# ClashOS

HarmonyOS PC 代理客户端，使用 ArkUI 和 C++ 内置内核，采用顶部导航。

支持配置文件及订阅导入、节点切换与测速、规则分流、连接与日志查看、备份恢复，
也可连接兼容 Clash REST API 的外部内核。内置协议包括 Shadowsocks AEAD、VMess、
Trojan、HTTP 和 SOCKS5；支持代理/规则集合、地理数据库、DNS、YAML 扩展与 JavaScript 脚本。
配置编辑器离线打包，提供语法高亮、查找替换、撤销重做与常用字段补全。

编辑配置时点击“补全”，可按当前文档选择节点、代理组、代理集合、规则集合和规则目标。
代理组候选会过滤重复成员和循环引用，VMess 的加密方式按协议提示。
支持 YAML 与 JSON，插入包含空格、Emoji 或特殊字符的名称时自动处理引号，并可撤销。
尚未下载的远程 Provider 节点不会作为已知名称提示，仍可手动填写并通过原生校验确认。

这是独立实现的内核，配置兼容范围尚未覆盖 Mihomo 的全部协议和选项。
功能范围及待完成事项见 [功能状态](docs/feature-coverage.json)。

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
