# 随源码提供的依赖

原生依赖位于 `entry/src/main/cpp/third_party/`，由项目 CMake 直接构建。
保留固定版本源码有助于离线构建，并避免首次构建拉取完整上游仓库。
版本、来源及本地适配说明保留在对应目录的 `SOURCE.json`、`SOURCE.txt`、
`UPSTREAM.json` 或 `README.md` 中；各依赖的 LICENSE / COPYING 和源码版权声明均保留。

主要依赖包括 libyaml、Mbed TLS、tiny_sha3、RE2 / Abseil、QuickJS、zstd、
libmaxminddb、HevSocks5Tunnel / lwIP，以及 CA 集合和公共后缀列表。
离线编辑器依赖固定于 `scripts/config-editor/package-lock.json`，
生成资源及第三方声明位于 `entry/src/main/resources/rawfile/config-editor/`。

为控制首次克隆体积，移除了 Abseil / RE2 不参与项目构建的上游测试、测试数据、
基准程序、示例应用、CI、其他构建系统元数据及 Mbed TLS 的历史变更日志。
项目关闭第三方测试及安装目标，保留生产代码、头文件、平台适配、CMake 和许可证。
因此这里是用于构建 ClashOS 的源码子集，并非可直接运行上游全部测试的发行包。
升级依赖时应重新审查版本、许可、适配和源码范围，并运行项目原生及 TUN 回归。

项目自身的公开测试夹具和独立参考端保留在 `tests/`，不随 HAP 打包。
验证截图和逐次设备测试记录不作为源码依赖，存放在仓库外。
