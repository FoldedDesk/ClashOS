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

离线编辑器的测试及重新打包：

```sh
npm ci --prefix scripts/config-editor --ignore-scripts
npm test --prefix scripts/config-editor
npm run build --prefix scripts/config-editor
```

`fixtures` 内的域名、账户和密码是公开测试数据。`fixtures/vmess/server-key.pem`
是独立 TLS 参考端的公开测试私钥，只用于本地测试。应用不会默认加载这些配置。
