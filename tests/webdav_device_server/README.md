# WebDAV device fixture

Independent HarmonyOS test app, bundle `com.clashos.webdavtest`; it is not part of the production ClashOS HAP. Start `EntryAbility` to serve HTTP on **127.0.0.1:18088** inside the emulator. All files stay in memory until the process ends. The public test credentials are `fixture` / `clashos-webdav-test`.

Point ClashOS WebDAV at `http://127.0.0.1:18088/dav/`. The client uses its `ClashOS/` child collection. The fixture implements MKCOL, PROPFIND, create-only PUT, GET and conditional DELETE, including stale ETags, XML entities, namespaced properties and out-of-scope listing entries.

Loopback-only admin endpoints expose request counts and filenames, never backup contents:

- `/test-admin/state`
- `/test-admin/mode/change-etag`
- `/test-admin/mode/fail-put`
- `/test-admin/mode/bad-list`
- `/test-admin/mode/corrupt-get`
- `/test-admin/mode/normal`
- `/test-admin/xml-events`
- `POST /test-admin/clipboard`: put a public fixture body (up to 256 KB) on the device clipboard for UI paste tests. An empty body clears it. Never reads or returns existing clipboard contents.

Build as a separate HarmonyOS project with the installed DevEco SDK and `hvigorw --mode module -p product=default -p module=entry@default assembleHap --no-daemon`. Use a writable `HVIGOR_USER_HOME` and npm cache when the default home cache is restricted. Install only the fixture HAP, then start its ability. Optional HDC forwarding `tcp:18088` to `tcp:18088` lets a host client inspect metadata. Remove that forwarding rule and uninstall the fixture after testing; clear the test WebDAV account in ClashOS as well.

Host-side deterministic tests: `node tests/webdav_client_test.cjs` and `node tests/profile_files_test.cjs`, run from the main project root.

## VLESS device verification

The same removable app optionally runs an independent VLESS v0 protocol fixture.
It is inactive until `POST /test-admin/vless/start`. Plain TCP / WebSocket listen
on `127.0.0.1:18097`; TLS / WebSocket + TLS listen on `127.0.0.1:18098`.
`GET /test-admin/vless/state` reports readiness, validated requests and UDP counts.
Only the fixed public UUID in `../fixtures/vless/device-links.txt` is accepted.
The server never forwards to arbitrary destinations: `vless.device.test:80`
returns HTTP 204 for `GET /verify`, and `vless.device.test:443` echoes UDP bytes.

Build from this directory within the full repository. The native TLS bridge uses
the existing bundled Mbed TLS source and relays only to the ArkTS parser on
`127.0.0.1:18099`. It avoids the first-record callback loss observed with the
simulator's TLSSocketServer; the VLESS/UDP/WebSocket parser is independent of the
production implementation. The two PEM files are copies of the public test
certificate/key in `../fixtures/vmess`, never production credentials.

1. Start this app, forward port 18088 if using a host client, and POST the start endpoint. Wait until state lists both `tcp` and `tls`.
2. Import `../fixtures/vless/device-links.txt` through ClashOS's node-link dialog. The self-signed test TLS nodes explicitly set `allowInsecure=1`.
3. Select each node and request `http://vless.device.test/verify` through the actual HTTP and SOCKS5 listeners; both must return 204. Check the same URL with node latency probes.
4. `POST /test-admin/vless/probe` runs an independent SOCKS5 UDP client inside this INTERNET-authorized app. It uses port 7891 without authentication and verifies empty, 8-byte, 4096-byte and maximum SOCKS-envelope payloads. It returns only counts, lengths and success/failure.
5. Verify wrong-UUID and enabled certificate-check controls fail, then restore the working node. Check UI selection and a saved node-form change after cold startup.
6. Restore the original ClashOS profile, mode and group selections; delete only the newly created fixture profile. Clear the fixture clipboard, remove owned forwards and uninstall this test app.

These controls prove emulator proxy forwarding, not true-device VPN authorization
or full interoperability with every VLESS extension. Host-side OpenSSL tests
separately verify accepted CA chains, SNI, malformed frames and HTTPS destinations.
