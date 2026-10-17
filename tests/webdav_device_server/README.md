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
VLESS mode accepts only the fixed public UUID in `../fixtures/vless/device-links.txt`.
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

## Subscription device verification

Shadowsocks 2022 device and independent-server verification is documented in
[`../fixtures/ss2022/README.md`](../fixtures/ss2022/README.md). The test app's
`/test-admin/ss2022/start`, `/state` and `/stop` routes use only public fixed
keys and loopback HTTP/TLS/DNS fixtures.

`GET /test-admin/subscription/source` supplies a public local starter profile with HTTP **18890**, SOCKS disabled,
the public `subscription-fixture` / `public-proxy-password` account and a hosts override for `subscription.device.test`.
After importing it, add `http://subscription.device.test:18088/public-subscription.yaml` with a blank name,
server interval enabled and the internal HTTP download route. Direct SDK DNS fails; the authenticated internal
HTTP route resolves the app's hosts override and returns the profile, UTF-8 name, quota, expiry and homepage.

`/test-admin/subscription/mode/{ready,custom,bad-http,invalid-config,slow,no-metadata,port-conflict}` controls responses.
`custom` requires User-Agent `clash-public-fixture/2`, changes quota from 8 KB to 16 KB and suggests four hours;
manual interval zero must remain off. `slow` responds after four seconds, allowing a three-second deadline control.
`port-conflict` returns a valid profile using port 18088, already occupied by this independent fixture: active-update
failure must restore prior file/metadata and reload HTTP18890. The other failure modes must not replace prior data.
`/test-admin/subscription/state` exposes public counters and a custom-agent boolean, without recording origin request URLs or credentials.
The right-click homepage opens `/public-home` in the system browser; `homeRequests` proves the visit.
`/public-install-links` supplies real browser anchors for `clash`, `clashos` and `clash-verge`, with a Chinese/emoji
name and a percent-encoded nested subscription query. `encodedQueryRequests` increments only when the origin
receives the exact original `token=PUBLIC%2Bvalue%26tail&flag=meta` query; the fixture never records URLs or credentials.
Test OS resolution without an explicit target bundle, cold/warm delivery, duplicate delivery, cancellation,
invalid nested protocols, queued distinct requests, an unsaved configuration-editor draft and a delete confirmation.
Before pressing Import, cancellation and invalid links must leave request counters, original runtime and selections unchanged.
Turn off automatic updates for owned imports. In the browser, explicitly identify and close only the public fixture tab.
For HDC-driven URI delivery, transfer and run an owned shell script with a properly quoted URI: HDC's command
reconstruction otherwise splits the outer `&name=` parameter. Remove that script after verification.
Verify cold startup, selected-profile-only backup/restore and preserved request settings, then restore the user's
original runtime/selections/window and remove every owned public profile, backup, download, test app and forward.

## HTTP / SOCKS device verification

`POST /test-admin/forward/start` starts the same optional plain/TLS fixture ports.
`GET /test-admin/vless/state` also reports the `forward` protocol counters.
The independent ArkTS decoder additionally accepts HTTP CONNECT and SOCKS5.
It supports anonymous access or the public `fixture` / `p@ss:word` credentials;
provided wrong credentials are rejected. Only `forward.device.test:80` with
`GET /verify` and `forward.device.test:443` UDP echoes are permitted.

Import `../fixtures/forward/device-links.txt` through the node-link dialog. For
all six authenticated/anonymous/TLS nodes, test HTTP and SOCKS ingress and latency
against `http://forward.device.test/verify`. HTTP nodes must report UDP disabled.
For SOCKS nodes, `POST /test-admin/forward/probe` verifies an actual on-device UDP
association, including empty, 8-byte, 4096-byte and maximum-envelope payloads.
The fixture binds a separate loopback UDP relay for each control connection and
closes it with the control channel. TLS protects that control channel only.

Check wrong credentials and required test-certificate validation fail. In the
node form, change a username, apply, restart, and verify the change affects
authentication; then correct the credentials and verify TCP/UDP after restart.
Restore the original profile, mode, groups and window, remove the owned test
profile and forwards, clear only the fixture clipboard and uninstall this app.

## Connection probe device verification

Start the optional VLESS/HTTP fixture and activate `../fixtures/probes/device.yaml`.
The HTTP fixture accepts these additional fixed targets for native delay probes:

- `https://tls-eof.device.test/`: close after the complete TLS ClientHello.
- `https://tls-alert.device.test/`: return a fatal TLS handshake alert.
- `http://probe-mixed.device.test/verify`: alternate HTTP 204 and HTTP 503.
- `http://probe-slow.device.test/verify`: return HTTP 204 after three seconds.

Use the untrusted/wrong-host TLS nodes to verify trust and hostname errors remain
rejected. In ClashOS, open the continuous probe dialog from Tests or a node's
right-click menu. Check mixed-result counts against `forward.probe-pass-tcp` and
`probe-fail-tcp`; verify copy/report actions, three/five/ten attempt controls,
stopping pending work, closing the dialog and changing runtime configuration
during a pending request. Stop/close/change controls must issue no later probes.

`POST /test-admin/https/{google|gstatic|github}/{http1|http2|system}` runs an
independent HarmonyOS HTTP/TLS client against three fixed public destinations.
Omit the final segment for default HTTP negotiation. It uses the core's explicit
loopback proxy, or the OS default proxy in `system` mode, and returns only status,
elapsed time or an error code. Requests disable response caching; HTTP/1.1 uses
`Connection: close` for cold-connection checks. It never returns response bodies,
headers, clipboard data, node addresses or credentials. The API follows the
[HarmonyOS HTTP proxy options](https://developer.huawei.com/consumer/en/doc/harmonyos-references-V5/js-apis-http-V5).
Restore the original profile/runtime/selections/window and remove owned fixture
applications and forwards after verification.

## Independent Shadowsocks HTTPS reference

The removable app can run a second HTTP CONNECT proxy on **127.0.0.1:18106**.
It implements SIP004 with HarmonyOS CryptoArchitectureKit MD5, SHA-1 and AES-GCM,
and NetworkKit sockets. It does not call the production core or its cryptography.
Only `www.google.com:443`, `www.gstatic.com:443` and `api.github.com:443` are allowed.
The supported test ciphers are `aes-128-gcm` and `aes-256-gcm`.

1. `POST /test-admin/ss-reference/self-test` must return `passed: true`. The public
   Python/OpenSSL vectors verify master/subkey derivation, transmitted bytes,
   every receive split, bytewise input, empty records, nonce carry, authentication,
   reserved length bits and truncated replies. Regenerate both native and device
   fixtures with `python tests/generate_ss_aead_vectors.py` using cryptography.
2. `POST /test-admin/ss-reference/config` accepts a private JSON body with
   `address` (numeric IPv4), `port`, `cipher` and `password`. Use an owned 0600
   input file, never shell arguments or logs. The endpoint and keys remain in
   memory; state responses contain only counters and readiness. Configuration
   requires a successful self-test and replaces any previous reference listener.
3. Compare `POST /test-admin/https/{google|gstatic|github}/reference` with `/http1`.
   Both use the same OS HTTP/1.1 client, TLS verification, public URL and headers;
   `/http1` uses the production listener on 7890, `/reference` uses 18106. Pin
   both routes to the same SS endpoint before interpreting a codec comparison.
   Alternate order and retain every planned outcome, including non-2xx responses.
4. `GET /test-admin/ss-reference/state` separates encrypted upload/download,
   authenticated plaintext, remote EOF before data, decoding, truncation and
   socket errors. Verify actual core transfer totals stay unchanged for reference
   requests. An HTTP 403 is a completed HTTPS response, not a TLS connection error.
5. `POST /test-admin/ss-reference/stop` closes peers and clears endpoint/key state.
   Restore the original user runtime and all group selections/candidates, delete
   private inputs, remove owned forwards and uninstall this app.

These controls can demonstrate that a failure also occurs outside the core.
They cannot prove a single cause for all failures, long-term route reliability,
full browser behavior or support for untested Shadowsocks variants. API response
bodies/headers and private endpoint details are never exported.

## dialer-proxy device verification

The HTTP/SOCKS parser can additionally tunnel only `chain.device.test:18097` or
`:18098` to the corresponding fixed loopback fixture port. This lets the native
core establish real two-hop connections without arbitrary network forwarding.
The `forward` state exposes separate `relay-tcp`/`relay-tls` counts; VLESS
request/UDP counts come from the independent exit parser.

Start the VLESS fixture and import `../fixtures/dialer/device.yaml`. For each
of four `Chain Gateway` entries and four `Chain Route` exits, verify HTTP and
SOCKS ingress at `http://vless.device.test/verify`, node delay, and the on-device
UDP probe. Each probe checks 0/8/4096/65483-byte datagrams. The fixture TLS CA is
public and explicitly skipped only by these test nodes; host peers separately
check actual HTTPS trust. Select a different dialer in the visual node form,
save/apply, restart the app, and verify both metadata and actual forwarding.
Restore the original saved profile, runtime settings, all group selections and
window; delete only the owned fixture profile/public file, remove added forwards
and uninstall this fixture app.
