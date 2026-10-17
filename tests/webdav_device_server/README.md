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
