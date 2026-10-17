# Public rule-provider fixtures

The YAML/text examples and MRS files contain only reserved test domains and
documentation IP ranges. `tests/generate_rule_mrs_fixtures.py` independently
encodes the MRS v1 wire layout with a Python pointer trie and `ipaddress`, then
compresses it with the host Zstandard library. It also produces malformed
length, topology, UTF-8, compression and range cases.

Wire-format references are the upstream mihomo `mrs_reader.go`,
`component/trie/domain_set_bin.go` and `component/cidr/ipcidr_set_bin.go`:
https://github.com/MetaCubeX/mihomo/tree/Meta/rules/provider

These files are regression inputs and are not packaged in the application.
To additionally check a downloaded real-world domain MRS file:

```sh
rtk proxy env CLAHSOS_MRS_DOMAIN_FILE=/path/to/google.mrs python3 tests/run_native_tests.py --suite rules
```

The implementation is also checked against a pinned upstream Google MRS during
device-verification work; its source URL and digest are recorded with the
verification results. Production configurations and subscription credentials
are never embedded in these fixtures.
