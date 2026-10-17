# GeoData reference fixtures

`generate_geo_fixtures.py` independently encodes the v2ray routercommon protobuf
schema. Its addresses and domain names are documentation ranges and reserved
test names. It also encodes invalid prefixes, duplicate categories, truncated
messages and overflowing varints.

The two generated MMDB files are from MaxMind's reader release 1.14.1,
`t/maxmind-db/test-data`. The TSV expectations are extracted from that same
project's `source-data` JSON, with only network and country/ASN values retained.
These artificial records do not describe current Internet address ownership.
Their upstream MIT license is included in this directory.

Schema: https://github.com/v2fly/v2ray-core/blob/master/app/router/routercommon/common.proto
MMDB fixtures: https://github.com/maxmind/MaxMind-DB

No test fixtures or user configurations are packaged in the application.
