#!/usr/bin/env python3
"""Independent HTTP(S) rule-provider resources, sharing only the public test transport peer."""
import json
from pathlib import Path
import provider_reference_peer


def feed(mode):
    fixtures = Path(__file__).parent / 'fixtures/rules'
    if mode == 'mrs':
        return (fixtures / 'domain.mrs').read_bytes()
    if mode == 'text':
        return b'# plain rule feed\n+.downloaded.test\nexact.test\n'
    if mode == 'classical':
        return json.dumps({'payload': ['DOMAIN-SUFFIX,downloaded.test', 'AND,((NETWORK,tcp),(DST-PORT,443))']}).encode()
    return json.dumps({'payload': ['+.changed.test'] if mode == 'v2' else ['+.downloaded.test', 'exact.test']}).encode()


if __name__ == '__main__':
    provider_reference_peer.feed = feed
    provider_reference_peer.main()
