// Independent public cache bytes: do not use the production cache writer here.
const fs = require('node:fs'), crypto = require('node:crypto');
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const definition = {type: 'http', url: 'https://example.invalid/public-pool', path: 'pool.yaml', headers: {'X-Public': 'ONE, TWO'}};
const node = '[Pool] Public 日本 #1 😀';
const body = `proxies:
  - {name: 'Public 日本 #1', type: http, server: 127.0.0.1, port: 18097}
  - {name: "Public O'Brien #2", type: http, server: 127.0.0.1, port: 18097, dialer-proxy: Manual Pick}
  - {name: Drop, type: direct}
`;
const source = `x-feed: &feed
  type: http
  url: https://example.invalid/public-pool
  path: pool.yaml
  header: {X-Public: [ONE, TWO]}
proxy-providers:
  Pool:
    <<: *feed
    filter: Public
    exclude-filter: Drop
    override: {additional-prefix: '[Pool] ', additional-suffix: ' 😀'}
proxy-groups:
  - {name: Manual Pick, type: select, proxies: [DIRECT]}
  - {name: Cached Route, type: select, use: [Pool], filter: '#1'}
rules: ['MATCH,Cached Route']
`;
function resource(value = body, name = 'Pool', provider = definition) {
  const source = [provider.type, provider.url || '', provider.path || '', ...Object.entries(provider.headers || {}).sort(([a], [b]) => a.localeCompare(b)).flat()].join('\0');
  const bytes = Buffer.from('# ClahsOS provider source: ' + hash(source) + '\n' + value);
  return {suffix: '.provider-' + hash(name).slice(0, 16) + '.cache', data: bytes.toString('base64')};
}
function seed(profile, value = body) {const cache = resource(value); fs.writeFileSync(profile + cache.suffix, Buffer.from(cache.data, 'base64'), {mode: 0o600}); return cache;}
module.exports = {definition, node, body, source, resource, seed};
