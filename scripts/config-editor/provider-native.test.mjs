// Explicit integration suite: the cache writer, CodeMirror and native parser are independent.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {spawnSync} from 'node:child_process';
import {createRequire} from 'node:module';
import {EditorState} from '@codemirror/state';
import {yaml} from '@codemirror/lang-yaml';
import {json} from '@codemirror/lang-json';
import {CompletionContext} from '@codemirror/autocomplete';
import {clashCompletions} from './completion.mjs';
const fixture = createRequire(import.meta.url)('../../tests/provider_cache_fixture.cjs');
const native = process.env.CLASHOS_NATIVE_TESTS;
if (!native || !fs.existsSync(native)) throw Error('Set CLASHOS_NATIVE_TESTS to the compiled native_tests executable');

test('Actual provider cache → projected YAML/JSON → native names → completion → validation → cold load', async t => {
  const files = fs.mkdtempSync(path.join(os.tmpdir(), 'clashos-provider-pipeline-'));
  t.after(() => fs.rmSync(files, {recursive: true, force: true}));
  fs.mkdirSync(path.join(files, 'profiles'), {mode: 0o700});
  const profile = path.join(files, 'profiles', 'public.yaml'), request = path.join(files, 'request.json');
  fs.writeFileSync(profile, fixture.source, {mode: 0o600});
  const resource = fixture.seed(profile);
  const run = (command, data) => {
    fs.writeFileSync(request, JSON.stringify(data), {mode: 0o600});
    const result = spawnSync(native, [command, request], {encoding: 'utf8', timeout: 10000, maxBuffer: 4 * 1024 * 1024});
    assert.equal(result.status, 0, result.stderr); return JSON.parse(result.stdout);
  };
  const context = JSON.stringify({version: 1, profile, resources: []});
  for (const language of ['yaml', 'json']) {
    let text = fixture.source.replace('proxies: [DIRECT]', 'proxies: [¦]').replace('MATCH,Cached Route', 'MATCH,Manual Pick');
    if (language === 'json') text = JSON.stringify({'proxy-providers': {Pool: {type: 'http', url: fixture.definition.url, path: 'pool.yaml', header: {'X-Public': ['ONE', 'TWO']}, filter: 'Public', override: {'additional-prefix': '[Pool] ', 'additional-suffix': ' 😀'}}}, 'proxy-groups': [{name: 'Manual Pick', type: 'select', proxies: ['¦']}, {name: 'Cached Route', type: 'select', use: ['Pool'], filter: '#1'}], rules: ['MATCH,Manual Pick']});
    const pos = text.indexOf('¦'); let state = EditorState.create({doc: text.replace('¦', ''), extensions: [language === 'yaml' ? yaml() : json()]});
    let calls = 0;
    const result = await clashCompletions(language, async query => {calls++; return run('editor-provider-request', {files, profile, source: fixture.source, query});})(new CompletionContext(state, pos, true));
    assert.equal(calls, 1); const options = result?.options || [];
    assert(options.some(o => o.label === fixture.node));
    assert(!options.some(o => o.label.includes("O'Brien") || o.label.includes('Drop')));
    const choice = options.find(o => o.label === fixture.node);
    choice.apply({get state(){return state;}, dispatch(spec){state = state.update(spec).state;}, focus(){}});
    const source = state.doc.toString();
    assert.match(run('profile-cache-request', {files, kind: 'validate', source, context: ''}).error, /Unknown proxy/);
    assert.equal(run('profile-cache-request', {files, kind: 'validate', source, context}).error, '');
    assert.equal(run('profile-cache-request', {files, kind: 'rules', source, context}).error, '');
    assert.equal(run('profile-cache-request', {files, kind: 'objects', source, context}).error, '');
    fs.writeFileSync(profile, source);
    const loaded = run('profile-cache-request', {files, profile, kind: 'load'});
    assert.equal(loaded.error, ''); assert.equal(loaded.nodes, 2); assert.equal(loaded.groups, 2);
    const archiveContext = JSON.stringify({version: 1, profile: '', resources: [resource]});
    fs.unlinkSync(profile + resource.suffix);
    assert.equal(run('profile-cache-request', {files, kind: 'validate', source, context: archiveContext}).error, '');
    assert(run('profile-cache-request', {files, kind: 'validate', source, context}).error);
    assert(run('profile-cache-request', {files, kind: 'validate', source: source.replace('pool.yaml', 'changed.yaml'), context: archiveContext}).error);
    fs.writeFileSync(profile, fixture.source); fixture.seed(profile);
  }
});
