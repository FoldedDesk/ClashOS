import { ClashNativeCore } from './ClashNativeCore';
import { ProfileBackup, BackupProfile } from './BackupTypes';
import { ObjectEdits, ObjectSequenceEdits, ObjectEditItem, parseObjectEditsText } from './ObjectEditsTypes';
import { parseRuleEditsText } from './RuleEditsTypes';
import { ZipEntry, readZip, writeZip, zipText } from './BackupZip';
import { utf8Bytes } from './TextCodec';
import { SubscriptionData, SubscriptionUsage, subscriptionOptions, subscriptionData, subscriptionUrl } from './SubscriptionTypes';

interface ArchiveObject { name: string; }
interface ArchiveSequence { prepend: ArchiveObject[]; append: ArchiveObject[]; delete: string[]; }
interface RuleSequence { prepend: string[]; append: string[]; delete: string[]; }
interface MigratedSequences { rules: RuleSequence; proxies: ArchiveSequence; groups: ArchiveSequence; }
interface VergeOption { merge?: string; script?: string; rules?: string; proxies?: string; groups?: string; update_interval?: number; allow_auto_update?: boolean; user_agent?: string; timeout_seconds?: number; with_proxy?: boolean; self_proxy?: boolean; danger_accept_invalid_certs?: boolean; }
interface VergeSelection { name: string; now: string; }
interface VergeItem { uid: string; type: string; name?: string; file: string; url?: string; option?: VergeOption; selected?: VergeSelection[]; updated?: number; extra?: SubscriptionUsage; home?: string; }
interface VergeIndex { current?: string; items: VergeItem[]; }
interface VergeAppearance { theme_mode?: string; }
interface VergeNativeEdits { rules: RuleSequence; proxies: ArchiveSequence; groups: ArchiveSequence; }

export class BackupArchiveCodec {
  private native: ClashNativeCore;
  constructor(native: ClashNativeCore = new ClashNativeCore()) { this.native = native; }
  private yaml(text: string): string { return this.native.backupYaml(text); }
  private text(files: ZipEntry[], name: string, optional: boolean = false): string {
    const file: ZipEntry | undefined = files.find((entry: ZipEntry) => entry.name === name);
    if (!file) { if (optional) return ''; throw new Error(`ZIP 缺少文件：${name}`); }
    if (file.bytes.length > 8 * 1024 * 1024) throw new Error('ZIP 中单份配置超过 8 MB');
    return zipText(file.bytes);
  }
  private file(item: VergeItem): string {
    if (typeof item.file !== 'string' || !item.file || /[\\/\u0000-\u001f:]/.test(item.file) || item.file === '.' || item.file === '..') throw new Error('订阅索引中的文件路径无效');
    return `profiles/${item.file}`;
  }
  private reference(index: VergeIndex, files: ZipEntry[], uid: string | undefined, kind: string, fallback: string): string {
    if (uid !== undefined && (typeof uid !== 'string' || !uid)) throw new Error('订阅扩展引用无效');
    const item: VergeItem | undefined = index.items.find((entry: VergeItem) => entry.uid === (uid ?? fallback));
    if (!item) { if (uid !== undefined) throw new Error('ZIP 缺少订阅引用的扩展'); return ''; }
    if (item.type !== kind) throw new Error('ZIP 扩展引用类型不一致');
    const value: string = this.text(files, this.file(item));
    if (utf8Bytes(value).length > 256 * 1024) throw new Error('ZIP 中单份扩展超过 256 KB');
    return value;
  }
  private sequence(text: string): string {
    if (!text.trim()) return '{"prepend":[],"append":[],"delete":[]}';
    const value: ArchiveSequence = JSON.parse(this.yaml(text)) as ArchiveSequence;
    if (!value || typeof value !== 'object' || !Array.isArray(value.prepend) || !Array.isArray(value.append) || !Array.isArray(value.delete) ||
      Object.keys(value).some((key: string) => ['prepend', 'append', 'delete'].indexOf(key) < 0) ||
      value.prepend.length + value.append.length > 1000 || value.delete.length > 2000 ||
      value.delete.some((item: string) => typeof item !== 'string')) throw new Error('ZIP 中规则或节点增删设置无效');
    return JSON.stringify(value);
  }

  decode(bytes: Uint8Array): string {
    const files: ZipEntry[] = readZip(bytes, { backupInflate: (data: Uint8Array, expected: number): Uint8Array => this.native.backupInflate(data, expected) });
    const nativeArchive: ZipEntry | undefined = files.find((entry: ZipEntry) => entry.name === 'clashos-backup.json');
    if (nativeArchive) return zipText(nativeArchive.bytes);
    const index: VergeIndex = JSON.parse(this.yaml(this.text(files, 'profiles.yaml'))) as VergeIndex;
    if (!index || !Array.isArray(index.items) || index.items.length > 3502) throw new Error('Clash Verge 订阅索引无效');
    const seen: Set<string> = new Set<string>();
    index.items.forEach((item: VergeItem) => {
      if (!item || typeof item.uid !== 'string' || !item.uid || seen.has(item.uid) || typeof item.type !== 'string' ||
        ['remote', 'local', 'merge', 'script', 'rules', 'proxies', 'groups'].indexOf(item.type) < 0) throw new Error('Clash Verge 订阅条目、类型或编号无效');
      seen.add(item.uid);
    });
    const archive: ProfileBackup = { format: 'ClashOS.profile-backup', version: 2, createdAt: new Date().toISOString(), profiles: [],
      migrationNotes: ['来自 Clash Verge ZIP。订阅、扩展和节点选择保留；桌面端口、系统代理、WebDAV 账户、DNS 覆盖和自定义样式不迁移。',
        '全局扩展需单独勾选恢复；配置本身引用的扩展会随该配置保留。'] };
    const globalMerge: string = this.reference(index, files, undefined, 'merge', 'Merge');
    const globalScript: string = this.reference(index, files, undefined, 'script', 'Script');
    if (index.items.some((item: VergeItem) => item.uid === 'Merge' || item.uid === 'Script')) archive.globals = { merge: globalMerge, script: globalScript };
    const appearanceText: string = this.text(files, 'verge.yaml', true);
    if (appearanceText.trim()) {
      const appearance: VergeAppearance = JSON.parse(this.yaml(appearanceText)) as VergeAppearance;
      if (appearance && ['light', 'dark', 'system'].indexOf(appearance.theme_mode ?? '') >= 0) archive.appearance = { mode: appearance.theme_mode as string, accent: '#3478F6' };
    }
    index.items.filter((item: VergeItem) => item.type === 'remote' || item.type === 'local').forEach((item: VergeItem) => {
      const option: VergeOption = item.option ?? {};
      if (!option || typeof option !== 'object' || Array.isArray(option)) throw new Error('ZIP 订阅选项无效');
      let interval: number = option.allow_auto_update === false ? 0 : option.update_interval ?? 0;
      if (!Number.isInteger(interval) || interval < 0 || interval > 10080) throw new Error('ZIP 订阅更新间隔超出 0–10080 分钟');
      const selections: VergeSelection[] = item.selected ?? [];
      if (!Array.isArray(selections) || selections.length > 1000 || selections.some((selection: VergeSelection) => !selection ||
        typeof selection.name !== 'string' || typeof selection.now !== 'string' || /[\u0000-\u001f\u007f]/.test(selection.name + selection.now))) throw new Error('ZIP 节点选择记录无效');
      const seq: string = `{"rules":${this.sequence(this.reference(index, files, option.rules, 'rules', 'Rules'))},"proxies":${this.sequence(this.reference(index, files, option.proxies, 'proxies', 'Proxies'))},"groups":${this.sequence(this.reference(index, files, option.groups, 'groups', 'Groups'))}}`;
      const entry: BackupProfile = { name: item.name ?? '导入配置', content: this.text(files, this.file(item)), sourceUrl: item.type === 'remote' ? item.url ?? '' : '',
        updateInterval: item.type === 'remote' ? interval : 0, pinned: false, resources: [],
        merge: this.reference(index, files, option.merge, 'merge', 'Merge'), script: this.reference(index, files, option.script, 'script', 'Script'), sequence: seq,
        selections: selections.map((selection: VergeSelection) => `${JSON.stringify(selection.name)} ${JSON.stringify(selection.now)}\n`).join('') };
      if (item.type === 'remote' && !entry.sourceUrl) throw new Error('ZIP 远程订阅缺少地址');
      if (item.type === 'remote') {
        for (const value of [option.with_proxy, option.self_proxy, option.allow_auto_update, option.danger_accept_invalid_certs]) if (value !== undefined && typeof value !== 'boolean') throw new Error('ZIP 订阅开关无效');
        const subscription: SubscriptionData = { options: subscriptionOptions({ userAgent: option.user_agent ?? 'clashos/1.0', timeoutSeconds: option.timeout_seconds ?? 20,
          route: option.self_proxy ? 'core' : option.with_proxy ? 'system' : 'direct' }), followInterval: false };
        if (item.extra !== undefined || item.home !== undefined) {
          if (item.home !== undefined && typeof item.home !== 'string') throw new Error('ZIP 订阅主页无效');
          subscription.info = { checkedAt: typeof item.updated === 'number' && Number.isSafeInteger(item.updated) && item.updated >= 0 && item.updated <= 8640000000000 ? item.updated * 1000 : Date.now(),
            usage: item.extra, home: item.home ? subscriptionUrl(item.home, true) : undefined };
        }
        entry.subscription = subscriptionData(subscription);
        if (option.danger_accept_invalid_certs && !archive.migrationNotes?.includes('订阅下载仍使用系统证书校验；原客户端的忽略无效证书选项不迁移。')) archive.migrationNotes?.push('订阅下载仍使用系统证书校验；原客户端的忽略无效证书选项不迁移。');
      }
      archive.profiles.push(entry);
    });
    return JSON.stringify(archive);
  }

  private nativeSequence(edits: ObjectSequenceEdits): ArchiveSequence {
    const parse = (item: ObjectEditItem): ArchiveObject => JSON.parse(this.yaml(item.content)) as ArchiveObject;
    return { prepend: edits.prepend.map(parse), append: edits.append.map(parse), delete: edits.remove };
  }
  private exportScript(entry: BackupProfile): string {
    if (!entry.objectEdits && !entry.ruleEdits) return entry.script ?? '';
    const objects: ObjectEdits = parseObjectEditsText(entry.objectEdits ?? ''), rules = parseRuleEditsText(entry.ruleEdits ?? '');
    const edits: VergeNativeEdits = { proxies: this.nativeSequence(objects.proxies), groups: this.nativeSequence(objects.groups),
      rules: { prepend: rules.prepend, append: rules.append, delete: rules.remove } };
    // Native visual edits follow extension scripts. Export them in that same
    // position instead of moving them into Verge's earlier sequence phase.
    return `function main(config, profileName) {\n  const result = ${entry.script?.trim() ? `(function() {\n${entry.script}\nreturn main;\n})()(config, profileName)` : 'config'};\n  function applyEdits(result) {\n` +
      `  const edits = JSON.parse(${JSON.stringify(JSON.stringify(edits))});\n  for (const [kind, field] of [['proxies','proxies'],['groups','proxy-groups'],['rules','rules']]) {\n` +
      `    const e = edits[kind];\n    if (!e.prepend.length && !e.append.length && !e.delete.length) continue;\n    const removed = new Set(e.delete);\n` +
      `    result[field] = e.prepend.concat((result[field] || []).filter(x => !removed.has(kind === 'rules' ? x : x.name)), e.append);\n  }\n  return result;\n  }\n  return result && typeof result.then === 'function' ? result.then(applyEdits) : applyEdits(result);\n}\n`;
  }
  encode(archive: ProfileBackup): Uint8Array {
    const files: ZipEntry[] = [], items: VergeItem[] = [];
    const add = (name: string, text: string): void => { files.push({ name, bytes: utf8Bytes(text) }); };
    const extension = (uid: string, type: string, text: string): string => {
      const file: string = `${uid}.${type === 'script' ? 'js' : 'yaml'}`;
      items.push({ uid, type, file }); add(`profiles/${file}`, text || (type === 'script' ? 'function main(config) { return config; }\n' : '{}\n')); return uid;
    };
    if (archive.globals) { extension('Merge', 'merge', archive.globals.merge); extension('Script', 'script', archive.globals.script); }
    archive.profiles.forEach((entry: BackupProfile, index: number) => {
      const uid: string = `clashos-${index}`, option: VergeOption = { update_interval: entry.updateInterval, allow_auto_update: entry.updateInterval > 0 };
      const subscription: SubscriptionData | undefined = subscriptionData(entry.subscription);
      if (subscription) {
        option.user_agent = subscription.options.userAgent; option.timeout_seconds = subscription.options.timeoutSeconds;
        option.with_proxy = subscription.options.route === 'system'; option.self_proxy = subscription.options.route === 'core';
      }
      const file: string = `${uid}.yaml`;
      add(`profiles/${file}`, entry.content);
      option.merge = extension(`${uid}-merge`, 'merge', entry.merge ?? '');
      option.script = extension(`${uid}-script`, 'script', this.exportScript(entry));
      const sequence: MigratedSequences = entry.sequence ? JSON.parse(entry.sequence) as MigratedSequences : {
        rules: { prepend: [], append: [], delete: [] }, proxies: { prepend: [], append: [], delete: [] }, groups: { prepend: [], append: [], delete: [] } };
      option.rules = extension(`${uid}-rules`, 'rules', JSON.stringify(sequence.rules));
      option.proxies = extension(`${uid}-proxies`, 'proxies', JSON.stringify(sequence.proxies));
      option.groups = extension(`${uid}-groups`, 'groups', JSON.stringify(sequence.groups));
      const selected: VergeSelection[] = [];
      const pattern: RegExp = /("(?:[^"\\]|\\.)*")\s+("(?:[^"\\]|\\.)*")/g;
      let match: RegExpExecArray | null;
      while ((match = pattern.exec(entry.selections)) !== null) selected.push({ name: JSON.parse(match[1]) as string, now: JSON.parse(match[2]) as string });
      items.push({ uid, type: entry.sourceUrl ? 'remote' : 'local', name: entry.name, file, url: entry.sourceUrl || undefined, option, selected,
        extra: entry.sourceUrl ? subscription?.info?.usage : undefined, home: entry.sourceUrl ? subscription?.info?.home : undefined,
        updated: subscription?.info ? Math.floor(subscription.info.checkedAt / 1000) : undefined });
    });
    add('profiles.yaml', JSON.stringify({ current: archive.profiles.length ? 'clashos-0' : undefined, items } as VergeIndex));
    add('config.yaml', '{}\n');
    add('verge.yaml', JSON.stringify({ theme_mode: archive.appearance?.mode ?? 'system' } as VergeAppearance));
    add('clashos-backup.json', JSON.stringify(archive));
    add('ClashOS-README.txt', 'ClashOS backup: profiles.yaml and profiles/ follow Clash Verge Rev. Native caches, edits, appearance and explicitly selected ClashOS network/window/tray preferences are preserved in clashos-backup.json for lossless ClashOS restoration. Network preferences may contain proxy account passwords. Desktop-compatible members do not apply ClashOS network/window/tray preferences. Desktop DNS overrides, system proxy, WebDAV accounts and controller keys are not migrated. File providers may need reimport on the destination.\n');
    return writeZip(files);
  }
}
