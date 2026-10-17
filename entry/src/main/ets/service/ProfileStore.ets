import { common } from '@kit.AbilityKit';
import { fileIo, fileUri, picker } from '@kit.CoreFileKit';
import { http } from '@kit.NetworkKit';
import { util } from '@kit.ArkTS';
import { ClashNativeCore } from './ClashNativeCore';
import { utf8Bytes } from './TextCodec';
import { RuleEdits, RuleEditorSnapshot, parseRuleEditsText } from './RuleEditsTypes';
import { ObjectEdits, ObjectEditorSnapshot, ProxyNodeDraft, ProxyGroupDraft, parseObjectEditsText } from './ObjectEditsTypes';
import { mergeSettingsText, ScriptPreview } from './ConfigMergeTypes';
import { BackupArchiveCodec } from './BackupArchiveCodec';
import { BACKUP_LIMIT, BACKUP_RESOURCE_PATTERN, BackupProfile, BackupResource, BackupPreview, BackupPreviewRow, ProfileBackup, BackupGlobals, BackupCreateOptions } from './BackupTypes';
import { AppearanceStore } from './AppearanceStore';
import { appearanceSettings } from '../theme/AppearanceTypes';
import { GroupIconStore } from './GroupIconStore';
import { validateGroupIconBackup } from './GroupIconBackup';

export interface ClashProfile {
  id: string;
  name: string;
  fileName: string;
  path: string;
  format: string;
  size: number;
  updatedAt: string;
  sourceUrl: string;
  updateInterval: number;
  pinned: boolean;
}

interface ProfileMetadata {
  name: string;
  sourceUrl: string;
  updateInterval: number;
  updatedAt: number;
  pinned: boolean;
}

export interface MergeEditSnapshot {
  sequence: string;
  profile?: ClashProfile;
  global: boolean;
  source: string;
  rules: string;
  objects: string;
  settings: string;
  globalText: string;
  profileText: string;
  script: boolean;
  globalScript: string;
  profileScript: string;
  profileName: string;
}

export const DEFAULT_PROFILE: string = 'mixed-port: 7890\nmode: rule\nproxies: []\nproxy-groups: []\nrules:\n  - MATCH,DIRECT\n';

export class ProfileStore {
  private context: common.UIAbilityContext;
  private profileDir: string;
  private validator: ClashNativeCore = new ClashNativeCore();
  private idCounter: number = 0;

  constructor(context: common.UIAbilityContext) {
    this.context = context;
    this.profileDir = `${context.filesDir}/profiles`;
    this.ensureDirectory();
  }

  async pickAndImport(): Promise<ClashProfile | undefined> {
    const options = new picker.DocumentSelectOptions();
    options.fileSuffixFilters = ['Clash 配置|.yaml,.yml,.json'];
    options.maxSelectNumber = 1;
    const paths: string[] = await new picker.DocumentViewPicker(this.context).select(options);
    return paths.length === 0 ? undefined : this.importPath(paths[0]);
  }

  async pickProviderContent(): Promise<string | undefined> {
    const options = new picker.DocumentSelectOptions();
    options.fileSuffixFilters = ['代理集合|.yaml,.yml,.json'];
    options.maxSelectNumber = 1;
    const paths: string[] = await new picker.DocumentViewPicker(this.context).select(options);
    return paths.length === 0 ? undefined : this.readSelectedText(paths[0]);
  }

  async pickRuleProviderFile(): Promise<string | undefined> {
    const options = new picker.DocumentSelectOptions();
    options.fileSuffixFilters = ['规则集合|.yaml,.yml,.json,.txt,.mrs'];
    options.maxSelectNumber = 1;
    const paths: string[] = await new picker.DocumentViewPicker(this.context).select(options);
    if (paths.length === 0) return undefined;
    const destination: string = `${this.profileDir}/.rule-import-${Date.now()}-${this.idCounter++}.tmp`;
    this.copyResourceFile(paths[0], destination);
    return destination;
  }

  releaseRuleImport(path: string): void {
    if (path.startsWith(`${this.profileDir}/.rule-import-`) && path.endsWith('.tmp') && this.exists(path)) fileIo.unlinkSync(path);
  }

  async pickGeoFile(): Promise<string | undefined> {
    const options = new picker.DocumentSelectOptions();
    options.fileSuffixFilters = ['地理数据库|.dat,.mmdb'];
    options.maxSelectNumber = 1;
    const paths: string[] = await new picker.DocumentViewPicker(this.context).select(options);
    if (paths.length === 0) return undefined;
    const destination: string = `${this.profileDir}/.geo-import-${Date.now()}-${this.idCounter++}.tmp`;
    this.copyResourceFile(paths[0], destination, 64 * 1024 * 1024);
    return destination;
  }

  releaseGeoImport(path: string): void {
    if (path.startsWith(`${this.profileDir}/.geo-import-`) && path.endsWith('.tmp') && this.exists(path)) fileIo.unlinkSync(path);
  }

  private copyResourceFile(source: string, destination: string, limit: number = 8 * 1024 * 1024): void {
    const temporary: string = `${destination}.tmp`;
    let input: fileIo.File;
    try { input = fileIo.openSync(source, fileIo.OpenMode.READ_ONLY); }
    catch (_) { input = fileIo.openSync(this.resolvePath(source), fileIo.OpenMode.READ_ONLY); }
    try {
      if (fileIo.statSync(input.fd).size > limit) throw new Error(`资源文件超过 ${limit / (1024 * 1024)} MB`);
      const output = fileIo.openSync(temporary, fileIo.OpenMode.CREATE | fileIo.OpenMode.READ_WRITE | fileIo.OpenMode.TRUNC);
      try {
        this.validator.protectFile(output.fd);
        const buffer: ArrayBuffer = new ArrayBuffer(8192);
        let total: number = 0;
        while (true) {
          const count: number = fileIo.readSync(input.fd, buffer);
          if (count === 0) break;
          total += count;
          if (total > limit) throw new Error(`资源文件超过 ${limit / (1024 * 1024)} MB`);
          let written: number = 0;
          while (written < count) {
            const chunk: ArrayBuffer = buffer.slice(written, count);
            const size: number = fileIo.writeSync(output.fd, chunk);
            if (size <= 0 || size > count - written) throw new Error('规则集合文件未完整写入');
            written += size;
          }
        }
        fileIo.fsyncSync(output.fd);
      } finally { fileIo.closeSync(output); }
      fileIo.renameSync(temporary, destination);
    } finally {
      fileIo.closeSync(input);
      if (this.exists(temporary)) fileIo.unlinkSync(temporary);
    }
  }

  private readSelectedText(path: string, limit: number = 8 * 1024 * 1024): string {
    let file: fileIo.File;
    try { file = fileIo.openSync(path, fileIo.OpenMode.READ_ONLY); }
    catch (_) { file = fileIo.openSync(this.resolvePath(path), fileIo.OpenMode.READ_ONLY); }
    try {
      if (fileIo.statSync(file.fd).size > limit) throw new Error(`文件超过 ${limit / (1024 * 1024)} MB`);
      const decoder = util.TextDecoder.create('utf-8', { fatal: true });
      const buffer: ArrayBuffer = new ArrayBuffer(8192);
      const chunks: string[] = [];
      let total: number = 0;
      while (true) {
        const count: number = fileIo.readSync(file.fd, buffer);
        if (count === 0) break;
        total += count;
        if (total > limit) throw new Error(`文件超过 ${limit / (1024 * 1024)} MB`);
        chunks.push(decoder.decodeToString(new Uint8Array(buffer, 0, count), { stream: true }));
      }
      chunks.push(decoder.decodeToString(new Uint8Array(0)));
      return chunks.join('');
    } finally { fileIo.closeSync(file); }
  }

  importPath(sourcePath: string): ClashProfile {
    const content: string = this.readSelectedText(sourcePath);
    const fileName: string = this.baseName(this.resolvePath(sourcePath));
    return this.create(fileName.replace(/\.(yaml|yml|json)$/i, ''), content);
  }

  create(name: string, content: string = DEFAULT_PROFILE, sourceUrl: string = '', rules: string = '', objects: string = '', merge: string = '', script: string = '', globals?: BackupGlobals, sequence: string = ''): ClashProfile {
    const cleanName: string = this.validName(name);
    this.validateConfig(content, rules, objects, mergeSettingsText(globals?.merge ?? this.globalMergeText(), merge, globals?.script ?? this.globalScriptText(), script, cleanName, sequence));
    let id: string;
    do { id = `${Date.now()}-${this.idCounter++}`; }
    while (['.yaml', '.yml', '.json', '.meta.json', '.yaml.rules.json', '.json.rules.json', '.yaml.objects.json', '.json.objects.json', '.yaml.merge.yaml', '.json.merge.yaml', '.yaml.script.js', '.json.script.js', '.yaml.selections', '.json.selections'].some((suffix: string) => this.exists(`${this.profileDir}/${id}${suffix}`)));
    const format: string = content.trim().startsWith('{') ? 'JSON' : 'YAML';
    const fileName: string = `${id}.${format === 'JSON' ? 'json' : 'yaml'}`;
    const metadata: ProfileMetadata = {
      name: cleanName, sourceUrl, updateInterval: 0, updatedAt: Date.now(), pinned: false
    };
    this.atomicWrite(`${this.profileDir}/${fileName}`, content);
    try {
      if (rules) this.atomicWrite(`${this.profileDir}/${fileName}.rules.json`, rules);
      if (objects) this.atomicWrite(`${this.profileDir}/${fileName}.objects.json`, objects);
      if (merge) this.atomicWrite(`${this.profileDir}/${fileName}.merge.yaml`, merge);
      if (script) this.atomicWrite(`${this.profileDir}/${fileName}.script.js`, script);
      if (sequence) this.atomicWrite(`${this.profileDir}/${fileName}.verge-seq.json`, sequence);
      this.writeMetadata(id, metadata);
    } catch (error) {
      let cleaned: boolean = true;
      [`${this.profileDir}/${fileName}`, `${this.profileDir}/${fileName}.rules.json`, `${this.profileDir}/${fileName}.objects.json`, `${this.profileDir}/${fileName}.merge.yaml`, `${this.profileDir}/${fileName}.script.js`, `${this.profileDir}/${fileName}.verge-seq.json`, `${this.profileDir}/${id}.meta.json`]
        .forEach((path: string) => { try { if (this.exists(path)) fileIo.unlinkSync(path); } catch (_) { cleaned = false; } });
      throw new Error(`${(error as Error).message}${cleaned ? '' : '；部分新增文件未能清理'}`);
    }
    return this.makeProfile(id, fileName, content, metadata);
  }

  list(): ClashProfile[] {
    this.ensureDirectory();
    const profiles: ClashProfile[] = [];
    fileIo.listFileSync(this.profileDir).forEach((fileName: string) => {
      if (!/\.(yaml|yml|json)$/i.test(fileName) || fileName.startsWith('.') || fileName.endsWith('.meta.json') || fileName.endsWith('.rules.json') || fileName.endsWith('.objects.json') || fileName.endsWith('.merge.yaml') || fileName.endsWith('.verge-seq.json')) return;
      try {
        const id: string = fileName.replace(/\.(yaml|yml|json)$/i, '');
        const text: string = fileIo.readTextSync(`${this.profileDir}/${fileName}`);
        const metadata: ProfileMetadata = this.readMetadata(id, fileName);
        profiles.push(this.makeProfile(id, fileName, text, metadata));
      } catch (_) {
        // A concurrently removed file is skipped; stored configurations are never replaced here.
      }
    });
    profiles.sort((a: ClashProfile, b: ClashProfile) => a.pinned !== b.pinned ? (a.pinned ? -1 : 1) :
      Number(b.id.split('-')[0]) - Number(a.id.split('-')[0]));
    return profiles;
  }

  read(profile: ClashProfile): string {
    return fileIo.readTextSync(this.profilePath(profile));
  }

  ruleEditsText(profile: ClashProfile): string {
    const path: string = `${this.profilePath(profile)}.rules.json`;
    if (!this.exists(path)) return '';
    if (fileIo.statSync(path).size > 256 * 1024) throw new Error('自定义规则超过 256 KB');
    const text: string = fileIo.readTextSync(path);
    if (!text) throw new Error('自定义规则文件为空');
    parseRuleEditsText(text);
    return text;
  }

  objectEditsText(profile: ClashProfile): string {
    const path: string = `${this.profilePath(profile)}.objects.json`;
    if (!this.exists(path)) return '';
    if (fileIo.statSync(path).size > 2 * 1024 * 1024) throw new Error('节点和代理组修改超过 2 MB');
    const text: string = fileIo.readTextSync(path);
    if (!text) throw new Error('节点和代理组修改文件为空');
    parseObjectEditsText(text); return text;
  }

  private readMergeText(path: string): string {
    if (!this.exists(path)) return '';
    if (fileIo.statSync(path).size > 256 * 1024) throw new Error('扩展配置超过 256 KB');
    const text: string = fileIo.readTextSync(path);
    if (!text) throw new Error('扩展配置文件为空');
    if (utf8Bytes(text).length > 256 * 1024) throw new Error('扩展配置超过 256 KB');
    return text;
  }

  globalMergeText(): string { return this.readMergeText(`${this.profileDir}/.global-merge.yaml`); }
  profileMergeText(profile: ClashProfile): string { return this.readMergeText(`${this.profilePath(profile)}.merge.yaml`); }
  globalScriptText(): string { return this.readMergeText(`${this.profileDir}/.global-script.js`); }
  sequenceText(profile: ClashProfile): string { return this.readMergeText(`${this.profilePath(profile)}.verge-seq.json`); }
  backupGlobals(): BackupGlobals { return { merge: this.globalMergeText(), script: this.globalScriptText() }; }
  backupNamesSnapshot(): string { return JSON.stringify(this.list().map((profile: ClashProfile) => `${profile.id}/${profile.name}`).sort()); }
  validateBackupGlobals(profile: ClashProfile | undefined, globals: BackupGlobals): void {
    this.validator.ruleEditor(profile ? this.read(profile) : DEFAULT_PROFILE, profile ? this.ruleEditsText(profile) : '', true,
      profile ? this.objectEditsText(profile) : '', mergeSettingsText(globals.merge, profile ? this.profileMergeText(profile) : '',
        globals.script, profile ? this.profileScriptText(profile) : '', profile?.name ?? '默认配置', profile ? this.sequenceText(profile) : ''));
  }
  replaceBackupGlobals(expected: BackupGlobals, next: BackupGlobals): void {
    const current: BackupGlobals = this.backupGlobals();
    if (current.merge !== expected.merge || current.script !== expected.script) throw new Error('全局扩展已变化，请重新预览备份');
    const mergePath: string = `${this.profileDir}/.global-merge.yaml`, scriptPath: string = `${this.profileDir}/.global-script.js`;
    let mergeChanged: boolean = false;
    try {
      if (next.merge !== expected.merge) { this.writeOptionalText(mergePath, next.merge); mergeChanged = true; }
      if (next.script !== expected.script) this.writeOptionalText(scriptPath, next.script);
    } catch (_) {
      if (mergeChanged) {
        try { this.writeOptionalText(mergePath, expected.merge); }
        catch (_) { throw new Error('全局扩展写入失败，原 YAML 扩展未能撤回，请检查存储后重新加载配置'); }
      }
      throw new Error('全局扩展未能保存，原设置已保留');
    }
  }
  private writeOptionalText(path: string, text: string): void {
    if (text.length > 0) this.atomicWrite(path, text);
    else if (this.exists(path)) fileIo.unlinkSync(path);
  }
  profileScriptText(profile: ClashProfile): string { return this.readMergeText(`${this.profilePath(profile)}.script.js`); }
  mergeSettings(profile?: ClashProfile, profileName?: string): string {
    return mergeSettingsText(this.globalMergeText(), profile ? this.profileMergeText(profile) : '', this.globalScriptText(), profile ? this.profileScriptText(profile) : '',
      profileName ?? (profile ? this.readMetadata(profile.id, profile.fileName).name : '默认配置'), profile ? this.sequenceText(profile) : '');
  }

  mergeSnapshot(profile: ClashProfile | undefined, global: boolean, script: boolean = false): MergeEditSnapshot {
    const globalText: string = this.globalMergeText(), profileText: string = profile ? this.profileMergeText(profile) : '';
    const globalScript: string = this.globalScriptText(), profileScript: string = profile ? this.profileScriptText(profile) : '';
    const profileName: string = profile ? this.readMetadata(profile.id, profile.fileName).name : '默认配置';
    const sequence: string = profile ? this.sequenceText(profile) : '';
    return { profile, global, source: profile ? this.read(profile) : DEFAULT_PROFILE, rules: profile ? this.ruleEditsText(profile) : '',
      objects: profile ? this.objectEditsText(profile) : '', settings: mergeSettingsText(globalText, profileText, globalScript, profileScript, profileName, sequence), sequence, globalText, profileText,
      script, globalScript, profileScript, profileName };
  }

  private editedExtensions(snapshot: MergeEditSnapshot, text: string): string {
    return mergeSettingsText(!snapshot.script && snapshot.global ? text : snapshot.globalText, !snapshot.script && !snapshot.global ? text : snapshot.profileText,
      snapshot.script && snapshot.global ? text : snapshot.globalScript, snapshot.script && !snapshot.global ? text : snapshot.profileScript, snapshot.profileName, snapshot.sequence);
  }

  previewMerge(snapshot: MergeEditSnapshot, text: string): string {
    const merges: string = this.editedExtensions(snapshot, text);
    const result = this.validator.ruleEditor(snapshot.source, snapshot.rules, true, snapshot.objects, merges);
    if (result.content === undefined) throw new Error('内核未能生成合并配置');
    return result.content;
  }

  previewScript(snapshot: MergeEditSnapshot, text: string): ScriptPreview {
    return this.validator.previewExtensions(snapshot.source, snapshot.rules, snapshot.objects, this.editedExtensions(snapshot, text));
  }

  saveMerge(snapshot: MergeEditSnapshot, text: string): string {
    const current = this.mergeSnapshot(snapshot.profile, snapshot.global, snapshot.script);
    if (current.source !== snapshot.source || current.rules !== snapshot.rules || current.objects !== snapshot.objects || current.settings !== snapshot.settings)
      throw new Error('配置或扩展已变化，请重新打开扩展编辑器');
    this.previewMerge(snapshot, text);
    const value: string = text.trim() ? text : '';
    const path: string = snapshot.script ? (snapshot.global ? `${this.profileDir}/.global-script.js` : `${this.profilePath(snapshot.profile as ClashProfile)}.script.js`) :
      snapshot.global ? `${this.profileDir}/.global-merge.yaml` : `${this.profilePath(snapshot.profile as ClashProfile)}.merge.yaml`;
    if (value) this.atomicWrite(path, value); else if (this.exists(path)) fileIo.unlinkSync(path);
    return value;
  }

  rollbackMerge(snapshot: MergeEditSnapshot, expected: string, previous: string): void {
    const path: string = snapshot.script ? (snapshot.global ? `${this.profileDir}/.global-script.js` : `${this.profilePath(snapshot.profile as ClashProfile)}.script.js`) :
      snapshot.global ? `${this.profileDir}/.global-merge.yaml` : `${this.profilePath(snapshot.profile as ClashProfile)}.merge.yaml`;
    if (this.readMergeText(path) !== expected) throw new Error('扩展配置已被其他操作修改');
    if (previous) this.atomicWrite(path, previous); else if (this.exists(path)) fileIo.unlinkSync(path);
  }

  previewObjects(content: string, edits: ObjectEdits, rules: string = '', validate: boolean = true, merges: string = ''): ObjectEditorSnapshot {
    const text: string = JSON.stringify(edits); parseObjectEditsText(text); parseRuleEditsText(rules);
    return this.validator.objectEditor(content, text, rules, validate, merges);
  }

  nodeDraft(content: string, patch: string = '', validate: boolean = true): ProxyNodeDraft { return this.validator.nodeDraft(content, patch, validate); }
  groupDraft(content: string, patch: string = '', validate: boolean = true): ProxyGroupDraft { return this.validator.groupDraft(content, patch, validate); }

  saveObjectEdits(profile: ClashProfile, expectedContent: string, expectedRules: string, expectedObjects: string, edits: ObjectEdits, expectedMerges?: string): string {
    if (this.read(profile) !== expectedContent || this.ruleEditsText(profile) !== expectedRules || this.objectEditsText(profile) !== expectedObjects) throw new Error('配置、规则或节点已变化，请重新打开编辑器');
    const merges: string = this.mergeSettings(profile);
    if (expectedMerges !== undefined && merges !== expectedMerges) throw new Error('扩展配置已变化，请重新打开编辑器');
    this.previewObjects(expectedContent, edits, expectedRules, true, merges);
    const text: string = JSON.stringify(edits); this.atomicWrite(`${this.profilePath(profile)}.objects.json`, text); return text;
  }

  rollbackObjectEdits(profile: ClashProfile, expected: string, previous: string): void {
    if (this.objectEditsText(profile) !== expected) throw new Error('节点和代理组已被其他操作修改');
    const path: string = `${this.profilePath(profile)}.objects.json`;
    if (previous) this.atomicWrite(path, previous); else fileIo.unlinkSync(path);
  }

  previewRules(content: string, edits: RuleEdits, render: boolean = false, objects: string = '', merges: string = ''): RuleEditorSnapshot {
    const text: string = JSON.stringify(edits);
    parseRuleEditsText(text); parseObjectEditsText(objects);
    return this.validator.ruleEditor(content, text, render, objects, merges);
  }

  saveRuleEdits(profile: ClashProfile, expectedContent: string, expectedEdits: string, edits: RuleEdits, expectedObjects?: string, expectedMerges?: string): string {
    const objects: string = this.objectEditsText(profile);
    if (this.read(profile) !== expectedContent || this.ruleEditsText(profile) !== expectedEdits || (expectedObjects !== undefined && objects !== expectedObjects)) throw new Error('配置、规则或节点已变化，请重新打开编辑器');
    const merges: string = this.mergeSettings(profile);
    if (expectedMerges !== undefined && merges !== expectedMerges) throw new Error('扩展配置已变化，请重新打开编辑器');
    this.previewRules(expectedContent, edits, false, objects, merges);
    const text: string = JSON.stringify(edits);
    this.atomicWrite(`${this.profilePath(profile)}.rules.json`, text);
    return text;
  }

  rollbackRuleEdits(profile: ClashProfile, expectedEdits: string, previous: string): void {
    if (this.ruleEditsText(profile) !== expectedEdits) throw new Error('自定义规则已被其他操作修改');
    const path: string = `${this.profilePath(profile)}.rules.json`;
    if (previous) this.atomicWrite(path, previous);
    else fileIo.unlinkSync(path);
  }

  effectiveContent(profile: ClashProfile): string {
    const content: string = this.read(profile), edits: string = this.ruleEditsText(profile), objects: string = this.objectEditsText(profile);
    const merges: string = this.mergeSettings(profile);
    if (!edits && !objects && !merges) return content;
    const rendered: string | undefined = this.previewRules(content, parseRuleEditsText(edits), true, objects, merges).content;
    if (rendered === undefined) throw new Error('内核未能生成完整配置');
    return rendered;
  }

  async pickBackup(): Promise<string | undefined> {
    const options = new picker.DocumentSelectOptions();
    options.fileSuffixFilters = ['ClashOS / Clash Verge 备份|.json,.zip'];
    options.maxSelectNumber = 1;
    const paths: string[] = await new picker.DocumentViewPicker(this.context).select(options);
    if (paths.length === 0) return undefined;
    let file: fileIo.File;
    try { file = fileIo.openSync(paths[0], fileIo.OpenMode.READ_ONLY); }
    catch (_) { file = fileIo.openSync(this.resolvePath(paths[0]), fileIo.OpenMode.READ_ONLY); }
    let bytes: Uint8Array;
    try {
      if (fileIo.statSync(file.fd).size > BACKUP_LIMIT) throw new Error('备份超过 32 MB');
      const parts: Uint8Array[] = []; let total: number = 0;
      const buffer: ArrayBuffer = new ArrayBuffer(8192);
      while (true) {
        const count: number = fileIo.readSync(file.fd, buffer); if (!count) break;
        total += count; if (total > BACKUP_LIMIT) throw new Error('备份超过 32 MB'); parts.push(new Uint8Array(buffer.slice(0, count)));
      }
      bytes = new Uint8Array(total); let offset: number = 0;
      parts.forEach((part: Uint8Array) => { bytes.set(part, offset); offset += part.length; });
    } finally { fileIo.closeSync(file); }
    return bytes.length > 1 && bytes[0] === 0x50 && bytes[1] === 0x4b ? new BackupArchiveCodec(this.validator).decode(bytes) : util.TextDecoder.create('utf-8', { fatal: true }).decodeToString(bytes);
  }

  private readBackupResource(path: string): Uint8Array {
    const file = fileIo.openSync(path, fileIo.OpenMode.READ_ONLY);
    try {
      const limit: number = 8 * 1024 * 1024 + 256;
      if (fileIo.statSync(file.fd).size > limit) throw new Error('集合缓存超过备份上限');
      const parts: Uint8Array[] = [];
      const buffer = new ArrayBuffer(8192);
      let total: number = 0;
      while (true) {
        const count: number = fileIo.readSync(file.fd, buffer);
        if (count === 0) break;
        total += count;
        if (total > limit) throw new Error('集合缓存超过备份上限');
        parts.push(new Uint8Array(buffer.slice(0, count)));
      }
      const result = new Uint8Array(total);
      let offset: number = 0;
      parts.forEach((part: Uint8Array) => { result.set(part, offset); offset += part.length; });
      return result;
    } finally { fileIo.closeSync(file); }
  }

  createBackup(options?: BackupCreateOptions): string {
    const available: ClashProfile[] = this.list();
    if (options && (new Set(options.profileIds).size !== options.profileIds.length || options.profileIds.some((id: string) => !available.some((p: ClashProfile) => p.id === id))))
      throw new Error('所选配置已变化，请重新选择备份内容');
    const profiles: ClashProfile[] = options ? available.filter((profile: ClashProfile) => options.profileIds.indexOf(profile.id) >= 0) : available;
    if (profiles.length === 0 && (!options || (!options.includeGlobals && !options.includeAppearance))) throw new Error('请选择配置或需要备份的设置');
    if (profiles.length > 500) throw new Error('一次最多备份 500 份配置');
    const names: string[] = fileIo.listFileSync(this.profileDir);
    const entries: BackupProfile[] = [];
    let estimated: number = 0;
    const base64 = new util.Base64Helper();
    profiles.forEach((profile: ClashProfile) => {
      const content: string = this.read(profile);
      const selectionsPath: string = `${this.profilePath(profile)}.selections`;
      if (this.exists(selectionsPath) && fileIo.statSync(selectionsPath).size > 65536) throw new Error('节点选择记录超过备份上限');
      const selections: string = this.exists(selectionsPath) ? fileIo.readTextSync(selectionsPath) : '';
      if (utf8Bytes(selections).length > 65536) throw new Error('节点选择记录超过备份上限');
      const resources: BackupResource[] = [];
      estimated += utf8Bytes(content).length + selections.length;
      names.forEach((name: string) => {
        if (!name.startsWith(profile.fileName)) return;
        const suffix: string = name.substring(profile.fileName.length);
        if (!BACKUP_RESOURCE_PATTERN.test(suffix)) return;
        const data: string = base64.encodeToStringSync(this.readBackupResource(`${this.profileDir}/${name}`));
        resources.push({ suffix, data }); estimated += data.length;
        if (resources.length > 256 || estimated > BACKUP_LIMIT) throw new Error('备份超过 32 MB 或集合数量上限');
      });
      const ruleEdits: string = this.ruleEditsText(profile);
      const objectEdits: string = this.objectEditsText(profile);
      const merge: string = this.profileMergeText(profile);
      const script: string = this.profileScriptText(profile);
      const sequence: string = this.sequenceText(profile);
      estimated += utf8Bytes(ruleEdits).length + utf8Bytes(objectEdits).length + utf8Bytes(merge).length + utf8Bytes(script).length + utf8Bytes(sequence).length;
      entries.push({ name: profile.name, content, ruleEdits, objectEdits, merge, script, sequence, sourceUrl: profile.sourceUrl, updateInterval: profile.updateInterval,
        pinned: profile.pinned, selections, resources });
      if (estimated > BACKUP_LIMIT) throw new Error('备份超过 32 MB');
    });
    const backup: ProfileBackup = { format: 'ClashOS.profile-backup', version: options ? 2 : 1, createdAt: new Date().toISOString(), profiles: entries };
    if (options?.includeGlobals) backup.globals = this.backupGlobals();
    if (options?.includeAppearance) {
      backup.appearance = new AppearanceStore(this.context.filesDir, (fd: number) => this.validator.protectFile(fd)).load();
      backup.groupIcons = new GroupIconStore(this.context.filesDir, (fd: number) => this.validator.protectFile(fd)).exportBackup();
    }
    const text: string = JSON.stringify(backup);
    if (utf8Bytes(text).length > BACKUP_LIMIT) throw new Error('备份超过 32 MB');
    return text;
  }

  inspectBackup(text: string, useArchiveGlobals: boolean = false): BackupPreview {
    const started: number = Date.now();
    if (utf8Bytes(text).length > BACKUP_LIMIT) throw new Error('备份超过 32 MB');
    let archive: ProfileBackup;
    try { archive = JSON.parse(text) as ProfileBackup; } catch (_) { throw new Error('备份不是有效的 JSON 文件'); }
    if (archive === null || typeof archive !== 'object' || archive.format !== 'ClashOS.profile-backup' || [1, 2].indexOf(archive.version) < 0 ||
      typeof archive.createdAt !== 'string' || !Number.isFinite(Date.parse(archive.createdAt)) ||
      !Array.isArray(archive.profiles) || archive.profiles.length > 500 ||
      (archive.profiles.length === 0 && (archive.version !== 2 || (archive.globals === undefined && archive.appearance === undefined)))) throw new Error('备份格式或版本不受支持');
    if (archive.version === 1 && (archive.globals !== undefined || archive.appearance !== undefined)) throw new Error('旧版备份不能包含全局设置');
    if (archive.groupIcons !== undefined) {
      if (archive.version !== 2 || archive.appearance === undefined) throw new Error('代理组图标必须随外观备份');
      archive.groupIcons = validateGroupIconBackup(archive.groupIcons);
    }
    if (archive.migrationNotes !== undefined && (!Array.isArray(archive.migrationNotes) || archive.migrationNotes.length > 16 ||
      archive.migrationNotes.some((note: string) => typeof note !== 'string' || utf8Bytes(note).length > 2048))) throw new Error('备份迁移说明无效');
    if (archive.globals !== undefined) {
      const value: BackupGlobals = archive.globals;
      if (value === null || typeof value !== 'object' || typeof value.merge !== 'string' || typeof value.script !== 'string' ||
        utf8Bytes(value.merge).length > 256 * 1024 || utf8Bytes(value.script).length > 256 * 1024) throw new Error('备份中的全局扩展无效或过大');
      archive.globals = { merge: value.merge.trim() ? value.merge : '', script: value.script.trim() ? value.script : '' };
    }
    if (archive.appearance !== undefined) {
      const value = archive.appearance;
      if (value === null || typeof value !== 'object' || typeof value.mode !== 'string' || typeof value.accent !== 'string' || value.mode.length > 16 || value.accent.length > 32)
        throw new Error('备份中的外观设置无效');
      archive.appearance = appearanceSettings(value.mode, value.accent, value.styles);
    }
    if (useArchiveGlobals && archive.globals === undefined) throw new Error('此备份不包含全局扩展');
    const currentGlobals: BackupGlobals = this.backupGlobals();
    const globals: BackupGlobals = useArchiveGlobals ? archive.globals as BackupGlobals : currentGlobals;
    const existing: ClashProfile[] = this.list();
    const names: string[] = existing.map((profile: ClashProfile) => profile.name);
    const namesSnapshot: string = JSON.stringify(existing.map((profile: ClashProfile) => `${profile.id}/${profile.name}`).sort());
    const rows: BackupPreviewRow[] = [];
    archive.profiles.forEach((entry: BackupProfile, index: number) => {
      if (Date.now() - started > 10000) throw new Error('备份校验耗时过长，请检查扩展脚本');
      if (entry === null || typeof entry !== 'object' || typeof entry.name !== 'string' || typeof entry.content !== 'string' ||
        typeof entry.sourceUrl !== 'string' || entry.sourceUrl.length > 8192 || typeof entry.pinned !== 'boolean' ||
        !Number.isInteger(entry.updateInterval) || entry.updateInterval < 0 || entry.updateInterval > 10080 ||
        typeof entry.selections !== 'string' || utf8Bytes(entry.selections).length > 65536 ||
        !Array.isArray(entry.resources) || entry.resources.length > 256) throw new Error('备份中的配置信息无效');
      this.validName(entry.name);
      if (entry.ruleEdits !== undefined && typeof entry.ruleEdits !== 'string') throw new Error('备份中的自定义规则无效');
      parseRuleEditsText(entry.ruleEdits ?? '');
      if (entry.objectEdits !== undefined && typeof entry.objectEdits !== 'string') throw new Error('备份中的节点和代理组修改无效');
      parseObjectEditsText(entry.objectEdits ?? '');
      if (entry.merge !== undefined && (typeof entry.merge !== 'string' || utf8Bytes(entry.merge).length > 256 * 1024)) throw new Error('备份中的扩展配置无效或过大');
      if (entry.script !== undefined && (typeof entry.script !== 'string' || utf8Bytes(entry.script).length > 256 * 1024)) throw new Error('备份中的扩展脚本无效或过大');
      if (entry.sequence !== undefined && (typeof entry.sequence !== 'string' || utf8Bytes(entry.sequence).length > 256 * 1024)) throw new Error('备份中的迁移设置无效或过大');
      if (entry.sourceUrl.length > 0) this.checkUrl(entry.sourceUrl);
      if (utf8Bytes(entry.content).length > 8 * 1024 * 1024) throw new Error('备份中的配置超过 8 MB');
      const suffixes: string[] = [];
      entry.resources.forEach((resource: BackupResource) => {
        if (resource === null || typeof resource !== 'object' || typeof resource.suffix !== 'string' || typeof resource.data !== 'string' ||
          !BACKUP_RESOURCE_PATTERN.test(resource.suffix) || suffixes.indexOf(resource.suffix) >= 0 ||
          resource.data.length > 12 * 1024 * 1024 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(resource.data)) throw new Error('备份包含无效的集合缓存');
        const bytes: Uint8Array = new util.Base64Helper().decodeSync(resource.data);
        if (bytes.length > 8 * 1024 * 1024 + 256 || new util.Base64Helper().encodeToStringSync(bytes) !== resource.data) throw new Error('备份中的集合缓存无效或过大');
        suffixes.push(resource.suffix);
      });
      let restoreName: string = entry.name, counter: number = 1;
      while (names.indexOf(restoreName) >= 0) {
        const suffix: string = counter === 1 ? '（恢复）' : `（恢复 ${counter}）`;
        restoreName = entry.name.substring(0, 100 - suffix.length).replace(/[\uD800-\uDBFF]$/, '') + suffix; counter++;
      }
      names.push(restoreName);
      let valid: boolean = true, error: string = '';
      try {
        this.validateConfig(entry.content, entry.ruleEdits ?? '', entry.objectEdits ?? '', mergeSettingsText(globals.merge, entry.merge ?? '', globals.script, entry.script ?? '', restoreName, entry.sequence ?? ''));
      } catch (failure) { valid = false; error = (failure as Error).message || '当前内核无法加载'; }
      rows.push({ index, name: entry.name, valid, resources: entry.resources.length, restoreName, error });
    });
    return { archive, rows, currentGlobals, namesSnapshot };
  }

  restoreBackup(text: string, selected: number[], useArchiveGlobals: boolean = false): ClashProfile[] {
    const preview: BackupPreview = this.inspectBackup(text, useArchiveGlobals);
    if (selected.length === 0 || selected.some((index: number) => !Number.isInteger(index) || index < 0 || index >= preview.rows.length || !preview.rows[index].valid) ||
      new Set(selected).size !== selected.length) throw new Error('请选择可以加载的配置');
    const created: ClashProfile[] = [];
    const started: number = Date.now();
    try {
      selected.forEach((index: number) => {
        if (Date.now() - started > 10000) throw new Error('恢复耗时过长，请检查扩展脚本');
        const entry: BackupProfile = preview.archive.profiles[index];
        const name: string = preview.rows[index].restoreName;
        const profile: ClashProfile = this.create(name, entry.content, entry.sourceUrl, entry.ruleEdits ?? '', entry.objectEdits ?? '', entry.merge ?? '', entry.script ?? '',
          useArchiveGlobals ? preview.archive.globals : undefined, entry.sequence ?? '');
        created.push(profile);
        this.writeMetadata(profile.id, { name, sourceUrl: entry.sourceUrl, updateInterval: entry.updateInterval,
          updatedAt: Date.now(), pinned: entry.pinned });
        if (entry.selections.length > 0) this.atomicWrite(`${profile.path}.selections`, entry.selections);
        entry.resources.forEach((resource: BackupResource) => this.atomicWriteBytes(`${profile.path}${resource.suffix}`, new util.Base64Helper().decodeSync(resource.data)));
      });
      return created;
    } catch (error) {
      let cleaned: boolean = true;
      created.forEach((profile: ClashProfile) => { try { this.remove(profile); } catch (_) { cleaned = false; } });
      throw new Error(cleaned ? '恢复未能完成，本次新增配置已撤回' : '恢复未能完成，部分新增文件无法清理，请检查存储空间和权限');
    }
  }

  private atomicWriteBytes(path: string, bytes: Uint8Array): void {
    const temporary: string = `${path}.tmp`;
    try {
      const file = fileIo.openSync(temporary, fileIo.OpenMode.CREATE | fileIo.OpenMode.READ_WRITE | fileIo.OpenMode.TRUNC);
      try { this.validator.protectFile(file.fd); this.writeBytes(file.fd, bytes); } finally { fileIo.closeSync(file); }
      fileIo.renameSync(temporary, path);
    } finally { if (this.exists(temporary)) fileIo.unlinkSync(temporary); }
  }

  private checkDraftSource(profile: ClashProfile, expectedSource?: string): void {
    if (expectedSource !== undefined && this.read(profile) !== expectedSource)
      throw new Error('配置已被更新，请重新打开编辑器以免覆盖新内容');
  }

  checkDraft(name: string, content: string, profile?: ClashProfile, expectedSource?: string): void {
    if (profile) this.checkDraftSource(profile, expectedSource);
    const cleanName: string = this.validName(name);
    this.validateConfig(content, profile ? this.ruleEditsText(profile) : '', profile ? this.objectEditsText(profile) : '',
      profile ? this.mergeSettings(profile, cleanName) : mergeSettingsText(this.globalMergeText(), '', this.globalScriptText(), '', cleanName));
  }

  save(profile: ClashProfile, name: string, content: string, expectedSource?: string): ClashProfile {
    this.checkDraftSource(profile, expectedSource);
    this.validateConfig(content, this.ruleEditsText(profile), this.objectEditsText(profile), this.mergeSettings(profile, this.validName(name)));
    const metadata: ProfileMetadata = this.readMetadata(profile.id, profile.fileName);
    metadata.name = this.validName(name);
    metadata.updatedAt = Date.now();
    this.atomicWrite(this.profilePath(profile), content);
    this.writeMetadata(profile.id, metadata);
    return this.makeProfile(profile.id, profile.fileName, content, metadata);
  }

  updateInfo(profile: ClashProfile, name: string, url: string, interval: number): ClashProfile {
    if (url.length > 0) this.checkUrl(url);
    if (!Number.isInteger(interval) || interval < 0 || interval > 10080) {
      throw new Error('更新间隔必须为 0 至 10080 分钟，0 表示关闭');
    }
    const metadata: ProfileMetadata = this.readMetadata(profile.id, profile.fileName);
    if (name.trim() !== metadata.name && (this.globalScriptText() || this.profileScriptText(profile)))
      this.validateConfig(this.read(profile), this.ruleEditsText(profile), this.objectEditsText(profile), this.mergeSettings(profile, this.validName(name)));
    metadata.name = this.validName(name);
    metadata.sourceUrl = url.trim();
    metadata.updateInterval = interval;
    this.writeMetadata(profile.id, metadata);
    return this.makeProfile(profile.id, profile.fileName, this.read(profile), metadata);
  }

  rollbackInfo(profile: ClashProfile, expectedName: string, previous: ClashProfile): void {
    const metadata: ProfileMetadata = this.readMetadata(profile.id, profile.fileName);
    if (metadata.name !== expectedName) throw new Error('配置信息已被其他操作修改');
    metadata.name = previous.name; metadata.sourceUrl = previous.sourceUrl; metadata.updateInterval = previous.updateInterval;
    this.writeMetadata(profile.id, metadata);
  }

  duplicate(profile: ClashProfile): ClashProfile {
    const duplicate: ClashProfile = this.create(`${profile.name} 副本`, this.read(profile), '', this.ruleEditsText(profile), this.objectEditsText(profile), this.profileMergeText(profile), this.profileScriptText(profile), undefined, this.sequenceText(profile));
    try {
      const selections: string = `${this.profilePath(profile)}.selections`;
      if (this.exists(selections)) this.copyResourceFile(selections, `${duplicate.path}.selections`, 65536);
      fileIo.listFileSync(this.profileDir).forEach((name: string) => {
        if ((name.startsWith(`${profile.fileName}.provider-`) || name.startsWith(`${profile.fileName}.rule-provider-`)) && name.endsWith('.cache')) {
          this.copyResourceFile(`${this.profileDir}/${name}`, `${this.profileDir}/${duplicate.fileName}${name.substring(profile.fileName.length)}`, 8 * 1024 * 1024 + 256);
        }
      });
      return duplicate;
    } catch (error) {
      this.remove(duplicate);
      throw new Error(`复制集合缓存失败：${(error as Error).message}`);
    }
  }

  setPinned(profile: ClashProfile): ClashProfile {
    const metadata: ProfileMetadata = this.readMetadata(profile.id, profile.fileName);
    metadata.pinned = !metadata.pinned;
    this.writeMetadata(profile.id, metadata);
    return this.makeProfile(profile.id, profile.fileName, this.read(profile), metadata);
  }

  async importSubscription(name: string, url: string): Promise<ClashProfile> {
    const content: string = await this.download(url, '', '', this.mergeSettings(undefined, this.validName(name.trim() || '远程订阅')));
    return this.create(name.trim() || '远程订阅', content, url.trim());
  }

  async updateSubscription(profile: ClashProfile): Promise<ClashProfile> {
    if (profile.sourceUrl.length === 0) throw new Error('本地配置没有订阅地址');
    const content: string = await this.download(profile.sourceUrl, this.ruleEditsText(profile), this.objectEditsText(profile), this.mergeSettings(profile));
    return this.save(profile, profile.name, content);
  }

  async exportProfile(profile: ClashProfile): Promise<boolean> {
    return this.exportText(`${profile.name}.${profile.format === 'JSON' && !this.ruleEditsText(profile) && !this.objectEditsText(profile) && !this.mergeSettings(profile) ? 'json' : 'yaml'}`, this.effectiveContent(profile));
  }

  async exportText(name: string, text: string): Promise<boolean> {
    return this.exportBytes(name, utf8Bytes(text));
  }

  async exportBytes(name: string, bytes: Uint8Array): Promise<boolean> {
    const options = new picker.DocumentSaveOptions();
    options.newFileNames = [name.replace(/[\\/:*?"<>|]/g, '_')];
    const paths: string[] = await new picker.DocumentViewPicker(this.context).save(options);
    if (paths.length === 0) return false;
    const file = fileIo.openSync(paths[0], fileIo.OpenMode.READ_WRITE | fileIo.OpenMode.TRUNC);
    try {
      this.writeBytes(file.fd, bytes);
    } finally {
      fileIo.closeSync(file);
    }
    return true;
  }

  remove(profile: ClashProfile): void {
    fileIo.unlinkSync(this.profilePath(profile));
    const rules: string = `${this.profilePath(profile)}.rules.json`;
    if (this.exists(rules)) fileIo.unlinkSync(rules);
    const objects: string = `${this.profilePath(profile)}.objects.json`;
    if (this.exists(objects)) fileIo.unlinkSync(objects);
    const merge: string = `${this.profilePath(profile)}.merge.yaml`;
    if (this.exists(merge)) fileIo.unlinkSync(merge);
    const script: string = `${this.profilePath(profile)}.script.js`;
    if (this.exists(script)) fileIo.unlinkSync(script);
    const sequence: string = `${this.profilePath(profile)}.verge-seq.json`;
    if (this.exists(sequence)) fileIo.unlinkSync(sequence);
    fileIo.listFileSync(this.profileDir).forEach((name: string) => {
      if ((name.startsWith(`${profile.fileName}.provider-`) || name.startsWith(`${profile.fileName}.rule-provider-`)) && (name.endsWith('.cache') || name.indexOf('.cache.tmp') >= 0)) {
        fileIo.unlinkSync(`${this.profileDir}/${name}`);
      }
    });
    for (const suffix of ['.meta.json', '.yaml.selections', '.json.selections', '.yml.selections']) {
      const path: string = `${this.profileDir}/${profile.id}${suffix}`;
      if (this.exists(path)) fileIo.unlinkSync(path);
    }
  }

  isUpdateDue(profile: ClashProfile): boolean {
    if (profile.sourceUrl.length === 0 || profile.updateInterval <= 0) return false;
    const metadata: ProfileMetadata = this.readMetadata(profile.id, profile.fileName);
    return Date.now() - metadata.updatedAt >= profile.updateInterval * 60000;
  }

  private async download(url: string, rules: string = '', objects: string = '', merges: string = ''): Promise<string> {
    this.checkUrl(url);
    const request = http.createHttp();
    try {
      const result = await request.request(url.trim(), {
        method: http.RequestMethod.GET,
        header: { 'User-Agent': 'ClashOS/1.0', 'Accept': 'application/yaml, application/json, text/plain' },
        connectTimeout: 10000,
        readTimeout: 20000,
        maxLimit: 8 * 1024 * 1024,
        expectDataType: http.HttpDataType.STRING
      });
      if (result.responseCode < 200 || result.responseCode >= 300) {
        throw new Error(`订阅服务器返回 HTTP ${result.responseCode}`);
      }
      const content: string = result.result.toString();
      this.validateConfig(content, rules, objects, merges);
      return content;
    } catch (error) {
      // Avoid putting token-bearing subscription URLs in logs or error banners.
      const message: string = (error as Error).message || '';
      if (message.startsWith('订阅服务器') || message.startsWith('配置')) throw new Error(message);
      throw new Error('订阅下载或校验失败，原配置已保留');
    } finally {
      request.destroy();
    }
  }

  private checkUrl(url: string): void {
    if (!/^https?:\/\/[^\s/]+(?:\/[^\s]*)?$/i.test(url.trim())) throw new Error('请输入完整的 HTTP 或 HTTPS 订阅地址');
  }

  private validateConfig(text: string, rules: string = '', objects: string = '', merges: string = ''): void {
    if (utf8Bytes(text).byteLength > 8 * 1024 * 1024) throw new Error('配置超过 8 MB');
    try {
      parseRuleEditsText(rules); parseObjectEditsText(objects);
      if (rules || objects || merges) this.validator.ruleEditor(text, rules, false, objects, merges);
      else this.validator.validate(text);
    } catch (error) {
      throw new Error(`配置校验失败：${(error as Error).message}`);
    }
  }

  private validName(name: string): string {
    const value: string = name.trim();
    if (value.length === 0 || value.length > 100) throw new Error('配置名称应为 1 至 100 个字符');
    return value;
  }

  private profilePath(profile: ClashProfile): string {
    if (profile.fileName.indexOf('/') >= 0 || profile.fileName.indexOf('\\') >= 0 || profile.fileName.startsWith('.')) {
      throw new Error('配置文件路径无效');
    }
    return `${this.profileDir}/${profile.fileName}`;
  }

  private makeProfile(id: string, fileName: string, text: string, metadata: ProfileMetadata): ClashProfile {
    return { id, name: metadata.name, fileName, path: `${this.profileDir}/${fileName}`,
      format: text.trim().startsWith('{') ? 'JSON' : 'YAML', size: utf8Bytes(text).byteLength,
      updatedAt: this.formatTime(new Date(metadata.updatedAt)), sourceUrl: metadata.sourceUrl,
      updateInterval: metadata.updateInterval, pinned: metadata.pinned };
  }

  private readMetadata(id: string, fileName: string): ProfileMetadata {
    const path: string = `${this.profileDir}/${id}.meta.json`;
    if (this.exists(path)) {
      const parsed: ProfileMetadata = JSON.parse(fileIo.readTextSync(path)) as ProfileMetadata;
      return { name: parsed.name || fileName, sourceUrl: parsed.sourceUrl || '',
        updateInterval: parsed.updateInterval || 0, updatedAt: parsed.updatedAt || Number(id.split('-')[0]) || Date.now(),
        pinned: parsed.pinned === true };
    }
    return { name: fileName.replace(/\.(yaml|yml|json)$/i, ''), sourceUrl: '', updateInterval: 0,
      updatedAt: Number(id.split('-')[0]) || Date.now(), pinned: false };
  }

  private writeMetadata(id: string, metadata: ProfileMetadata): void {
    this.atomicWrite(`${this.profileDir}/${id}.meta.json`, JSON.stringify(metadata));
  }

  private exists(path: string): boolean {
    try { return fileIo.accessSync(path); } catch (_) { return false; }
  }

  private ensureDirectory(): void {
    if (!this.exists(this.profileDir)) fileIo.mkdirSync(this.profileDir, true);
  }

  private atomicWrite(path: string, text: string): void {
    const temporary: string = `${path}.tmp`;
    let committed: boolean = false;
    try {
      const file = fileIo.openSync(temporary, fileIo.OpenMode.CREATE | fileIo.OpenMode.READ_WRITE | fileIo.OpenMode.TRUNC);
      try { this.validator.protectFile(file.fd); this.writeFile(file.fd, text); }
      finally { fileIo.closeSync(file); }
      fileIo.renameSync(temporary, path);
      committed = true;
    } finally {
      if (!committed && this.exists(temporary)) fileIo.unlinkSync(temporary);
    }
  }

  private writeFile(fd: number, text: string): void {
    const bytes: Uint8Array = utf8Bytes(text);
    this.writeBytes(fd, bytes);
  }

  private writeBytes(fd: number, bytes: Uint8Array): void {
    let offset: number = 0;
    while (offset < bytes.length) {
      const written: number = fileIo.writeSync(fd, bytes.slice(offset, offset + 8192).buffer as ArrayBuffer);
      if (written <= 0 || written > Math.min(8192, bytes.length - offset)) throw new Error('文件未完整写入');
      offset += written;
    }
    fileIo.fsyncSync(fd);
  }

  private baseName(path: string): string {
    const parts: string[] = path.split('/');
    return parts[parts.length - 1] || 'profile.yaml';
  }

  private resolvePath(path: string): string {
    return path.startsWith('file://') ? new fileUri.FileUri(path).path : path;
  }

  private formatTime(date: Date): string {
    return `${date.getFullYear()}-${`${date.getMonth() + 1}`.padStart(2, '0')}-${`${date.getDate()}`.padStart(2, '0')} ${`${date.getHours()}`.padStart(2, '0')}:${`${date.getMinutes()}`.padStart(2, '0')}`;
  }
}
