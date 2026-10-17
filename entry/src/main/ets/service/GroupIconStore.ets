import { fileIo } from '@kit.CoreFileKit';
import { util } from '@kit.ArkTS';
import { utf8Bytes } from './TextCodec';
import { GroupIconEntry, GroupIconSettings, GroupIconSnapshot, groupIconName, groupIconSource, localIconName, parseGroupIcons } from './GroupIconTypes';
import { GroupIconAsset, GroupIconBackup, GROUP_ICON_BACKUP_LIMIT, assertIconPng, decodeIconAsset, validateGroupIconBackup } from './GroupIconBackup';

export class GroupIconStore {
  private path: string;
  private directory: string;
  private protect: (fd: number) => void;
  constructor(filesDir: string, protect: (fd: number) => void) {
    this.path = `${filesDir}/group-icons.json`; this.directory = `${filesDir}/group-icons`;
    this.protect = protect;
  }
  private text(): string {
    if (!fileIo.accessSync(this.path)) return '';
    if (fileIo.statSync(this.path).size > 512 * 1024) throw new Error('图标设置文件过大');
    return fileIo.readTextSync(this.path);
  }
  load(): GroupIconEntry[] { return parseGroupIcons(this.text()); }
  revision(): string { return this.text(); }
  snapshot(name: string): GroupIconSnapshot {
    groupIconName(name);
    const revision: string = this.text();
    try { return { name, source: parseGroupIcons(revision).find((entry: GroupIconEntry) => entry.name === name)?.source ?? '', revision, error: '' }; }
    catch (_) { return { name, source: '', revision, error: '现有图标设置无法读取，保存将重建图标设置' }; }
  }
  displaySource(source: string): string {
    const name: string = localIconName(source);
    return name ? `file://${this.directory}/${name}` : source;
  }
  private write(path: string, bytes: Uint8Array): void {
    const file = fileIo.openSync(path, fileIo.OpenMode.CREATE | fileIo.OpenMode.READ_WRITE | fileIo.OpenMode.TRUNC);
    try {
      this.protect(file.fd); let offset: number = 0;
      while (offset < bytes.length) {
        const count: number = fileIo.writeSync(file.fd, bytes.slice(offset).buffer as ArrayBuffer);
        if (count <= 0 || count > bytes.length - offset) throw new Error('图标设置未完整写入');
        offset += count;
      }
      fileIo.fsyncSync(file.fd);
    } finally { fileIo.closeSync(file); }
  }
  save(snapshot: GroupIconSnapshot, raw: string): GroupIconEntry[] {
    groupIconName(snapshot.name); const source: string = groupIconSource(raw);
    if (this.text() !== snapshot.revision) throw new Error('图标设置已变化，请重新打开');
    let previous: GroupIconEntry[] = [];
    if (!snapshot.error) previous = parseGroupIcons(snapshot.revision);
    const entries: GroupIconEntry[] = previous.filter((entry: GroupIconEntry) => entry.name !== snapshot.name);
    if (source) entries.push({ name: snapshot.name, source });
    return this.replace(entries, snapshot.revision);
  }
  private replace(entries: GroupIconEntry[], revision: string): GroupIconEntry[] {
    if (this.text() !== revision) throw new Error('图标设置已变化，请重新打开');
    let previous: GroupIconEntry[] = [];
    try { previous = parseGroupIcons(revision); } catch (_) {}
    const data: GroupIconSettings = { version: 1, entries };
    const encoded: string = JSON.stringify(data); parseGroupIcons(encoded);
    entries.forEach((entry: GroupIconEntry) => {
      const file: string = localIconName(entry.source);
      if (file && !fileIo.accessSync(`${this.directory}/${file}`)) throw new Error('导入的图标已不可用，请重新选择图片');
    });
    const temporary: string = `${this.path}.tmp`; let committed: boolean = false;
    try {
      this.write(temporary, utf8Bytes(encoded));
      if (this.text() !== revision) throw new Error('图标设置已变化，请重新打开');
      fileIo.renameSync(temporary, this.path); committed = true;
    }
    finally { if (!committed && fileIo.accessSync(temporary)) fileIo.unlinkSync(temporary); }
    const retained: Set<string> = new Set<string>(entries.map((entry: GroupIconEntry) => entry.source));
    previous.forEach((entry: GroupIconEntry) => { if (!retained.has(entry.source)) { retained.add(entry.source); this.releaseImage(entry.source); } });
    return entries;
  }
  stageImage(png: ArrayBuffer): string {
    const bytes: Uint8Array = new Uint8Array(png);
    assertIconPng(bytes);
    if (!fileIo.accessSync(this.directory)) fileIo.mkdirSync(this.directory);
    // Each import owns an atomically allocated directory.
    const folder: string = fileIo.mkdtempSync(`${this.directory}/icon-XXXXXX`);
    const path: string = `${folder}/icon.png`;
    try { this.write(path, bytes); }
    catch (error) {
      try { if (fileIo.accessSync(path)) fileIo.unlinkSync(path); fileIo.rmdirSync(folder); } catch (_) {}
      throw new Error((error as Error).message || '图片未能保存');
    }
    return `local:${folder.slice(this.directory.length + 1)}/icon.png`;
  }
  exportBackup(): GroupIconBackup {
    const entries: GroupIconEntry[] = this.load(), assets: GroupIconAsset[] = [], seen: Set<string> = new Set<string>();
    const base64 = new util.Base64Helper(); let total: number = utf8Bytes(JSON.stringify(entries)).length;
    entries.forEach((entry: GroupIconEntry) => {
      const name: string = localIconName(entry.source); if (!name || seen.has(name)) return;
      const file = fileIo.openSync(`${this.directory}/${name}`, fileIo.OpenMode.READ_ONLY);
      let bytes: Uint8Array;
      try {
        const size: number = fileIo.statSync(file.fd).size;
        if (size < 33 || size > 512 * 1024) throw new Error('本地图标图片大小无效');
        bytes = new Uint8Array(size); let used: number = 0;
        while (used < size) {
          const buffer: ArrayBuffer = new ArrayBuffer(Math.min(size - used, 65536)), count: number = fileIo.readSync(file.fd, buffer);
          if (count <= 0 || count > buffer.byteLength) throw new Error('本地图标未能完整读取');
          bytes.set(new Uint8Array(buffer, 0, count), used); used += count;
        }
      } finally { fileIo.closeSync(file); }
      assertIconPng(bytes);
      const data: string = base64.encodeToStringSync(bytes); total += data.length;
      if (total > GROUP_ICON_BACKUP_LIMIT) throw new Error('代理组图标备份超过 16 MB');
      assets.push({ name, data }); seen.add(name);
    });
    return { version: 1, entries, assets };
  }
  restoreBackup(value: GroupIconBackup, revision: string): GroupIconEntry[] {
    const backup: GroupIconBackup = validateGroupIconBackup(value);
    if (this.text() !== revision) throw new Error('图标设置已变化，请重新预览备份');
    const staged: GroupIconEntry[] = []; let committed: boolean = false;
    try {
      backup.assets.forEach((asset: GroupIconAsset) => {
        staged.push({ name: asset.name, source: this.stageImage(decodeIconAsset(asset.data).slice().buffer as ArrayBuffer) });
      });
      const entries: GroupIconEntry[] = backup.entries.map((entry: GroupIconEntry): GroupIconEntry => ({ name: entry.name,
        source: localIconName(entry.source) ? staged.find((item: GroupIconEntry) => item.name === localIconName(entry.source))!.source : entry.source }));
      const saved: GroupIconEntry[] = this.replace(entries, revision); committed = true; return saved;
    } finally { if (!committed) staged.forEach((entry: GroupIconEntry) => this.releaseImage(entry.source)); }
  }
  releaseImage(source: string): void {
    const name: string = localIconName(source); if (!name) return;
    // Never let optional cleanup invalidate a committed display choice.
    try {
      if (this.load().some((entry: GroupIconEntry) => entry.source === source)) return;
      const path: string = `${this.directory}/${name}`;
      if (fileIo.accessSync(path)) fileIo.unlinkSync(path);
      fileIo.rmdirSync(path.slice(0, path.lastIndexOf('/')));
    } catch (_) {}
  }
}
