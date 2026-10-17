import { common } from '@kit.AbilityKit';
import { fileIo } from '@kit.CoreFileKit';
import { util } from '@kit.ArkTS';
import { ClashNativeCore } from './ClashNativeCore';
import { BACKUP_LIMIT, BACKUP_FILE_PATTERN, BackupEntry, WebDavSettings, BackupCreateOptions } from './BackupTypes';
import { ProfileStore } from './ProfileStore';
import { utf8Bytes } from './TextCodec';
import { BackupArchiveCodec } from './BackupArchiveCodec';

export class BackupStore {
  private directory: string;
  private settingsPath: string;
  private protector: ClashNativeCore = new ClashNativeCore();
  private profiles: ProfileStore;

  constructor(context: common.UIAbilityContext, profiles: ProfileStore) {
    this.directory = `${context.filesDir}/backups`;
    this.settingsPath = `${context.filesDir}/webdav-settings.json`;
    this.profiles = profiles;
    if (!fileIo.accessSync(this.directory)) fileIo.mkdirSync(this.directory, true);
  }

  loadSettings(): WebDavSettings {
    if (!fileIo.accessSync(this.settingsPath)) return { url: '', username: '', password: '' };
    try {
      if (fileIo.statSync(this.settingsPath).size > 16384) throw new Error('oversized');
      const data: WebDavSettings = JSON.parse(fileIo.readTextSync(this.settingsPath)) as WebDavSettings;
      if (data === null || typeof data.url !== 'string' || typeof data.username !== 'string' || typeof data.password !== 'string') throw new Error('invalid');
      return data;
    } catch (_) { throw new Error('无法读取 WebDAV 设置，请重新填写后保存'); }
  }

  saveSettings(settings: WebDavSettings): void {
    if (settings.url.length > 8192 || settings.username.length > 1000 || settings.password.length > 4000) throw new Error('WebDAV 设置内容过长');
    this.atomicWrite(this.settingsPath, JSON.stringify(settings));
  }

  forgetSettings(): void {
    if (fileIo.accessSync(this.settingsPath)) fileIo.unlinkSync(this.settingsPath);
  }

  list(): BackupEntry[] {
    const entries: BackupEntry[] = [];
    fileIo.listFileSync(this.directory).forEach((name: string) => {
      if (!BACKUP_FILE_PATTERN.test(name)) return;
      const bytes: number = fileIo.statSync(`${this.directory}/${name}`).size;
      entries.push({ name, bytes, updatedAt: new Date(Number(name.split('-')[2])).toISOString(), remote: false, etag: '' });
    });
    return entries.sort((a: BackupEntry, b: BackupEntry) => b.name.localeCompare(a.name));
  }

  create(options?: BackupCreateOptions): BackupEntry {
    return this.importText(this.profiles.createBackup(options));
  }

  importText(text: string): BackupEntry {
    const preview = this.profiles.inspectBackup(text);
    const name: string = `clashos-backup-${Date.now()}-${util.generateRandomUUID().replace(/-/g, '').toLowerCase()}.json`;
    this.atomicWrite(`${this.directory}/${name}`, text);
    return { name, bytes: utf8Bytes(text).length, updatedAt: preview.archive.createdAt, remote: false, etag: '' };
  }

  read(entry: BackupEntry): string {
    if (entry.remote || !BACKUP_FILE_PATTERN.test(entry.name)) throw new Error('本地备份名称无效');
    const path: string = `${this.directory}/${entry.name}`;
    if (fileIo.statSync(path).size > BACKUP_LIMIT) throw new Error('备份超过 32 MB');
    const text: string = fileIo.readTextSync(path);
    if (utf8Bytes(text).length > BACKUP_LIMIT) throw new Error('备份超过 32 MB');
    return text;
  }

  remove(entry: BackupEntry): void {
    if (entry.remote || !BACKUP_FILE_PATTERN.test(entry.name)) throw new Error('本地备份名称无效');
    fileIo.unlinkSync(`${this.directory}/${entry.name}`);
  }

  async export(entry: BackupEntry): Promise<boolean> {
    return this.profiles.exportText(entry.name, this.read(entry));
  }
  async exportZip(entry: BackupEntry): Promise<boolean> {
    const archive = this.profiles.inspectBackup(this.read(entry)).archive;
    return this.profiles.exportBytes(entry.name.replace(/\.json$/, '.zip'), new BackupArchiveCodec(this.protector).encode(archive));
  }

  private atomicWrite(path: string, text: string): void {
    const bytes: Uint8Array = utf8Bytes(text);
    if (bytes.length > BACKUP_LIMIT) throw new Error('备份超过 32 MB');
    const temporary: string = `${path}.tmp`;
    try {
      const file = fileIo.openSync(temporary, fileIo.OpenMode.CREATE | fileIo.OpenMode.READ_WRITE | fileIo.OpenMode.TRUNC);
      try {
        this.protector.protectFile(file.fd);
        let offset: number = 0;
        while (offset < bytes.length) {
          const count: number = fileIo.writeSync(file.fd, bytes.slice(offset, offset + 8192).buffer as ArrayBuffer);
          if (count <= 0 || count > Math.min(8192, bytes.length - offset)) throw new Error('备份未完整写入');
          offset += count;
        }
        fileIo.fsyncSync(file.fd);
      } finally { fileIo.closeSync(file); }
      fileIo.renameSync(temporary, path);
    } finally {
      if (fileIo.accessSync(temporary)) fileIo.unlinkSync(temporary);
    }
  }
}
