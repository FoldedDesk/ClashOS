import { fileIo } from '@kit.CoreFileKit';
import { AppearanceSettings, DEFAULT_ACCENT, appearanceSettings } from '../theme/AppearanceTypes';
import { utf8Bytes } from './TextCodec';

export function loadAppearance(filesDir: string): AppearanceSettings {
  const path: string = `${filesDir}/appearance.json`;
  if (!fileIo.accessSync(path)) return { mode: 'system', accent: DEFAULT_ACCENT };
  if (fileIo.statSync(path).size > 4096) throw new Error('外观设置文件过大');
  const value: AppearanceSettings = JSON.parse(fileIo.readTextSync(path)) as AppearanceSettings;
  if (!value || typeof value.mode !== 'string' || typeof value.accent !== 'string') throw new Error('外观设置格式无效');
  return appearanceSettings(value.mode, value.accent);
}

export class AppearanceStore {
  private path: string;
  private filesDir: string;
  private protect: (fd: number) => void;
  constructor(filesDir: string, protect: (fd: number) => void) { this.filesDir = filesDir; this.path = `${filesDir}/appearance.json`; this.protect = protect; }
  load(): AppearanceSettings {
    return loadAppearance(this.filesDir);
  }
  save(settings: AppearanceSettings): void {
    const value: AppearanceSettings = appearanceSettings(settings.mode, settings.accent);
    const temporary: string = `${this.path}.tmp`; let committed: boolean = false;
    try {
      const file = fileIo.openSync(temporary, fileIo.OpenMode.CREATE | fileIo.OpenMode.READ_WRITE | fileIo.OpenMode.TRUNC);
      try {
        this.protect(file.fd);
        const bytes: Uint8Array = utf8Bytes(JSON.stringify(value)); let offset: number = 0;
        while (offset < bytes.length) {
          const count: number = fileIo.writeSync(file.fd, bytes.slice(offset).buffer as ArrayBuffer);
          if (count <= 0 || count > bytes.length - offset) throw new Error('外观设置未完整写入');
          offset += count;
        }
        fileIo.fsyncSync(file.fd);
      } finally { fileIo.closeSync(file); }
      fileIo.renameSync(temporary, this.path); committed = true;
    } finally { if (!committed && fileIo.accessSync(temporary)) fileIo.unlinkSync(temporary); }
  }
}
