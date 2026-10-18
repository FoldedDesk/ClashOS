import { fileIo } from '@kit.CoreFileKit';
import { DesktopPreferences, desktopPreferences } from './DesktopController';
import { utf8Bytes } from './TextCodec';

export class DesktopStore {
  private path: string;
  private protect: (fd: number) => void;
  constructor(directory: string, protect: (fd: number) => void) { this.path = `${directory}/desktop.json`; this.protect = protect; }
  load(): DesktopPreferences {
    if (!fileIo.accessSync(this.path)) return { trayEnabled: true, closeToTray: true };
    if (fileIo.statSync(this.path).size > 1024) throw new Error('窗口与托盘设置文件过大');
    return desktopPreferences(JSON.parse(fileIo.readTextSync(this.path)) as DesktopPreferences);
  }
  save(value: DesktopPreferences): void {
    const next: DesktopPreferences = desktopPreferences(value);
    const temporary: string = `${this.path}.tmp`; let committed: boolean = false;
    try {
      const file = fileIo.openSync(temporary, fileIo.OpenMode.CREATE | fileIo.OpenMode.READ_WRITE | fileIo.OpenMode.TRUNC);
      try {
        this.protect(file.fd);
        const bytes: Uint8Array = utf8Bytes(JSON.stringify(next));
        let offset: number = 0;
        while (offset < bytes.length) {
          const count: number = fileIo.writeSync(file.fd, bytes.slice(offset).buffer as ArrayBuffer);
          if (count <= 0 || count > bytes.length - offset) throw new Error('窗口与托盘设置未完整写入');
          offset += count;
        }
        fileIo.fsyncSync(file.fd);
      } finally { fileIo.closeSync(file); }
      fileIo.renameSync(temporary, this.path); committed = true;
    } finally { if (!committed && fileIo.accessSync(temporary)) fileIo.unlinkSync(temporary); }
  }
}
