import { fileIo } from '@kit.CoreFileKit';
import { utf8Bytes } from './TextCodec';

export interface ControllerAccessSnapshot { secret: string; revision?: string; error: string; }

export function validateControllerSecret(value: string): string {
  if (value.length > 256 || /[^\x21-\x7E]/.test(value)) throw new Error('密钥需为不含空格的 ASCII 字符，最多 256 字符；留空可关闭认证');
  return value;
}

export class ControllerAccessStore {
  private path: string;
  private protect: (fd: number) => void;
  constructor(filesDir: string, protect: (fd: number) => void) {
    this.path = `${filesDir}/controller-access.json`; this.protect = protect;
  }
  private raw(): string | undefined {
    if (!fileIo.accessSync(this.path)) return undefined;
    if (fileIo.statSync(this.path).size > 4096) throw new Error('控制器认证设置文件过大');
    return fileIo.readTextSync(this.path);
  }
  snapshot(): ControllerAccessSnapshot {
    const revision: string | undefined = this.raw();
    if (revision === undefined) return { secret: '', error: '' };
    try {
      const value = JSON.parse(revision) as Record<string, string | number>;
      if (!value || value.version !== 1 || typeof value.secret !== 'string') throw new Error('invalid');
      return { secret: validateControllerSecret(value.secret as string), revision, error: '' };
    } catch (_) { return { secret: '', revision, error: '认证设置已损坏；保存新密钥可修复，留空保存会关闭认证' }; }
  }
  credential(): string {
    const value: ControllerAccessSnapshot = this.snapshot();
    if (value.error) throw new Error('控制器认证设置无效，请在内置控制器认证中修复');
    return value.secret;
  }
  private write(text: string | undefined): void {
    if (text === undefined) { if (fileIo.accessSync(this.path)) fileIo.unlinkSync(this.path); return; }
    const temporary: string = `${this.path}.tmp`; let committed: boolean = false;
    try {
      const file = fileIo.openSync(temporary, fileIo.OpenMode.CREATE | fileIo.OpenMode.READ_WRITE | fileIo.OpenMode.TRUNC);
      try {
        this.protect(file.fd);
        const bytes: Uint8Array = utf8Bytes(text); let offset: number = 0;
        while (offset < bytes.length) {
          const count: number = fileIo.writeSync(file.fd, bytes.slice(offset).buffer as ArrayBuffer);
          if (!Number.isInteger(count) || count <= 0 || count > bytes.length - offset) throw new Error('认证设置未完整写入');
          offset += count;
        }
        fileIo.fsyncSync(file.fd);
      } finally { fileIo.closeSync(file); }
      fileIo.renameSync(temporary, this.path); committed = true;
    } finally { if (!committed && fileIo.accessSync(temporary)) fileIo.unlinkSync(temporary); }
  }
  replace(previous: ControllerAccessSnapshot, secret: string): ControllerAccessSnapshot {
    validateControllerSecret(secret);
    if (this.raw() !== previous.revision) throw new Error('控制器认证设置已变化，请重新打开设置');
    const revision: string = JSON.stringify({ version: 1, secret }); this.write(revision);
    return { secret, revision, error: '' };
  }
  rollback(expected: ControllerAccessSnapshot, previous: ControllerAccessSnapshot): void {
    if (this.raw() !== expected.revision) throw new Error('认证设置已被其他操作修改，无法撤回');
    this.write(previous.revision);
  }
}
