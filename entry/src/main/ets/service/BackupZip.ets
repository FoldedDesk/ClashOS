import { util } from '@kit.ArkTS';
import { BACKUP_LIMIT } from './BackupTypes';
import { utf8Bytes } from './TextCodec';

export interface ZipEntry { name: string; bytes: Uint8Array; }
export interface ZipInflater { backupInflate: (bytes: Uint8Array, expected: number) => Uint8Array; }

export function zipText(bytes: Uint8Array): string { return util.TextDecoder.create('utf-8', { fatal: true, ignoreBOM: true }).decodeToString(bytes); }
const crcTable: number[] = [];
for (let i: number = 0; i < 256; i++) {
  let value: number = i;
  for (let bit: number = 0; bit < 8; bit++) value = (value >>> 1) ^ ((value & 1) ? 0xedb88320 : 0);
  crcTable.push(value >>> 0);
}
export function zipCrc(bytes: Uint8Array): number {
  let value: number = 0xffffffff;
  for (let i: number = 0; i < bytes.length; i++) value = (value >>> 8) ^ crcTable[(value ^ bytes[i]) & 255];
  return (value ^ 0xffffffff) >>> 0;
}
function checkName(name: string): void {
  if (!name || name.length > 1024 || /[\\\u0000-\u001f\u007f:]/.test(name) || name.startsWith('/') ||
    name.split('/').some((part: string, index: number, parts: string[]) => part === '.' || part === '..' || (!part && index < parts.length - 1)))
    throw new Error('ZIP 包含无效路径');
}

// Read only in memory: no archive-controlled paths are extracted to disk.
export function readZip(bytes: Uint8Array, inflater: ZipInflater): ZipEntry[] {
  if (bytes.length < 22 || bytes.length > BACKUP_LIMIT) throw new Error('ZIP 无效或超过 32 MB');
  const view: DataView = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const u16 = (at: number): number => view.getUint16(at, true);
  const u32 = (at: number): number => view.getUint32(at, true);
  let end: number = bytes.length - 22;
  while (end >= Math.max(0, bytes.length - 65557) && (u32(end) !== 0x06054b50 || end + 22 + u16(end + 20) !== bytes.length)) end--;
  if (end < Math.max(0, bytes.length - 65557) || u16(end + 4) || u16(end + 6) || u16(end + 8) !== u16(end + 10)) throw new Error('ZIP 目录无效或使用分卷');
  const count: number = u16(end + 10), directorySize: number = u32(end + 12), start: number = u32(end + 16);
  if (count > 4096 || start + directorySize !== end) throw new Error('ZIP 目录或文件数量无效，不支持 ZIP64');
  let cursor: number = start, total: number = 0;
  const entries: ZipEntry[] = [], names: Set<string> = new Set<string>(), ranges: number[][] = [];
  for (let i: number = 0; i < count; i++) {
    if (cursor + 46 > end || u32(cursor) !== 0x02014b50) throw new Error('ZIP 中央目录不完整');
    const flags: number = u16(cursor + 8), method: number = u16(cursor + 10), crc: number = u32(cursor + 16);
    const compressed: number = u32(cursor + 20), size: number = u32(cursor + 24), nameSize: number = u16(cursor + 28);
    const next: number = cursor + 46 + nameSize + u16(cursor + 30) + u16(cursor + 32), local: number = u32(cursor + 42);
    if (next > end || u16(cursor + 34) || (flags & ~0x80e) || (method !== 0 && method !== 8) || (u32(cursor + 38) >>> 16 & 0xf000) === 0xa000)
      throw new Error('ZIP 文件使用不支持的加密、压缩或链接格式');
    const nameBytes: Uint8Array = bytes.slice(cursor + 46, cursor + 46 + nameSize);
    if (!(flags & 0x800) && nameBytes.some((value: number) => value > 127)) throw new Error('ZIP 文件名必须使用 UTF-8');
    const name: string = zipText(nameBytes); checkName(name);
    if (names.has(name)) throw new Error('ZIP 包含重名文件');
    names.add(name); total += size;
    if (total > BACKUP_LIMIT || compressed > BACKUP_LIMIT || size > BACKUP_LIMIT || local + 30 > start || u32(local) !== 0x04034b50 ||
      u16(local + 6) !== flags || u16(local + 8) !== method) throw new Error('ZIP 文件头、大小或展开总量无效');
    const data: number = local + 30 + u16(local + 26) + u16(local + 28), finish: number = data + compressed;
    if (data > start || finish > start || zipText(bytes.slice(local + 30, local + 30 + u16(local + 26))) !== name ||
      (!(flags & 8) && (u32(local + 14) !== crc || u32(local + 18) !== compressed || u32(local + 22) !== size))) throw new Error('ZIP 本地目录与中央目录不一致');
    let extent: number = finish;
    if (flags & 8) {
      const signed: boolean = finish + 16 <= start && u32(finish) === 0x08074b50 && u32(finish + 4) === crc && u32(finish + 8) === compressed && u32(finish + 12) === size;
      const plain: boolean = finish + 12 <= start && u32(finish) === crc && u32(finish + 4) === compressed && u32(finish + 8) === size;
      if (!signed && !plain) throw new Error('ZIP 数据描述符无效');
      extent += signed ? 16 : 12;
    }
    if (ranges.some((range: number[]) => local < range[1] && extent > range[0])) throw new Error('ZIP 文件范围重叠');
    ranges.push([local, extent]);
    const payload: Uint8Array = bytes.slice(data, finish);
    const decoded: Uint8Array = method === 0 ? payload : inflater.backupInflate(payload, size);
    if (decoded.length !== size || zipCrc(decoded) !== crc || (name.endsWith('/') && size !== 0)) throw new Error('ZIP 校验失败或文件损坏');
    if (!name.endsWith('/')) entries.push({ name, bytes: decoded });
    cursor = next;
  }
  if (cursor !== end) throw new Error('ZIP 目录长度不一致');
  return entries;
}

export function writeZip(entries: ZipEntry[]): Uint8Array {
  if (entries.length > 4096) throw new Error('ZIP 文件数量过多');
  const names: Set<string> = new Set<string>();
  let size: number = 22;
  entries.forEach((entry: ZipEntry) => {
    checkName(entry.name); if (names.has(entry.name)) throw new Error('ZIP 包含重名文件'); names.add(entry.name);
    size += 76 + utf8Bytes(entry.name).length * 2 + entry.bytes.length;
  });
  if (size > BACKUP_LIMIT) throw new Error('ZIP 备份超过 32 MB');
  const output: Uint8Array = new Uint8Array(size), view: DataView = new DataView(output.buffer);
  const u16 = (at: number, value: number): void => view.setUint16(at, value, true);
  const u32 = (at: number, value: number): void => view.setUint32(at, value, true);
  const offsets: number[] = [], crcs: number[] = [];
  let cursor: number = 0;
  entries.forEach((entry: ZipEntry) => {
    const name: Uint8Array = utf8Bytes(entry.name); offsets.push(cursor); crcs.push(zipCrc(entry.bytes));
    u32(cursor, 0x04034b50); u16(cursor + 4, 20); u16(cursor + 6, 0x800); u16(cursor + 12, 0x21);
    u32(cursor + 14, crcs[crcs.length - 1]); u32(cursor + 18, entry.bytes.length); u32(cursor + 22, entry.bytes.length); u16(cursor + 26, name.length);
    output.set(name, cursor + 30); output.set(entry.bytes, cursor + 30 + name.length); cursor += 30 + name.length + entry.bytes.length;
  });
  const start: number = cursor;
  entries.forEach((entry: ZipEntry, index: number) => {
    const name: Uint8Array = utf8Bytes(entry.name);
    u32(cursor, 0x02014b50); u16(cursor + 4, 20); u16(cursor + 6, 20); u16(cursor + 8, 0x800); u16(cursor + 14, 0x21);
    u32(cursor + 16, crcs[index]); u32(cursor + 20, entry.bytes.length); u32(cursor + 24, entry.bytes.length); u16(cursor + 28, name.length); u32(cursor + 42, offsets[index]);
    output.set(name, cursor + 46); cursor += 46 + name.length;
  });
  u32(cursor, 0x06054b50); u16(cursor + 8, entries.length); u16(cursor + 10, entries.length); u32(cursor + 12, cursor - start); u32(cursor + 16, start);
  return output;
}
