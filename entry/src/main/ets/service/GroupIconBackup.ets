import { util } from '@kit.ArkTS';
import { utf8Bytes } from './TextCodec';
import { GroupIconEntry, localIconName, parseGroupIcons } from './GroupIconTypes';

export interface GroupIconAsset { name: string; data: string; }
export interface GroupIconBackup { version: number; entries: GroupIconEntry[]; assets: GroupIconAsset[]; }
export const GROUP_ICON_BACKUP_LIMIT: number = 16 * 1024 * 1024;

export function assertIconPng(bytes: Uint8Array): void {
  const integer = (offset: number): number => bytes[offset] * 16777216 + bytes[offset + 1] * 65536 + bytes[offset + 2] * 256 + bytes[offset + 3];
  if (bytes.length < 33 || bytes.length > 512 * 1024 || bytes.slice(0, 8).join(',') !== '137,80,78,71,13,10,26,10' ||
    integer(8) !== 13 || bytes.slice(12, 16).join(',') !== '73,72,68,82' ||
    integer(16) < 1 || integer(16) > 256 || integer(20) < 1 || integer(20) > 256) throw new Error('图标必须是 256 × 256 以内、512 KB 以内的 PNG');
}

export function decodeIconAsset(data: string): Uint8Array {
  if (typeof data !== 'string' || !data || data.length % 4 !== 0 || data.length > Math.ceil(512 * 1024 / 3) * 4 ||
    !/^[A-Za-z0-9+/]*={0,2}$/.test(data)) throw new Error('备份中的图标图片编码无效');
  const base64 = new util.Base64Helper();
  const bytes: Uint8Array = base64.decodeSync(data);
  assertIconPng(bytes);
  if (base64.encodeToStringSync(bytes) !== data) throw new Error('备份中的图标图片编码无效');
  return bytes;
}

export function validateGroupIconBackup(value: GroupIconBackup): GroupIconBackup {
  if (!value || value.version !== 1 || !Array.isArray(value.entries) || value.entries.length > 256 || !Array.isArray(value.assets) || value.assets.length > 256)
    throw new Error('备份中的代理组图标格式无效');
  const entries: GroupIconEntry[] = parseGroupIcons(JSON.stringify({ version: 1, entries: value.entries }));
  const expected: Set<string> = new Set<string>();
  entries.forEach((entry: GroupIconEntry) => { const name: string = localIconName(entry.source); if (name) expected.add(name); });
  const seen: Set<string> = new Set<string>(); let bytes: number = utf8Bytes(JSON.stringify(entries)).length;
  const assets: GroupIconAsset[] = value.assets.map((asset: GroupIconAsset): GroupIconAsset => {
    if (!asset || typeof asset.name !== 'string' || !localIconName(`local:${asset.name}`) || !expected.has(asset.name) || seen.has(asset.name) || typeof asset.data !== 'string')
      throw new Error('备份中的图标图片引用无效');
    bytes += asset.data.length;
    if (bytes > GROUP_ICON_BACKUP_LIMIT) throw new Error('代理组图标备份超过 16 MB');
    decodeIconAsset(asset.data); seen.add(asset.name); return { name: asset.name, data: asset.data };
  });
  if (seen.size !== expected.size) throw new Error('备份缺少代理组图标图片');
  return { version: 1, entries, assets };
}
