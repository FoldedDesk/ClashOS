import { utf8Bytes } from './TextCodec';

export interface ObjectEditItem { name: string; content: string; }
export interface ObjectSequenceEdits { prepend: ObjectEditItem[]; append: ObjectEditItem[]; remove: string[]; }
export interface ObjectEdits { version: number; proxies: ObjectSequenceEdits; groups: ObjectSequenceEdits; }
export interface EditorObjectView extends ObjectEditItem { type: string; server: string; port: string; }
export interface ObjectSnapshotSection { original: EditorObjectView[]; prepend: EditorObjectView[]; append: EditorObjectView[]; }
export interface ObjectEditorSnapshot { error: string; proxies: ObjectSnapshotSection; groups: ObjectSnapshotSection; choices: string[]; providers: string[]; }

export interface ProxyNodeForm {
  name: string; type: string; server: string; port: string; password: string; uuid: string; cipher: string; alterId: string;
  tls: boolean; udp: boolean; skipCertVerify: boolean; serverName: string; network: string; wsPath: string; wsHost: string;
}
export interface ProxyGroupForm {
  name: string; type: string; members: string[]; providers: string[]; url: string; interval: string; timeout: string; tolerance: string;
  expectedStatus: string; strategy: string; filter: string; excludeFilter: string; defaultSelected: string;
  lazy: boolean; disableUdp: boolean; includeAllProxies: boolean; includeAllProviders: boolean;
}
export interface ProxyNodeDraft { error: string; item: EditorObjectView; form: ProxyNodeForm; }
export interface ProxyGroupDraft { error: string; item: EditorObjectView; form: ProxyGroupForm; }

export function defaultProxyNodeForm(): ProxyNodeForm {
  return { name: '', type: 'ss', server: '', port: '443', password: '', uuid: '', cipher: 'aes-128-gcm', alterId: '0', tls: false, udp: true,
    skipCertVerify: false, serverName: '', network: 'tcp', wsPath: '/', wsHost: '' };
}
export function defaultProxyGroupForm(): ProxyGroupForm {
  return { name: '', type: 'select', members: ['DIRECT'], providers: [], url: 'https://www.gstatic.com/generate_204', interval: '300', timeout: '5000', tolerance: '50',
    expectedStatus: '*', strategy: 'consistent-hashing', filter: '', excludeFilter: '', defaultSelected: '', lazy: true, disableUdp: false, includeAllProxies: false, includeAllProviders: false };
}

export function emptyObjectSequence(): ObjectSequenceEdits { return { prepend: [], append: [], remove: [] }; }
export function emptyObjectEdits(): ObjectEdits { return { version: 1, proxies: emptyObjectSequence(), groups: emptyObjectSequence() }; }
export function emptyObjectSnapshot(): ObjectEditorSnapshot {
  return { error: '', proxies: { original: [], prepend: [], append: [] }, groups: { original: [], prepend: [], append: [] }, choices: ['DIRECT', 'REJECT'], providers: [] };
}
export function validEditorObjectName(name: string): boolean {
  return typeof name === 'string' && name.length > 0 && utf8Bytes(name).length <= 1024 && !/[\u0000-\u001f\u007f]/.test(name);
}
export function parseObjectEditsText(text: string): ObjectEdits {
  if (!text) return emptyObjectEdits();
  if (utf8Bytes(text).length > 2 * 1024 * 1024) throw new Error('节点和代理组修改超过 2 MB');
  let edits: ObjectEdits;
  try { edits = JSON.parse(text) as ObjectEdits; } catch (_) { throw new Error('节点和代理组修改不是有效 JSON'); }
  if (edits === null || typeof edits !== 'object' || edits.version !== 1 || Object.keys(edits).length !== 3) throw new Error('节点和代理组修改格式无效');
  [edits.proxies, edits.groups].forEach((section: ObjectSequenceEdits) => {
    if (section === null || typeof section !== 'object' || Object.keys(section).length !== 3 || !Array.isArray(section.prepend) || !Array.isArray(section.append) ||
      !Array.isArray(section.remove) || section.prepend.length + section.append.length > 1000 || section.remove.length > 2000 ||
      section.remove.some((name: string) => !validEditorObjectName(name))) throw new Error('节点或代理组修改的格式、名称或数量无效');
    [...section.prepend, ...section.append].forEach((item: ObjectEditItem) => {
      if (item === null || typeof item !== 'object' || Object.keys(item).length !== 2 || !validEditorObjectName(item.name) || item.name === 'DIRECT' || item.name === 'REJECT' ||
        typeof item.content !== 'string' || !item.content.trim() || utf8Bytes(item.content).length > 64 * 1024) throw new Error('单个节点或代理组的名称、配置或大小无效');
    });
  });
  return edits;
}
