import { utf8Bytes } from './TextCodec';

export interface ConfigMergeSettings { version: number; global: string; profile: string; globalScript?: string; profileScript?: string; profileName?: string; sequence?: string; }
export interface ScriptLog { scope: string; level: string; text: string; }
export interface ScriptPreview { error: string; content: string; logs: ScriptLog[]; }

export function mergeSettingsText(global: string, profile: string, globalScript: string = '', profileScript: string = '', profileName: string = '', sequence: string = ''): string {
  for (const text of [global, profile, globalScript, profileScript, sequence]) if (utf8Bytes(text).length > 256 * 1024) throw new Error('单份扩展超过 256 KB');
  if (sequence) return JSON.stringify({ version: 3, global, profile, globalScript, profileScript, profileName, sequence } as ConfigMergeSettings);
  if (globalScript || profileScript) return JSON.stringify({ version: 2, global, profile, globalScript, profileScript, profileName } as ConfigMergeSettings);
  return global || profile ? JSON.stringify({ version: 1, global, profile } as ConfigMergeSettings) : '';
}
