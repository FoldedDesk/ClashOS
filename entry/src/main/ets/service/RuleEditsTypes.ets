import { utf8Bytes } from './TextCodec';
import { ScriptLog } from './ConfigMergeTypes';

export interface RuleEdits {
  version: number;
  prepend: string[];
  append: string[];
  remove: string[];
}

export interface RuleEditorSnapshot {
  scriptLogs?: ScriptLog[];
  error: string;
  rules: string[];
  effective: string[];
  policies: string[];
  providers: string[];
  content?: string;
}

export function emptyRuleEdits(): RuleEdits { return { version: 1, prepend: [], append: [], remove: [] }; }

export function parseRuleEditsText(text: string): RuleEdits {
  if (!text) return emptyRuleEdits();
  if (utf8Bytes(text).length > 256 * 1024) throw new Error('自定义规则超过 256 KB');
  let edits: RuleEdits;
  try { edits = JSON.parse(text) as RuleEdits; } catch (_) { throw new Error('自定义规则文件不是有效 JSON'); }
  if (edits === null || typeof edits !== 'object' || edits.version !== 1 || Object.keys(edits).length !== 4 ||
    !Array.isArray(edits.prepend) || !Array.isArray(edits.append) || !Array.isArray(edits.remove) ||
    edits.prepend.length + edits.append.length > 1000 || edits.remove.length > 2000) throw new Error('自定义规则格式或数量无效');
  [edits.prepend, edits.append, edits.remove].forEach((rules: string[]) => {
    if (rules.some((rule: string) => typeof rule !== 'string' || !rule.trim() || utf8Bytes(rule).length > 4096 || /[\r\n\u0000]/.test(rule))) {
      throw new Error('每条规则应为不超过 4096 字节的单行文本');
    }
  });
  return edits;
}
