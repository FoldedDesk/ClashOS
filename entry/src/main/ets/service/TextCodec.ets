import { util } from '@kit.ArkTS';

// Some Harmony runtimes return undefined for encodeInto('') despite the SDK type.
export function utf8Bytes(text: string): Uint8Array {
  return text.length === 0 ? new Uint8Array(0) : new util.TextEncoder().encodeInto(text);
}
