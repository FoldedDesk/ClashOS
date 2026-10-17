import { EditorObjectView } from './ObjectEditsTypes';

export interface NodeLinkImport {
  error: string;
  nodes: EditorObjectView[];
  content: string;
}

export function emptyNodeLinkImport(): NodeLinkImport {
  return { error: '', nodes: [], content: '' };
}
