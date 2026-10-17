export function documentSeparator(text) { return /\r\n|\r|\n/.exec(text)?.[0] || '\n'; }
export function serializeDocument(doc, initialDoc, initialText) {
  return doc.eq(initialDoc) ? initialText : doc.sliceString(0,doc.length,documentSeparator(initialText));
}
