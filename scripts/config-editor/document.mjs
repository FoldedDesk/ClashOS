export function documentSeparator(text) { return /\r\n|\r|\n/.exec(text)?.[0] || '\n'; }
export function serializeDocument(doc, initialDoc, initialText) {
  return doc.eq(initialDoc) ? initialText : doc.sliceString(0,doc.length,documentSeparator(initialText));
}
// Replacing a template is an ordinary editor transaction, so a user's current
// draft, including its original line separators, remains recoverable with Undo.
export function replaceDocument(view,text,expected){
 if(!view||view.state.readOnly||view.composing||typeof text!=='string'||text.length>8*1024*1024)return false;
 if(expected!==undefined&&(typeof expected!=='string'||view.state.doc.toString()!==expected.replace(/\r\n|\r/g,'\n')))return false;
 view.dispatch({changes:{from:0,to:view.state.doc.length,insert:text},selection:{anchor:0},userEvent:'input.replace'});
 view.focus();return true;
}
