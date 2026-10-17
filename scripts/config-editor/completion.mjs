import {ensureSyntaxTree,syntaxTree} from '@codemirror/language';
import {Transaction} from '@codemirror/state';

import {fieldsFor,valuesFor} from './schema.mjs';
import {referenceCompletions,currentNodeType} from './references.mjs';
export {clashRootFields} from './schema.mjs';
function unquote(text) {
  try { if(text.startsWith('"'))return JSON.parse(text); } catch (_) {}
  return text.startsWith("'")&&text.endsWith("'")?text.slice(1,-1).replace(/''/g,"'"):text;
}
function pairKey(node, doc) {
  const key = node.getChild('Key') || node.getChild('PropertyName');
  return key ? unquote(doc.sliceString(key.from,key.to)) : '';
}

export function completionContext(state, pos, language) {
  const doc=state.doc,line=doc.lineAt(pos),before=doc.sliceString(line.from,pos);
  const tree=ensureSyntaxTree(state,pos,25)||syntaxTree(state);
  const probe=pos-(/[ \t]*$/.exec(before)[0].length);
  let node=tree.resolveInner(probe,-1);
  if(/Comment|BlockLiteral|BlockFolded/.test(node.name))return null;
  const path=[];let pair=null,keyNode=null;
  for(let n=node;n;n=n.parent)if(n.name==='Pair'||n.name==='Property'){
    if(!pair){pair=n;keyNode=n.getChild('Key')||n.getChild('PropertyName');}
    path.unshift(pairKey(n,doc));
  }
  const plain=/^(\s*)(?:-\s+)?([\w-]*)$/.exec(before);
  // A new indented YAML line is not attached to a Pair yet. Respect indentation
  // instead of accidentally inheriting the previous completed property's key.
  if(language==='yaml'&&plain){
    const indent=plain[1].replace(/\t/g,'  ').length+(before.trimStart().startsWith('- ')?2:0),stack=[];
    for(let i=1;i<line.number;i++){
      const text=doc.line(i).text;
      if(/^(?:---|\.\.\.)(?:\s|$)/.test(text)){stack.length=0;continue;}
      const m=/^(\s*)(?:-\s+)?("(?:[^"\\]|\\.)*"|'(?:[^']|'')*'|[^:#[\]{},]+?)\s*:\s*(.*)$/.exec(text);
      if(!m)continue;
      const depth=m[1].replace(/\t/g,'  ').length+(text.trimStart().startsWith('- ')?2:0);
      while(stack.length&&stack.at(-1).depth>=depth)stack.pop();
      if(!m[3]||/^[>|]/.test(m[3]))stack.push({depth,key:unquote(m[2].trim()),scalar:/^[>|]/.test(m[3])});
    }
    while(stack.length&&stack.at(-1).depth>=indent)stack.pop();
    if(stack.some(x=>x.scalar))return null;
    return {path:stack.map(x=>x.key),isKey:true,from:pos-plain[2].length,to:pos,prefix:plain[2],indent,language};
  }
  let isKey=!!keyNode&&pos>=keyNode.from&&pos<=keyNode.to;
  let container=node;while(container&&!['Object','Array'].includes(container.name))container=container.parent;
  if(language==='json'&&!isKey&&container?.name==='Object'&&/[{,]\s*"?[\w-]*$/.test(before)&&!['String','Number','True','False','Null'].includes(node.name))isKey=true;
  let from=pos,to=pos;
  const match=/[\w-]*$/.exec(before);if(match)from=pos-match[0].length;
  if(isKey&&keyNode&&pos>=keyNode.from&&pos<=keyNode.to){from=keyNode.from;to=keyNode.to;path.pop();}
  else if(isKey&&language==='json'){
    if(doc.sliceString(from-1,from)==='"')from--;
    if(pair&&keyNode&&pos>keyNode.to)path.pop();
  } else if(pair&&keyNode&&pos>=keyNode.to){
    const colon=doc.sliceString(keyNode.to,pos).indexOf(':');
    if(colon<0)return null;
    if(node.name==='String'||node.name==='QuotedLiteral'){from=node.from;to=node.to;}
  } else if(!isKey) return null;
  const prefix=doc.sliceString(from,pos).replace(/^["']/,'');
  return {path,isKey,from,to:Math.max(to,pos),prefix,indent:(/^\s*/.exec(before)[0]).length,language};
}

export function completionEdit(doc,info,option) {
  const remaining=doc.sliceString(info.to,Math.min(doc.length,info.to+20));
  let text;
  if(info.isKey){
    const key=info.language==='json'?JSON.stringify(option.label):option.label;
    text=key+(/^\s*:/.test(remaining)?'':': '+(info.language==='json'?JSON.stringify(option.value):typeof option.value==='string'?JSON.stringify(option.value):JSON.stringify(option.value)));
  }else text=info.language==='json'||option.reference?JSON.stringify(option.value):typeof option.value==='string'?option.value:String(option.value);
  // Replace an existing quoted scalar as a whole, preserving quotes in YAML too.
  if(!info.isKey&&info.language==='yaml'&&/^["']/.test(doc.sliceString(info.from,info.from+1)))text=JSON.stringify(option.value);
  const valueAt=info.isKey?text.indexOf(': ')+2:0;
  const selectValue=info.isKey&&valueAt>1;
  return {from:info.from,to:info.to,insert:text,anchor:info.from+(selectValue?valueAt:text.length),head:info.from+text.length};
}
export function clashCompletions(language) {
  const complete=context=>{
    const base=completionContext(context.state,context.pos,language);
    if(!base)return null;
    const references=referenceCompletions(context.state,context.pos,language,base),info=references||base;
    if(!context.explicit&&!info.prefix)return null;
    const candidates=references?references.candidates:info.isKey?fieldsFor(info.path):valuesFor(info.path,currentNodeType(context.state,context.pos)).map(value=>({label:String(value),value,type:typeof value==='boolean'?'keyword':'enum',detail:'Clash 参数值'}));
    const options=candidates.filter(x=>x.label.toLowerCase().startsWith(info.prefix.toLowerCase())).map(option=>({...option,apply:(view)=>{
      if(view.state.readOnly||view.composing||!view.state.doc.eq(context.state.doc))return;
      const edit=completionEdit(view.state.doc,info,option);
      view.dispatch({changes:{from:edit.from,to:edit.to,insert:edit.insert},selection:{anchor:edit.anchor,head:edit.head},annotations:Transaction.userEvent.of('input.complete')});view.focus();
    }}));
    return options.length?{from:info.from,to:info.to,options,filter:false}:null;
  };
  return context=>{
    if(context.aborted)return null;
    if(ensureSyntaxTree(context.state,context.state.doc.length,10))return complete(context);
    // Large profiles parse in short tasks so typing and cancellation stay
    // responsive. A captured document never borrows names from a newer draft.
    let canceled=false;context.addEventListener('abort',()=>{canceled=true;},{onDocChange:true});
    const deadline=Date.now()+600;
    return new Promise(resolve=>{
      const next=()=>{
        if(canceled||context.aborted||Date.now()>deadline){resolve(null);return;}
        if(ensureSyntaxTree(context.state,context.state.doc.length,10)){resolve(complete(context));return;}
        setTimeout(next,0);
      };
      setTimeout(next,0);
    });
  };
}
