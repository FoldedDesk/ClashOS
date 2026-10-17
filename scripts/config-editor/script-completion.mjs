import {syntaxTree} from '@codemirror/language';
import {snippetCompletion} from '@codemirror/autocomplete';
import {clashRootFields} from './completion.mjs';

// These are document completions, never executed script code. The native script
// runtime owns main(config, profileName), validation and console collection.
export function scriptCompletions(context) {
  const {state,pos}=context, before=state.doc.sliceString(state.doc.lineAt(pos).from,pos);
  const node=syntaxTree(state).resolveInner(pos,-1);
  if(/Comment|RegExp|Template/.test(node.name))return null;
  const bracket=/\bconfig\[(["'])([\w-]*)$/.exec(before);
  if(bracket){
    if(node.name!=='String'||node.parent?.name!=='MemberExpression'||
      state.doc.sliceString(node.parent.firstChild.from,node.parent.firstChild.to)!=='config')return null;
    const from=pos-bracket[2].length;
    const to=node.to-(state.doc.sliceString(node.to-1,node.to)===bracket[1]?1:0);
    return {from,to,options:clashRootFields.map(x=>({label:x.label,type:'property',detail:x.detail})),validFor:/^[\w-]*$/};
  }
  if(/String/.test(node.name))return null;
  const member=/\b(config|console)\.([\w$]*)$/.exec(before);
  if(member){
    const options=member[1]==='config'?clashRootFields.filter(x=>/^[\w$]+$/.test(x.label)).map(x=>({label:x.label,type:'property',detail:x.detail})):
      ['log','info','warn','error','debug'].map(label=>({label,type:'function',detail:'脚本输出'}));
    return {from:pos-member[2].length,to:node.name==='PropertyName'?node.to:pos,options,validFor:/^[\w$]*$/};
  }
  const word=context.matchBefore(/[\w$]*/);
  if(!word||(!context.explicit&&!word.text))return null;
  // Offer the entry template only at the start of a script, never inside a main
  // function where inserting another entry point would hide the existing one.
  if(state.doc.sliceString(0,word.from).trim())return null;
  return {from:word.from,options:[snippetCompletion('function main(config, profileName) {\n  ${}\n  return config;\n}',
    {label:'main',type:'function',detail:'Clash 扩展脚本入口'})],validFor:/^[\w$]*$/};
}
