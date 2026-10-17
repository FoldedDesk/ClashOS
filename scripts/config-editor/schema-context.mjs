import {fieldsFor,valuesFor} from './schema.mjs';
import {indexFor,scalarSpan} from './references.mjs';

const mappingTypes=new Set(['BlockMapping','FlowMapping','Object']);
const equalPath=(a,b)=>a.length===b.length&&a.every((v,i)=>v===b[i]);
function syntaxPath(node,model) {
  const path=[];
  for(let n=node.parent;n;n=n.parent)if(n.name==='Pair'||n.name==='Property')path.unshift(model.text(n.getChild('Key')||n.getChild('PropertyName')));
  return path;
}
function containerAt(index,pos,path) {
  const before=index.model.doc.sliceString(0,pos),tail=before.trimEnd().length;
  for(const probe of new Set([pos,tail]))for(let n=index.tree.resolveInner(probe,-1);n;n=n.parent)
    if(mappingTypes.has(n.name)&&index.model.contains(n,pos)&&equalPath(syntaxPath(n,index.model),path))return n;
  return null;
}

// Project only effective, known configuration containers onto their syntax
// definitions. Shared maps remain a graph; custom data never gains a schema
// merely because a key happens to look like a native configuration section.
function viewsFor(index) {
  if(index.schema.views)return index.schema.views;
  const model=index.model,views=[],pending=[{node:index.root,path:[]}],seen=new Set();
  while(pending.length){
    model.step();const view=pending.pop(),resolved=model.resolve(view.node)?.node;
    if(!resolved||!mappingTypes.has(resolved.name))continue;
    const id=resolved.from+':'+resolved.to+':'+JSON.stringify(view.path);if(seen.has(id))continue;seen.add(id);
    const map=model.mapping(view.node);if(!map)continue;
    views.push(view);
    const known=new Map(fieldsFor(view.path).map(f=>[f.label,f]));
    for(const field of map.fields.values()){
      model.step();const path=[...view.path,field.name];
      if(!view.path.length&&['proxy-providers','rule-providers'].includes(field.name)){
        for(const provider of model.fields(field.node))pending.push({node:provider.node,path:[...path,provider.name]});
      }else if(known.has(field.name)||view.path.join('.')==='sniffer.sniff'&&known.has(field.name.toUpperCase())){
        if(!fieldsFor(path).length)continue;
        if(model.isMap(field.node))pending.push({node:field.node,path});
        else for(const node of model.entries(field.node))pending.push({node,path});
      }
    }
  }
  index.schema.views=views;return views;
}
function values(view,key,model) {
  return valuesFor([...view.path,key],model.text(model.property(view.node,'type')));
}
function commonFields(views,model) {
  const first=fieldsFor(views[0].path);
  return first.flatMap(option=>{
    const peers=views.map(view=>fieldsFor(view.path).find(f=>f.label===option.label));
    if(peers.some(f=>!f||Array.isArray(f.value)!==Array.isArray(option.value)||typeof f.value!==typeof option.value))return [];
    const enums=views.map(view=>values(view,option.label,model)).filter(v=>v.length);
    if(!enums.length)return [option];
    const allowed=enums[0].filter(v=>enums.every(other=>other.includes(v)));
    return allowed.length?[{...option,value:allowed.includes(option.value)?option.value:allowed[0]}]:[];
  });
}
export function schemaCompletions(state,pos,language,info) {
  try {
    const index=indexFor(state,pos,language),model=index.model;if(!model||!index.schema)return null;
    const views=viewsFor(index);
    if(info.isKey){
      const container=containerAt(index,pos,info.path);
      if(!container){
        // The very first unpunctuated block key is still parsed as a scalar.
        // Project a prospective colon in an undispatched editor transaction;
        // source bytes, completion ranges and undo history remain untouched.
        const node=index.tree.resolveInner(pos,-1),line=state.doc.lineAt(pos);
        if(language==='yaml'&&info.path.length&&node.name==='Literal'&&node.to===pos&&/^\s+[\w-]+$/.test(state.doc.sliceString(line.from,pos))&&equalPath(syntaxPath(node,model),info.path))
          return schemaCompletions(state.update({changes:{from:pos,insert:':'}}).state,pos,language,info);
        return null;
      }
      const consumers=views.filter(view=>model.contributes(view.node,container));
      return consumers.length?{...info,candidates:commonFields(consumers,model)}:null;
    }
    const span=scalarSpan(state,pos,info,index.tree);if(!span||span.sequence)return null;
    const contexts=[];
    for(const view of views)for(const field of model.fields(view.node)){
      model.step();const schema=fieldsFor(view.path).find(f=>f.label===field.name);
      if(!schema||typeof schema.value==='object'||!model.fieldAt(view.node,field.name,pos))continue;
      contexts.push(values(view,field.name,model));
    }
    if(!contexts.length)return null;
    const candidates=contexts[0].filter(v=>contexts.every(other=>other.includes(v))).map(value=>({label:String(value),value,type:typeof value==='boolean'?'keyword':'enum',detail:'Clash 参数值'}));
    return {...span,candidates};
  }catch(error){if(!(error instanceof RangeError))throw error;return {...info,candidates:[]};}
}
