import {ensureSyntaxTree,syntaxTree} from '@codemirror/language';
import {ReferenceModel,scalarText,children} from './reference-model.mjs';
export {scalarText} from './reference-model.mjs';

const mappingTypes=new Set(['BlockMapping','FlowMapping','Object']);
const sequenceTypes=new Set(['BlockSequence','FlowSequence','Array']);
const scalarTypes=new Set(['Literal','QuotedLiteral','String']);
const cache=new WeakMap();
const ruleTypes=['DOMAIN','DOMAIN-SUFFIX','DOMAIN-KEYWORD','DOMAIN-WILDCARD','DOMAIN-REGEX','IP-CIDR','IP-CIDR6','SRC-IP-CIDR','SRC-IP-CIDR6','GEOIP','SRC-GEOIP','GEOSITE','IP-ASN','SRC-IP-ASN','DST-PORT','NETWORK','RULE-SET','AND','OR','NOT','MATCH'];

function indexFor(state,pos,language) {
  const complete=ensureSyntaxTree(state,state.doc.length,40),tree=complete||syntaxTree(state),doc=state.doc;
  const active=language==='json'?tree.topNode:children(tree.topNode,n=>n.name==='Document').filter(n=>n.from<=pos).at(-1);
  const key=language+':'+active?.from+':'+active?.to,old=cache.get(doc)?.get(key);if(old){old.model.work=0;return {...old,tree};}
  try {
    const model=new ReferenceModel(tree,pos,doc,language),root=model.root;
    const property=(node,key)=>model.property(node,key),text=node=>model.text(node),entries=node=>model.entries(node),fields=node=>model.fields(node);
    const nodes=entries(property(root,'proxies')).filter(n=>model.isMap(n)).map(node=>({node,name:text(property(node,'name')),dialer:text(property(node,'dialer-proxy')),detail:'节点 · '+(text(property(node,'type'))||'未知协议')}));
    const providers=fields(property(root,'proxy-providers')).map(pair=>{
      const node=pair.node,override=property(node,'override'),prefix=text(property(override,'additional-prefix'))||'',suffix=text(property(override,'additional-suffix'))||'';
      // Dynamic/filtered provider contents remain authoritative in the core.
      const visible=text(property(node,'type'))==='inline'&&!text(property(node,'filter'))&&!text(property(node,'exclude-filter'))&&!text(property(node,'exclude-type'));
      const overrideField=model.field(override,'dialer-proxy'),dialer=overrideField?text(overrideField.node):null;
      const definitions=entries(property(node,'payload')).filter(n=>model.isMap(n)).map(n=>({node:n,name:text(property(n,'name')),dialer:overrideField?dialer:text(property(n,'dialer-proxy'))})).filter(n=>n.name).map(n=>({...n,name:prefix+n.name+suffix,detail:'集合节点 · '+pair.name}));
      return {node,override,name:pair.name,detail:'代理集合',payload:visible?definitions:[],definitions,dialer,vertex:Symbol(pair.name)};
    });
    const ruleProviders=fields(property(root,'rule-providers')).map(pair=>({node:pair.node,name:pair.name,detail:'规则集合'}));
    const groups=entries(property(root,'proxy-groups')).filter(n=>model.isMap(n)).map(node=>({node,name:text(property(node,'name')),detail:'代理组 · '+(text(property(node,'type'))||'select'),members:model.strings(property(node,'proxies')),uses:model.strings(property(node,'use')),includeNodes:text(property(node,'include-all-proxies'))==='true'||text(property(node,'include-all'))==='true',includeProviders:text(property(node,'include-all-providers'))==='true'||text(property(node,'include-all'))==='true'}));
    const data={nodes,groups,providers,ruleProviders,model,root};if(complete){let map=cache.get(doc);if(!map){map=new Map();cache.set(doc,map);}map.set(key,data);}return {...data,tree};
  } catch(error) {
    if(!(error instanceof RangeError))throw error;
    return {tree,nodes:[],groups:[],providers:[],ruleProviders:[],model:null};
  }
}
function ownersAt(index,key,pos,kind) {
  const model=index.model;if(!model)return [];
  const owners=kind==='group'?index.groups:kind==='node'?[...index.nodes,...index.providers.flatMap(p=>p.definitions)]:kind==='override'?index.providers.map(p=>({...p,node:p.override})):kind==='provider'?[...index.providers,...index.ruleProviders]:[{node:index.root}];
  return owners.filter(owner=>model.fieldAt(owner.node,key,pos));
}
function contextsAt(index,info,pos) {
  const result=[];
  for(const [kind,keys] of [['group',['proxies','use','default-selected']],['node',['dialer-proxy']],['override',['dialer-proxy']],['provider',['proxy']],['root',['rules']]])
    for(const key of keys)for(const owner of ownersAt(index,key,pos,kind))result.push({kind,key,owner});
  if(result.length)return result;
  // Empty drafts can end just after a colon, beyond the Pair's syntax range.
  const path=info.path,key=path.at(-1),model=index.model;
  const owner=(values)=>{for(let i=values.length-1;i>=0;i--)if(model?.contains(model.resolve(values[i].node)?.node,pos)||model?.contains(values[i].node,pos))return values[i];};
  if(path.length===2&&path[0]==='proxy-groups'&&['proxies','use','default-selected'].includes(key))return [{kind:'group',key,owner:owner(index.groups)}];
  if(key==='dialer-proxy'&&(path.length===2&&path[0]==='proxies'||path.length===4&&path[0]==='proxy-providers'&&path[2]==='payload'))return [{kind:'node',key,owner:owner([...index.nodes,...index.providers.flatMap(p=>p.definitions)])}];
  if(key==='dialer-proxy'&&path.length===4&&path[0]==='proxy-providers'&&path[2]==='override')return [{kind:'override',key,owner:index.providers.find(p=>p.name===path[1])}];
  if(path.length===3&&['proxy-providers','rule-providers'].includes(path[0])&&key==='proxy')return [{kind:'provider',key}];
  if(path.length===1&&key==='rules')return [{kind:'root',key}];
  return [];
}
function circularGroups(index,target) {
  const parents=index.parents||new Map(),pending=Array.isArray(target)?[...target]:[target],seen=new Set();
  if(!index.parents){
    const edge=(from,to)=>{index.model?.step();if(!to)return;if(!parents.has(to))parents.set(to,[]);parents.get(to).push(from);};
    for(const node of [...index.nodes,...index.providers.flatMap(p=>p.definitions)])edge(node.name,node.dialer);
    for(const provider of index.providers){edge(provider.vertex,provider.dialer);for(const node of provider.definitions)edge(provider.vertex,node.name);}
    for(const group of index.groups){
      for(const member of group.members)edge(group.name,member.name);
      if(group.includeNodes)for(const node of index.nodes)edge(group.name,node.name);
      for(const provider of index.providers)if(group.includeProviders||group.uses.some(p=>p.name===provider.name))edge(group.name,provider.vertex);
    }
    index.parents=parents;
  }
  while(pending.length){index.model?.step();const name=pending.pop();if(seen.has(name))continue;seen.add(name);for(const parent of parents.get(name)||[])pending.push(parent);}return seen;
}
function targets(index) {
  return [{name:'DIRECT',detail:'内置出口'},{name:'REJECT',detail:'内置出口'},...index.nodes,...index.providers.flatMap(p=>p.payload),...index.groups];
}
function options(values) {
  const seen=new Set();return values.filter(x=>typeof x.name==='string'&&x.name.length>0&&x.name.length<=4096&&!/[\u0000-\u001f\u007f-\u009f]/.test(x.name)&&!seen.has(x.name)&&seen.add(x.name)).map(x=>({label:x.name,value:x.name,type:'variable',detail:x.detail,reference:true}));
}
function scalarSpan(state,pos,info,tree) {
  let node=tree.resolveInner(pos,-1),scalar;
  if(['Alias','Anchor','Tag'].includes(node.name))return null;
  let sequence=false;for(let n=node;n;n=n.parent){if(sequenceTypes.has(n.name)){sequence=true;break;}if(n.name==='Pair'||n.name==='Property'||mappingTypes.has(n.name))break;}
  const line=state.doc.lineAt(pos),before=state.doc.sliceString(line.from,pos),block=info.language==='yaml'&&/^\s*-\s*$/.test(before);sequence=sequence||block;
  for(let n=node;n;n=n.parent){if(n.name==='Key'||n.name==='PropertyName')break;if(scalarTypes.has(n.name)){scalar=n;break;}if(n.name==='Pair'||n.name==='Property'||sequenceTypes.has(n.name))break;}
  if(scalar){const raw=state.doc.sliceString(scalar.from,scalar.to),value=scalarText(raw,false,info.language),prefix=scalarText(state.doc.sliceString(scalar.from,pos),true,info.language);if(value===null||prefix===null||/[\r\n]/.test(raw))return null;return {...info,from:scalar.from,to:scalar.to,isKey:false,prefix,value,sequence};}
  // Empty block items and flow/JSON arrays have no scalar syntax node yet.
  if(block||['[',','].includes(node.name)||sequenceTypes.has(node.name))return {...info,from:pos,to:pos,isKey:false,prefix:'',value:'',sequence};
  if(!info.isKey&&info.from===pos)return {...info,isKey:false,prefix:'',value:'',sequence};return null;
}
function ruleOptions(index,span) {
  const value=span.value,cursor=span.prefix.length,parts=[];let start=0,depth=0;
  for(let i=0;i<value.length;i++){if(value[i]==='(')depth++;else if(value[i]===')'){if(--depth<0)return null;}else if(value[i]===','&&depth===0){parts.push([start,i]);start=i+1;}}
  parts.push([start,value.length]);const part=parts.findIndex(([from,to])=>from<=cursor&&cursor<=to);if(part<0)return null;
  const [from,to]=parts[part],token=value.slice(from,to),left=from+token.length-token.trimStart().length,right=to-(token.length-token.trimEnd().length),prefix=value.slice(left,cursor),kind=value.slice(...parts[0]).trim().toUpperCase();
  let candidates;
  if(part===0)candidates=ruleTypes.map(name=>({label:name,value:name,type:'keyword',detail:'分流规则类型',reference:true}));
  else if(kind==='RULE-SET'&&part===1)candidates=options(index.ruleProviders);
  else if((kind==='MATCH'||kind==='FINAL')&&part===1||ruleTypes.includes(kind)&&!['MATCH'].includes(kind)&&part===2)candidates=options(targets(index));
  else return null;
  // Native rule fields are comma-separated; such names can still be used in
  // group lists, but cannot be inserted as a single routing-rule target.
  candidates=candidates.filter(x=>!/[(),]/.test(x.value)).map(x=>({...x,value:value.slice(0,left)+x.value+value.slice(Math.max(left,right))}));
  return {...span,prefix,candidates};
}
function referenceResult(state,pos,language,info) {
  const index=indexFor(state,pos,language),contexts=contextsAt(index,info,pos);
  if(!contexts.length)return null;
  const span=scalarSpan(state,pos,info,index.tree);if(!span)return null;
  const results=contexts.map(({kind,key,owner})=>{
    if(span.sequence!==(['proxies','use','rules'].includes(key)))return null;
    if(kind==='root')return ruleOptions(index,span);
    let candidates=targets(index);
    const circular=owner?(kind==='override'?circularGroups(index,[owner.vertex,...owner.definitions.map(n=>n.name)]):owner.name?circularGroups(index,owner.name):new Set()):new Set();
    const editing=member=>member.from===span.from||member.source?.from===span.from;
    if(kind==='group'&&key==='use')candidates=index.providers.filter(p=>!circular.has(p.vertex)&&!owner?.uses.some(m=>m.name===p.name&&!editing(m)));
    if(kind==='node'||kind==='override')candidates=candidates.filter(n=>!circular.has(n.name));
    if(kind==='group'&&key==='proxies'){
      const duplicates=new Set(owner?.members.filter(m=>!editing(m)).map(m=>m.name));candidates=candidates.filter(x=>!duplicates.has(x.name)&&!circular.has(x.name));
    }
    if(kind==='group'&&key==='default-selected'&&owner){
      const members=new Set(owner.members.map(m=>m.name));for(const p of index.providers)if(owner.includeProviders||owner.uses.some(m=>m.name===p.name))for(const n of p.payload)members.add(n.name);
      if(owner.includeNodes)for(const n of index.nodes)members.add(n.name);candidates=candidates.filter(x=>members.has(x.name));
    }
    return {...span,candidates:options(candidates)};
  });
  if(results.some(x=>!x))return null;
  // Editing a shared template must be valid for every actual consumer.
  const first=results[0];
  return {...first,candidates:first.candidates.filter(option=>results.every(result=>result.prefix===first.prefix&&result.candidates.some(other=>other.label===option.label&&other.value===option.value)))};
}
export function referenceCompletions(state,pos,language,info) {
  try{return referenceResult(state,pos,language,info);}catch(error){if(!(error instanceof RangeError))throw error;return {...info,candidates:[]};}
}
export function currentNodeType(state,pos,language='yaml') {
  try {
    const index=indexFor(state,pos,language),model=index.model;if(!model)return null;
    for(let n=index.tree.resolveInner(pos,-1);n;n=n.parent)if(mappingTypes.has(n.name))return model.text(model.property(n,'type'));
    return null;
  }catch(error){if(!(error instanceof RangeError))throw error;return null;}
}
