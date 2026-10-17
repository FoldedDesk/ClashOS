import {ensureSyntaxTree,syntaxTree} from '@codemirror/language';

const mappingTypes=new Set(['BlockMapping','FlowMapping','Object']);
const sequenceTypes=new Set(['BlockSequence','FlowSequence','Array']);
const scalarTypes=new Set(['Literal','QuotedLiteral','String']);
const cache=new WeakMap();
const ruleTypes=['DOMAIN','DOMAIN-SUFFIX','DOMAIN-KEYWORD','DOMAIN-WILDCARD','DOMAIN-REGEX','IP-CIDR','IP-CIDR6','SRC-IP-CIDR','SRC-IP-CIDR6','GEOIP','SRC-GEOIP','GEOSITE','IP-ASN','SRC-IP-ASN','DST-PORT','NETWORK','RULE-SET','AND','OR','NOT','MATCH'];

export function scalarText(raw,partial=false) {
  if(raw.startsWith('"')){
    try{return JSON.parse(partial&&(raw.length===1||!raw.endsWith('"'))?raw+'"':raw);}catch(_){return null;}
  }
  if(raw.startsWith("'")){
    if(!partial&&!raw.endsWith("'"))return null;
    return raw.slice(1,raw.endsWith("'")&&raw.length>1?-1:undefined).replace(/''/g,"'");
  }
  return raw;
}
function children(node,predicate) {
  const found=[];for(let c=node?.firstChild;c;c=c.nextSibling)if(predicate(c))found.push(c);return found;
}
function pairs(node) {return children(node,n=>n.name==='Pair'||n.name==='Property');}
function keyOf(pair,doc) {
  const key=pair?.getChild('Key')||pair?.getChild('PropertyName');return key?scalarText(doc.sliceString(key.from,key.to)):null;
}
function valueOf(pair) {
  let colon=false;for(let c=pair?.firstChild;c;c=c.nextSibling){if(c.name===':')colon=true;else if(colon&&!c.type.isError&&c.name!=='Comment')return c;}return null;
}
function property(node,key,doc) {return valueOf(pairs(node).find(p=>keyOf(p,doc)===key));}
function textOf(node,doc) {return node&&scalarTypes.has(node.name)?scalarText(doc.sliceString(node.from,node.to)):null;}
function entries(node) {
  if(!node||!sequenceTypes.has(node.name))return [];
  return node.name==='Array'?children(node,n=>mappingTypes.has(n.name)||scalarTypes.has(n.name)):children(node,n=>n.name==='Item').map(n=>n.firstChild).filter(Boolean);
}
function strings(node,doc) {return entries(node).map(n=>({name:textOf(n,doc),from:n.from,to:n.to})).filter(x=>x.name!==null);}
function rootAt(tree,pos,language) {
  if(language==='json')return tree.topNode.getChild('Object');
  const documents=children(tree.topNode,n=>n.name==='Document');let active;
  for(const document of documents){if(document.from>pos)break;active=document;}
  return children(active,n=>mappingTypes.has(n.name))[0];
}
function indexFor(state,pos,language) {
  const complete=ensureSyntaxTree(state,state.doc.length,40),tree=complete||syntaxTree(state),root=rootAt(tree,pos,language),doc=state.doc;
  if(!root)return {tree,nodes:[],groups:[],providers:[],ruleProviders:[]};
  const key=language+':'+root.from+':'+root.to,old=cache.get(doc)?.get(key);if(old)return {...old,tree};
  const nodes=entries(property(root,'proxies',doc)).filter(n=>mappingTypes.has(n.name)).map(n=>({node:n,name:textOf(property(n,'name',doc),doc),dialer:textOf(property(n,'dialer-proxy',doc),doc),detail:'节点 · '+(textOf(property(n,'type',doc),doc)||'未知协议')}));
  const providers=pairs(property(root,'proxy-providers',doc)).map(pair=>{
    const node=valueOf(pair),override=property(node,'override',doc),prefix=textOf(property(override,'additional-prefix',doc),doc)||'',suffix=textOf(property(override,'additional-suffix',doc),doc)||'';
    // Filtered/dynamic resources stay authoritative in the native core. Do not
    // evaluate user regular expressions or fabricate downloaded provider nodes.
    const visible=textOf(property(node,'type',doc),doc)==='inline'&&!textOf(property(node,'filter',doc),doc)&&!textOf(property(node,'exclude-filter',doc),doc)&&!textOf(property(node,'exclude-type',doc),doc);
    const overrideDialer=property(override,'dialer-proxy',doc),dialer=overrideDialer?textOf(overrideDialer,doc):null;
    const definitions=entries(property(node,'payload',doc)).map(n=>({node:n,name:textOf(property(n,'name',doc),doc),dialer:overrideDialer?dialer:textOf(property(n,'dialer-proxy',doc),doc)})).filter(n=>n.name).map(n=>({...n,name:prefix+n.name+suffix,detail:'集合节点 · '+keyOf(pair,doc)}));
    const payload=visible?definitions:[];
    return {name:keyOf(pair,doc),detail:'代理集合',payload,definitions,dialer,vertex:Symbol(keyOf(pair,doc))};
  });
  const ruleProviders=pairs(property(root,'rule-providers',doc)).map(pair=>({name:keyOf(pair,doc),detail:'规则集合'}));
  const groups=entries(property(root,'proxy-groups',doc)).filter(n=>mappingTypes.has(n.name)).map(node=>({node,name:textOf(property(node,'name',doc),doc),detail:'代理组 · '+(textOf(property(node,'type',doc),doc)||'select'),members:strings(property(node,'proxies',doc),doc),uses:strings(property(node,'use',doc),doc),includeNodes:textOf(property(node,'include-all-proxies',doc),doc)==='true'||textOf(property(node,'include-all',doc),doc)==='true',includeProviders:textOf(property(node,'include-all-providers',doc),doc)==='true'||textOf(property(node,'include-all',doc),doc)==='true'}));
  const data={nodes,groups,providers,ruleProviders};if(complete){let map=cache.get(doc);if(!map){map=new Map();cache.set(doc,map);}map.set(key,data);}return {...data,tree};
}
function atGroup(index,pos) {
  for(let i=index.groups.length-1;i>=0;i--)if(index.groups[i].node.from<=pos)return index.groups[i];return null;
}
function circularGroups(index,target) {
  const parents=new Map(),pending=[target],seen=new Set();
  const edge=(from,to)=>{if(!to)return;if(!parents.has(to))parents.set(to,[]);parents.get(to).push(from);};
  for(const node of [...index.nodes,...index.providers.flatMap(p=>p.definitions)])edge(node.name,node.dialer);
  for(const provider of index.providers){edge(provider.vertex,provider.dialer);for(const node of provider.definitions)edge(provider.vertex,node.name);}
  for(const group of index.groups){
    for(const member of group.members)edge(group.name,member.name);
    if(group.includeNodes)for(const node of index.nodes)edge(group.name,node.name);
    for(const provider of index.providers)if(group.includeProviders||group.uses.some(p=>p.name===provider.name))edge(group.name,provider.vertex);
  }
  while(pending.length){const name=pending.pop();if(seen.has(name))continue;seen.add(name);for(const parent of parents.get(name)||[])pending.push(parent);}return seen;
}
function targets(index) {
  return [{name:'DIRECT',detail:'内置出口'},{name:'REJECT',detail:'内置出口'},...index.nodes,...index.providers.flatMap(p=>p.payload),...index.groups];
}
function options(values) {
  const seen=new Set();return values.filter(x=>typeof x.name==='string'&&x.name.length>0&&x.name.length<=4096&&!/[\r\n\u0000]/.test(x.name)&&!seen.has(x.name)&&seen.add(x.name)).map(x=>({label:x.name,value:x.name,type:'variable',detail:x.detail,reference:true}));
}
function scalarSpan(state,pos,info,tree) {
  let node=tree.resolveInner(pos,-1),scalar;
  let sequence=false;for(let n=node;n;n=n.parent){if(sequenceTypes.has(n.name)){sequence=true;break;}if(n.name==='Pair'||n.name==='Property'||mappingTypes.has(n.name))break;}
  const line=state.doc.lineAt(pos),before=state.doc.sliceString(line.from,pos),block=info.language==='yaml'&&/^\s*-\s*$/.test(before);sequence=sequence||block;
  for(let n=node;n;n=n.parent){if(n.name==='Key'||n.name==='PropertyName')break;if(scalarTypes.has(n.name)){scalar=n;break;}if(n.name==='Pair'||n.name==='Property'||sequenceTypes.has(n.name))break;}
  if(scalar){const raw=state.doc.sliceString(scalar.from,scalar.to),value=scalarText(raw),prefix=scalarText(state.doc.sliceString(scalar.from,pos),true);if(value===null||prefix===null||/[\r\n]/.test(raw))return null;return {...info,from:scalar.from,to:scalar.to,isKey:false,prefix,value,sequence};}
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
export function referenceCompletions(state,pos,language,info) {
  const path=info.path,key=path.at(-1),groupPath=path.length===2&&path[0]==='proxy-groups',providerPath=path.length===3&&['proxy-providers','rule-providers'].includes(path[0]);
  const dialerPath=key==='dialer-proxy'&&(path.length===2&&path[0]==='proxies'||path.length===4&&path[0]==='proxy-providers'&&path[2]==='payload');
  const overrideDialer=key==='dialer-proxy'&&path.length===4&&path[0]==='proxy-providers'&&path[2]==='override';
  if(!(groupPath&&['proxies','use','default-selected'].includes(key)||providerPath&&key==='proxy'||path.length===1&&key==='rules'||dialerPath||overrideDialer))return null;
  const index=indexFor(state,pos,language),span=scalarSpan(state,pos,info,index.tree);if(!span)return null;
  if(span.sequence!==(['proxies','use','rules'].includes(key)))return null;
  if(path.length===1&&key==='rules')return ruleOptions(index,span);
  let candidates=targets(index);const group=groupPath?atGroup(index,pos):null;
  if(groupPath&&key==='use'){
    const circular=group?.name?circularGroups(index,group.name):new Set();
    candidates=index.providers.filter(p=>!circular.has(p.vertex)&&!group?.uses.some(m=>m.name===p.name&&m.from!==span.from));
  }
  if(dialerPath){
    const node=[...index.nodes,...index.providers.flatMap(p=>p.definitions)].find(n=>n.node.from<=pos&&pos<=n.node.to),circular=node?.name?circularGroups(index,node.name):new Set();
    candidates=candidates.filter(n=>!circular.has(n.name));
  }
  if(overrideDialer){
    const provider=index.providers.find(p=>p.name===path[1]),circular=provider?circularGroups(index,provider.vertex):new Set();
    candidates=candidates.filter(n=>!circular.has(n.name));
  }
  if(groupPath&&key==='proxies'){
    const duplicates=new Set(group?.members.filter(m=>m.from!==span.from).map(m=>m.name)),circular=group?.name?circularGroups(index,group.name):new Set();
    candidates=candidates.filter(x=>!duplicates.has(x.name)&&!circular.has(x.name));
  }
  if(groupPath&&key==='default-selected'&&group){
    const members=new Set(group.members.map(m=>m.name));for(const p of index.providers)if(group.includeProviders||group.uses.some(m=>m.name===p.name))for(const n of p.payload)members.add(n.name);
    if(group.includeNodes)for(const n of index.nodes)members.add(n.name);candidates=candidates.filter(x=>members.has(x.name));
  }
  return {...span,candidates:options(candidates)};
}
export function currentNodeType(state,pos) {
  const doc=state.doc,tree=ensureSyntaxTree(state,doc.length,0)||syntaxTree(state);for(let n=tree.resolveInner(pos,-1);n;n=n.parent)if(mappingTypes.has(n.name))return textOf(property(n,'type',doc),doc);return null;
}
