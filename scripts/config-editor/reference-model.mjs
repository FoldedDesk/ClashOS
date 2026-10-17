import {CST} from 'yaml';

const mappings=new Set(['BlockMapping','FlowMapping','Object']);
const sequences=new Set(['BlockSequence','FlowSequence','Array']);
const scalars=new Set(['Literal','QuotedLiteral','String','PropertyName','Number','True','False','Null']);
const limit=250000;
export function children(node,predicate=()=>true) {
  const found=[];for(let c=node?.firstChild;c;c=c.nextSibling)if(predicate(c))found.push(c);return found;
}
export function valueOf(pair,doc) {
  let colon=false;for(let c=pair?.firstChild;c;c=c.nextSibling){
    if(c.name===':')colon=true;
    // Lezer currently includes a separating colon in alias keys (*key: value),
    // which libyaml accepts. Recover only that exact missing-colon shape.
    else if(c.name==='Key'&&c.getChild('Alias')&&!pair.getChild(':')&&doc?.sliceString(c.to-1,c.to)===':')colon=true;
    else if(colon&&!c.type.isError&&c.name!=='Comment')return c;
  }return null;
}
export function scalarText(raw,partial=false,language='yaml') {
  if(raw.length>65536)return null;
  const quote=raw[0];
  if(partial&&(quote==='"'||quote==="'")) {
    const escaped=quote==='"'&&(/\\+$/.exec(raw.slice(0,-1))?.[0].length||0)%2===1;
    const paired=quote==="'"&&(/'+$/.exec(raw.slice(1))?.[0].length||0)%2===0;
    if(raw.length===1||raw.at(-1)!==quote||escaped||paired)raw+=quote;
  }
  if(language==='json')try{return raw.startsWith('"')?JSON.parse(raw):raw;}catch{return null;}
  let invalid=false;
  const type=raw.startsWith('"')?'double-quoted-scalar':raw.startsWith("'")?'single-quoted-scalar':'scalar';
  try {const result=CST.resolveAsScalar({type,source:raw,offset:0,indent:0},true,()=>{invalid=true;});return invalid?null:result?.value??null;}catch{return null;}
}
function id(node){return node?node.name+':'+node.from+':'+node.to:'';}

// A lazy view over the existing Lezer tree. Aliases share syntax nodes; neither
// a complete JS object nor an expanded copy of a template is ever constructed.
// Limits apply to graph work, not to alias expansion, and drafts may be invalid.
export class ReferenceModel {
  constructor(tree,pos,doc,language) {
    this.doc=doc;this.language=language;this.work=0;this.anchors=new Map();this.resolved=new Map();this.maps=new Map();this.texts=new Map();
    this.tags=new Map([['!!','tag:yaml.org,2002:']]);
    if(language==='json'){this.root=tree.topNode.getChild('Object');return;}
    for(const document of children(tree.topNode,n=>n.name==='Document')){if(document.from>pos)break;this.document=document;}
    for(const directive of children(this.document,n=>n.name==='Directive')) {
      const match=/^%TAG\s+(\S+)\s+(\S+)/.exec(doc.sliceString(directive.from,directive.to));if(match)this.tags.set(match[1],match[2]);
    }
    const pending=children(this.document);
    while(pending.length){
      this.step();const node=pending.pop();
      if(node.name==='Anchored'){
        const anchor=node.getChild('Anchor'),name=anchor&&doc.sliceString(anchor.from+1,anchor.to);
        // libyaml rejects duplicate anchors instead of rebinding them.
        if(name)this.anchors.set(name,this.anchors.has(name)?null:node);
      }
      for(let c=node.lastChild;c;c=c.prevSibling)pending.push(c);
    }
    this.root=children(this.document,n=>mappings.has(n.name)||['Anchored','Tagged','Alias'].includes(n.name))[0];
  }
  step(){if(++this.work>limit)throw new RangeError('Reference graph work limit');}
  tag(raw) {
    if(raw.startsWith('!<')&&raw.endsWith('>'))return raw.slice(2,-1);
    const match=/^(![^!]*!)(.*)$/.exec(raw);return match&&this.tags.has(match[1])?this.tags.get(match[1])+match[2]:raw;
  }
  resolve(input,depth=0,seen=new Set()) {
    if(!input||depth>64)return null;this.step();const key=id(input);
    if(this.resolved.has(key))return this.resolved.get(key);
    if(seen.has(key))return null;seen.add(key);let node=input,tag=null;
    while(node&&['Key','Anchored','Tagged'].includes(node.name)) {
      this.step();if(++depth>64)return null;
      if(node.name==='Tagged'){const t=node.getChild('Tag');if(t)tag=this.tag(this.doc.sliceString(t.from,t.to));}
      node=children(node,n=>!['Anchor','Tag','Comment'].includes(n.name)&&!n.type.isError)[0];
    }
    let result=node?{node,tag}:null;
    if(node?.name==='Alias'){
      const aliasKey=node.parent?.name==='Key'&&!node.parent.parent?.getChild(':')&&this.doc.sliceString(node.to-1,node.to)===':';
      const target=this.anchors.get(this.doc.sliceString(node.from+1,node.to-(aliasKey?1:0)));
      result=target&&target.from<node.from?this.resolve(target,depth+1,seen):null;
    }
    this.resolved.set(key,result);return result;
  }
  text(input) {
    const node=this.resolve(input)?.node;if(!node)return null;const key=id(node);if(this.texts.has(key))return this.texts.get(key);
    let result=null;
    if(scalars.has(node.name))result=scalarText(this.doc.sliceString(node.from,node.to),false,this.language);
    else if(node.name==='BlockLiteral') {
      const header=node.getChild('BlockLiteralHeader'),content=node.getChild('BlockLiteralContent');
      if(header&&content&&node.to-node.from<=65536){
        let owner=node.parent;while(owner&&owner.name!=='Pair')owner=owner.parent;
        const column=(owner?.getChild('Key')?.from??node.from)-this.doc.lineAt(node.from).from;
        const h={type:'block-scalar-header',offset:header.from,indent:column,source:this.doc.sliceString(header.from,header.to)};
        let invalid=false;try {result=CST.resolveAsScalar({type:'block-scalar',offset:node.from,indent:column,props:[h,{type:'newline',source:'\n',offset:content.from-1,indent:column}],source:this.doc.sliceString(content.from,node.to)+(this.doc.sliceString(node.to,node.to+1)==='\n'?'\n':'')},true,()=>{invalid=true;})?.value??null;}catch{}
        if(invalid)result=null;
      }
    }
    this.texts.set(key,result);return result;
  }
  isMap(input){return mappings.has(this.resolve(input)?.node.name);}
  entries(input) {
    const node=this.resolve(input)?.node;if(!node||!sequences.has(node.name))return [];
    return node.name==='Array'?children(node,n=>!['[',']',',','Comment'].includes(n.name)&&!n.type.isError):children(node,n=>n.name==='Item').map(n=>children(n,c=>c.name!=='Comment'&&!c.type.isError)[0]).filter(Boolean);
  }
  mapping(input,depth=0,seen=new Set()) {
    const node=this.resolve(input)?.node;if(!node||!mappings.has(node.name)||depth>64)return null;
    const key=id(node);if(this.maps.has(key))return this.maps.get(key);if(seen.has(key))return null;seen.add(key);this.maps.set(key,null);
    const own=new Map(),merges=[];let duplicate=false;
    for(const pair of children(node,n=>n.name==='Pair'||n.name==='Property')){
      this.step();const k=pair.getChild('Key')||pair.getChild('PropertyName'),name=this.text(k),resolved=this.resolve(k);
      if(name===null)return null;
      if(resolved?.tag==='tag:yaml.org,2002:merge'&&name!=='<<')return null;
      const merge=this.language==='yaml'&&name==='<<'&&(resolved?.tag==='tag:yaml.org,2002:merge'||!resolved?.tag&&resolved?.node.name==='Literal');
      if(merge)merges.push(valueOf(pair,this.doc));
      else {if(own.has(name))duplicate=true;else own.set(name,{name,node:valueOf(pair,this.doc),pair});}
    }
    if(merges.length>1||merges.length&&duplicate)return null;
    const inheritedMaps=[];
    if(merges.length){
      const value=merges[0],resolved=this.resolve(value)?.node;
      const sources=sequences.has(resolved?.name)?this.entries(value):[value];
      for(const source of sources){
        const inherited=this.mapping(source,depth+1,new Set(seen));if(!inherited||inherited.duplicate)return null;
        inheritedMaps.push(inherited);
        for(const [name,field] of inherited.fields){this.step();if(!own.has(name))own.set(name,field);}
      }
    }
    const result={node,fields:own,duplicate,merges:inheritedMaps};this.maps.set(key,result);return result;
  }
  contributes(input,source) {
    const pending=[this.mapping(input)],seen=new Set(),target=id(source);
    while(pending.length){
      this.step();const map=pending.pop();if(!map||seen.has(map))continue;seen.add(map);
      if(id(map.node)===target)return true;pending.push(...map.merges);
    }return false;
  }
  fields(node){return [...this.mapping(node)?.fields.values()||[]];}
  field(node,key){return this.mapping(node)?.fields.get(key);}
  property(node,key){return this.field(node,key)?.node;}
  contains(node,pos){
    if(!node||node.from>pos)return false;if(pos<=node.to)return true;
    if(this.tailPosition!==pos){
      const prefix=this.doc.sliceString(0,pos);let from=prefix.length;while(from&&/\s/.test(prefix[from-1]))from--;
      this.tailPosition=pos;this.tailFrom=from;
    }
    return node.to>=this.tailFrom;
  }
  fieldAt(node,key,pos){
    const field=this.field(node,key);if(!field)return false;
    const resolved=this.resolve(field.node)?.node;
    // Source locations belong to the definition, even when reached via an
    // alias. A shared template can affect several consumers at the same time.
    return this.contains(field.node,pos)||this.contains(resolved,pos)||this.contains(field.pair,pos)&&pos>=(field.pair.getChild('Key')||field.pair.getChild('PropertyName')).to;
  }
  strings(node){return this.entries(node).map(n=>({name:this.text(n),from:n.from,to:n.to,source:this.resolve(n)?.node})).filter(x=>x.name!==null);}
}
