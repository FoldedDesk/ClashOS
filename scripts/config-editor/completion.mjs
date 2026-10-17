import {syntaxTree} from '@codemirror/language';
import {Transaction} from '@codemirror/state';

// Common Clash fields. The native validator remains authoritative for semantics.
const field = (label, value, detail) => ({label, value, detail, type: 'property'});
const fields = {
  root: [field('port',7890,'HTTP 代理端口'),field('socks-port',7891,'SOCKS5 端口'),field('mixed-port',7890,'HTTP / SOCKS5 共用端口'),field('mode','rule','rule / global / direct'),field('log-level','info','日志级别'),field('ipv6',false,'IPv6'),field('dns',{},'DNS 设置'),field('proxies',[],'节点列表'),field('proxy-groups',[],'代理组'),field('proxy-providers',{},'代理集合'),field('rule-providers',{},'规则集合'),field('rules',[],'分流规则'),field('hosts',{},'自定义域名映射'),field('geo-auto-update',false,'自动更新地理数据库'),field('geo-update-interval',24,'地理数据库更新间隔（小时）'),field('geox-url',{},'地理数据库地址')],
  dns: [field('enable',true,'启用 DNS'),field('listen','127.0.0.1:1053','DNS 监听地址'),field('ipv6',false,'返回 IPv6 地址'),field('nameserver',[],'默认 DNS 服务器'),field('fallback',[],'备用 DNS'),field('default-nameserver',[],'Bootstrap DNS'),field('proxy-server-nameserver',[],'节点域名解析服务器'),field('nameserver-policy',{},'按域名选择 DNS'),field('fallback-filter',{},'备用 DNS 筛选'),field('use-hosts',true,'使用 hosts'),field('respect-rules',false,'遵循分流规则')],
  proxies: [field('name','节点名称','节点名称'),field('type','ss','节点协议'),field('server','example.com','服务器'),field('port',443,'服务器端口'),field('cipher','aes-128-gcm','Shadowsocks 加密方式'),field('password','','服务器密码'),field('uuid','','VMess UUID'),field('alterId',0,'VMess alterId'),field('tls',true,'TLS'),field('servername','example.com','TLS SNI'),field('sni','example.com','TLS SNI'),field('skip-cert-verify',false,'跳过证书验证'),field('udp',true,'UDP'),field('network','tcp','传输协议'),field('ws-opts',{},'WebSocket 参数')],
  'proxy-groups': [field('name','代理组','代理组名称'),field('type','select','代理组类型'),field('proxies',[],'候选节点 / 代理组'),field('use',[],'代理集合'),field('url','https://www.gstatic.com/generate_204','健康检查地址'),field('interval',300,'健康检查间隔（秒）'),field('timeout',5000,'检查超时（毫秒）'),field('tolerance',50,'延迟容差'),field('lazy',true,'延迟检测'),field('strategy','consistent-hashing','负载均衡策略'),field('disable-udp',false,'禁用 UDP'),field('filter','','名称过滤'),field('exclude-filter','','排除过滤')],
  'proxy-providers': [field('type','http','http / file / inline'),field('url','https://example.com/proxies.yaml','集合地址'),field('path','./providers/proxies.yaml','缓存路径'),field('interval',3600,'更新间隔（秒）'),field('health-check',{},'集合健康检查'),field('payload',[],'内置节点'),field('filter','','名称过滤'),field('exclude-filter','','排除过滤')],
  'rule-providers': [field('type','http','http / file / inline'),field('behavior','domain','domain / ipcidr / classical'),field('format','yaml','yaml / text / mrs'),field('url','https://example.com/rules.yaml','规则集合地址'),field('path','./providers/rules.yaml','缓存路径'),field('interval',86400,'更新间隔（秒）'),field('payload',[],'内置规则')],
  'health-check': [field('enable',true,'启用检查'),field('url','https://www.gstatic.com/generate_204','检查地址'),field('interval',300,'检查间隔（秒）'),field('timeout',5000,'超时（毫秒）'),field('lazy',true,'延迟检测'),field('expected-status','204','预期 HTTP 状态')],
  'ws-opts': [field('path','/','WebSocket 路径'),field('headers',{},'WebSocket 请求头')],
  'fallback-filter': [field('geoip',true,'按 GeoIP 筛选'),field('geoip-code','CN','GeoIP 地区'),field('ipcidr',[],'IP 段'),field('domain',[],'域名')],
  'geox-url': [field('mmdb','https://example.com/Country.mmdb','GeoIP MMDB'),field('geoip','https://example.com/geoip.dat','GeoIP DAT'),field('geosite','https://example.com/geosite.dat','GeoSite DAT'),field('asn','https://example.com/ASN.mmdb','ASN MMDB')]
};
export const clashRootFields = fields.root;
const booleans = new Set(['enable','ipv6','tls','udp','skip-cert-verify','lazy','disable-udp','use-hosts','respect-rules','geo-auto-update','geoip']);
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
  let node=syntaxTree(state).resolveInner(pos,-1);
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
      const text=doc.line(i).text,m=/^(\s*)(?:-\s+)?([\w-]+)\s*:\s*(.*)$/.exec(text);
      if(!m)continue;
      const depth=m[1].replace(/\t/g,'  ').length+(text.trimStart().startsWith('- ')?2:0);
      while(stack.length&&stack.at(-1).depth>=depth)stack.pop();
      if(!m[3]||/^[>|]/.test(m[3]))stack.push({depth,key:m[2],scalar:/^[>|]/.test(m[3])});
    }
    while(stack.length&&stack.at(-1).depth>=indent)stack.pop();
    if(stack.some(x=>x.scalar))return null;
    return {path:stack.map(x=>x.key),isKey:true,from:pos-plain[2].length,to:pos,prefix:plain[2],indent,language};
  }
  let isKey=!!keyNode&&pos>=keyNode.from&&pos<=keyNode.to;
  if(language==='json'&&!isKey&&/[{,]\s*"?[\w-]*$/.test(before)&&!['String','Number','True','False','Null'].includes(node.name))isKey=true;
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

function valueOptions(path) {
  const key=path.at(-1),parent=path.at(-2);
  if(booleans.has(key))return [true,false];
  if(key==='mode')return ['rule','global','direct'];
  if(key==='log-level')return ['debug','info','warning','error','silent'];
  if(key==='type'){
    if(parent==='proxy-groups')return ['select','url-test','fallback','load-balance'];
    if(parent==='proxies'||(path[0]==='proxy-providers'&&path.includes('payload')))return ['ss','vmess','trojan','direct','reject'];
    if(path[0]==='proxy-providers'||path[0]==='rule-providers')return ['http','file','inline'];
    return [];
  }
  if(key==='cipher')return ['aes-128-gcm','aes-256-gcm','chacha20-ietf-poly1305'];
  if(key==='network')return ['tcp','ws'];
  if(key==='behavior')return ['domain','ipcidr','classical'];
  if(key==='format')return ['yaml','text','mrs'];
  if(key==='strategy')return ['consistent-hashing','round-robin','sticky-sessions'];
  return [];
}
function schema(path) {
  if(!path.length)return fields.root;
  const key=path.at(-1);
  if(path.length===1&&(key==='proxy-providers'||key==='rule-providers'))return []; // Arbitrary provider names.
  if(path.length===2&&(path[0]==='proxy-providers'||path[0]==='rule-providers'))return fields[path[0]];
  if(key==='payload')return path[0]==='proxy-providers'?fields.proxies:[];
  if(key==='proxies'&&path.length>1)return []; // Scalar group-member names, not node mappings.
  if(fields[key])return fields[key];
  if(path[0]==='proxy-providers'||path[0]==='rule-providers')return fields[path[0]];
  return [];
}
export function completionEdit(doc,info,option) {
  const remaining=doc.sliceString(info.to,Math.min(doc.length,info.to+20));
  let text;
  if(info.isKey){
    const key=info.language==='json'?JSON.stringify(option.label):option.label;
    text=key+(/^\s*:/.test(remaining)?'':': '+(info.language==='json'?JSON.stringify(option.value):typeof option.value==='string'?JSON.stringify(option.value):JSON.stringify(option.value)));
  }else text=info.language==='json'?JSON.stringify(option.value):typeof option.value==='string'?option.value:String(option.value);
  // Replace an existing quoted scalar as a whole, preserving quotes in YAML too.
  if(!info.isKey&&info.language==='yaml'&&/^["']/.test(doc.sliceString(info.from,info.from+1)))text=JSON.stringify(option.value);
  const valueAt=info.isKey?text.indexOf(': ')+2:0;
  const selectValue=info.isKey&&valueAt>1;
  return {from:info.from,to:info.to,insert:text,anchor:info.from+(selectValue?valueAt:text.length),head:info.from+text.length};
}
export function clashCompletions(language) {
  return context=>{
    const info=completionContext(context.state,context.pos,language);
    if(!info||(!context.explicit&&!info.prefix))return null;
    const candidates=info.isKey?schema(info.path):valueOptions(info.path).map(value=>({label:String(value),value,type:typeof value==='boolean'?'keyword':'enum',detail:'Clash 参数值'}));
    const options=candidates.filter(x=>x.label.toLowerCase().startsWith(info.prefix.toLowerCase())).map(option=>({...option,apply:(view)=>{
      const edit=completionEdit(view.state.doc,info,option);
      view.dispatch({changes:{from:edit.from,to:edit.to,insert:edit.insert},selection:{anchor:edit.anchor,head:edit.head},annotations:Transaction.userEvent.of('input.complete')});view.focus();
    }}));
    return options.length?{from:info.from,to:info.to,options,filter:false}:null;
  };
}
