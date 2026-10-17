// Suggestions describe the shipping native parser; validation stays authoritative.
const field = (label, value, detail) => ({label, value, detail, type: 'property'});
const providerCommon = [field('type','http','http / file / inline'),field('url','https://example.com/provider.yaml','下载地址'),field('path','./providers/public.yaml','缓存路径'),field('proxy','DIRECT','下载使用的节点 / 代理组'),field('interval',3600,'更新间隔（秒）'),field('timeout',5000,'下载超时（毫秒）'),field('size-limit',8388608,'最大下载字节数'),field('header',{},'下载请求头')];
export const fields = {
  root: [field('port',7890,'HTTP 代理端口'),field('socks-port',7891,'SOCKS5 端口'),field('mixed-port',7890,'HTTP / SOCKS5 共用端口'),field('mode','rule','rule / global / direct'),field('log-level','info','日志级别'),field('ipv6',false,'IPv6'),field('allow-lan',false,'允许局域网连接'),field('bind-address','127.0.0.1','监听地址'),field('authentication',[],'HTTP / SOCKS5 账号密码'),field('skip-auth-prefixes',[],'免认证来源网段'),field('lan-allowed-ips',[],'允许连接的来源网段'),field('lan-disallowed-ips',[],'禁止连接的来源网段'),field('dns',{},'DNS 设置'),field('sniffer',{},'域名嗅探'),field('proxies',[],'节点列表'),field('proxy-groups',[],'代理组'),field('proxy-providers',{},'代理集合'),field('rule-providers',{},'规则集合'),field('rules',[],'分流规则'),field('hosts',{},'自定义域名映射'),field('geo-auto-update',false,'自动更新地理数据库'),field('geo-update-interval',24,'地理数据库更新间隔（小时）'),field('geox-url',{},'地理数据库地址')],
  dns: [field('enable',true,'启用 DNS'),field('listen','127.0.0.1:1053','DNS 监听地址'),field('ipv6',false,'返回 IPv6 地址'),field('nameserver',[],'默认 DNS 服务器'),field('fallback',[],'备用 DNS'),field('default-nameserver',[],'Bootstrap DNS'),field('proxy-server-nameserver',[],'节点域名解析服务器'),field('proxy-server-nameserver-policy',{},'节点域名的 DNS 策略'),field('direct-nameserver',[],'直连域名解析服务器'),field('direct-nameserver-follow-policy',false,'直连解析遵循策略'),field('nameserver-policy',{},'按域名选择 DNS'),field('fallback-filter',{},'备用 DNS 筛选'),field('use-hosts',true,'使用 hosts'),field('respect-rules',false,'遵循分流规则'),field('enhanced-mode','redir-host','DNS 增强模式；普通监听返回真实 IP')],
  proxies: [field('name','节点名称','节点名称'),field('type','ss','节点协议'),field('server','example.com','服务器'),field('port',443,'服务器端口'),field('cipher','aes-128-gcm','Shadowsocks / VMess 加密方式'),field('password','','服务器密码'),field('uuid','','VMess UUID'),field('alterId',0,'VMess alterId'),field('tls',true,'TLS'),field('servername','example.com','TLS SNI'),field('sni','example.com','TLS SNI'),field('skip-cert-verify',false,'跳过证书验证'),field('alpn',[],'TLS ALPN 协议'),field('udp',true,'UDP'),field('network','tcp','传输协议'),field('ws-opts',{},'WebSocket 参数')],
  'proxy-groups': [field('name','代理组','代理组名称'),field('type','select','代理组类型'),field('proxies',[],'候选节点 / 代理组'),field('use',[],'代理集合'),field('include-all',false,'包含全部节点和代理集合'),field('include-all-proxies',false,'包含全部静态节点'),field('include-all-providers',false,'包含全部代理集合'),field('default-selected','','默认候选节点'),field('url','https://www.gstatic.com/generate_204','健康检查地址'),field('interval',300,'健康检查间隔（秒）'),field('timeout',5000,'检查超时（毫秒）'),field('expected-status','204','预期 HTTP 状态'),field('tolerance',50,'延迟容差'),field('lazy',true,'延迟检测'),field('strategy','consistent-hashing','负载均衡策略'),field('disable-udp',false,'禁用 UDP'),field('filter','','名称过滤'),field('exclude-filter','','排除过滤'),field('icon','','代理组图片链接'),field('hidden',false,'隐藏代理组卡片')],
  'proxy-providers': [...providerCommon,field('health-check',{},'集合健康检查'),field('payload',[],'内置节点'),field('filter','','名称过滤'),field('exclude-filter','','排除过滤'),field('exclude-type','','排除节点协议，以 | 分隔'),field('override',{},'节点覆盖设置')],
  'rule-providers': [...providerCommon,field('behavior','domain','domain / ipcidr / classical'),field('format','yaml','yaml / text / mrs'),field('payload',[],'内置规则')],
  'health-check': [field('enable',true,'启用检查'),field('url','https://www.gstatic.com/generate_204','检查地址'),field('interval',300,'检查间隔（秒）'),field('timeout',5000,'超时（毫秒）'),field('lazy',true,'延迟检测'),field('expected-status','204','预期 HTTP 状态')],
  override: [field('additional-prefix','','节点名称前缀'),field('additional-suffix','','节点名称后缀'),field('udp',true,'覆盖 UDP 设置'),field('skip-cert-verify',false,'覆盖证书验证设置')],
  'ws-opts': [field('path','/','WebSocket 路径'),field('headers',{},'WebSocket 请求头')],
  'fallback-filter': [field('geoip',true,'按 GeoIP 筛选'),field('geoip-code','CN','GeoIP 地区'),field('ipcidr',[],'IP 段'),field('domain',[],'域名')],
  'geox-url': [field('mmdb','https://example.com/Country.mmdb','GeoIP MMDB'),field('geoip','https://example.com/geoip.dat','GeoIP DAT'),field('geosite','https://example.com/geosite.dat','GeoSite DAT'),field('asn','https://example.com/ASN.mmdb','ASN MMDB')],
  sniffer: [field('enable',true,'启用域名嗅探'),field('force-dns-mapping',true,'嗅探 DNS 映射流量'),field('parse-pure-ip',true,'嗅探直接访问 IP 的流量'),field('override-destination',true,'使用嗅探域名连接目标'),field('sniff',{},'HTTP / TLS / QUIC 协议'),field('force-domain',[],'强制嗅探域名'),field('skip-domain',[],'跳过域名'),field('skip-src-address',[],'跳过来源网段'),field('skip-dst-address',[],'跳过目标网段')],
  sniff: [field('HTTP',{},'HTTP Host'),field('TLS',{},'TLS SNI'),field('QUIC',{},'QUIC v1 / v2 Initial')],
  sniffProtocol: [field('ports',[443],'端口或端口范围'),field('override-destination',true,'使用此协议的嗅探域名连接目标')]
};
export const clashRootFields = fields.root;

export function nodePath(path) {
  return path.length===1&&path[0]==='proxies'||path.length===3&&path[0]==='proxy-providers'&&path[2]==='payload';
}
export function fieldsFor(path) {
  if(!path.length)return fields.root;
  if(path.length===1)return ['dns','proxies','proxy-groups','geox-url','sniffer'].includes(path[0])?fields[path[0]]:[];
  if(path.length===2&&['proxy-providers','rule-providers'].includes(path[0]))return fields[path[0]];
  if(nodePath(path))return fields.proxies;
  if(nodePath(path.slice(0,-1))&&path.at(-1)==='ws-opts')return fields['ws-opts'];
  if(path.length===3&&path[0]==='proxy-providers'&&['health-check','override'].includes(path[2]))return fields[path[2]];
  if(path.join('.')==='dns.fallback-filter')return fields['fallback-filter'];
  if(path.join('.')==='sniffer.sniff')return fields.sniff;
  if(path.length===3&&path[0]==='sniffer'&&path[1]==='sniff'&&['HTTP','TLS','QUIC'].includes(path[2].toUpperCase()))return fields.sniffProtocol;
  return [];
}
export function valuesFor(path,nodeType) {
  const key=path.at(-1),parent=path.slice(0,-1),entry=fieldsFor(parent).find(x=>x.label===key);
  if(!entry)return [];
  if(typeof entry.value==='boolean')return [true,false];
  if(path.length===1&&key==='mode')return ['rule','global','direct'];
  if(path.length===1&&key==='log-level')return ['debug','info','warning','error','silent'];
  if(key==='type'){
    if(parent.length===1&&parent[0]==='proxy-groups')return ['select','url-test','fallback','load-balance'];
    if(nodePath(parent))return ['ss','vmess','trojan','direct','reject'];
    return ['http','file','inline'];
  }
  if(key==='cipher'&&nodePath(parent))return nodeType?.toLowerCase()==='vmess'?['auto','aes-128-gcm','chacha20-poly1305','none','zero']:['aes-128-gcm','aes-256-gcm','chacha20-ietf-poly1305'];
  if(key==='network'&&nodePath(parent))return ['tcp','ws'];
  if(key==='behavior')return ['domain','ipcidr','classical'];
  if(key==='format')return ['yaml','text','mrs'];
  if(key==='strategy')return ['consistent-hashing','round-robin','sticky-sessions'];
  if(path.join('.')==='dns.enhanced-mode')return ['redir-host','fake-ip'];
  return [];
}
