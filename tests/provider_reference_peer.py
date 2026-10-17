#!/usr/bin/env python3
"""Independent provider endpoint over inherited sockets; payloads contain only public dummy credentials."""
import sys,socket,ssl,json,gzip,zlib
from vmess_reference_peer import Wire
from https_reference_peer import Tunnel,context

TOKEN='Bearer private-test-token'

def feed(mode):
    names=['remote-b','remote-c'] if mode=='v2' else ['remote-a','remote-b']
    if mode=='duplicate':names=['remote-a','remote-a']
    if mode=='conflict':names=['local-node']
    if mode=='regions':names=['香港 A','日本 B']
    nodes=[dict(name=name,type='ss',server='node.invalid',port=443,cipher='aes-256-gcm',password='probe-password',udp=True) for name in names]
    return json.dumps({'proxies':nodes},ensure_ascii=False).encode()

def main():
    fd,alter,kind,mode=int(sys.argv[1]),int(sys.argv[2]),sys.argv[3],sys.argv[4]
    conn=socket.socket(fileno=fd);conn.settimeout(5)
    outer=kind=='vmess-ws-tls'
    if outer:conn=context().wrap_socket(conn,server_side=True)
    wire=Wire(conn)
    if outer:wire.upgrade()
    tunnel=Tunnel(wire,'direct' if kind in ('plain','https') else kind,alter,'')
    secure=kind!='plain' and not kind.endswith('-plain')
    tls=None
    if secure:
        incoming,outgoing=ssl.MemoryBIO(),ssl.MemoryBIO();ctx=context();tls=ctx.wrap_bio(incoming,outgoing,server_side=True)
        def flush():
            data=outgoing.read()
            if data:tunnel.send(data)
        def action(fn):
            while True:
                try:result=fn();flush();return result
                except ssl.SSLWantReadError:
                    flush();data=tunnel.receive()
                    if not data:raise EOFError()
                    incoming.write(data)
        try:action(tls.do_handshake)
        except (ssl.SSLError,EOFError,ConnectionResetError):
            if mode=='untrusted':return
            raise
        receive=lambda:action(lambda:tls.read(4096))
        send=lambda data:(tls.write(data),flush())
    else:
        receive=tunnel.receive;send=tunnel.send
    request=b''
    while b'\r\n\r\n' not in request:request+=receive()
    lines=request.decode().split('\r\n');assert lines[0].startswith('GET /') and lines[0].endswith(' HTTP/1.1')
    headers=dict((line.split(':',1)[0].lower(),line.split(':',1)[1].strip()) for line in lines[1:] if ':' in line)
    if mode=='cross-target':assert 'authorization' not in headers and 'x-private-test' not in headers, 'Cross-origin redirect leaked credentials'
    else:assert headers.get('authorization')==TOKEN and headers.get('x-private-test')=='private-header'
    assert 'gzip' in headers.get('accept-encoding','')
    body=feed(mode)
    code=b'200 OK';extra=b''
    if mode=='status':code=b'503 Unavailable'
    if mode in ('redirect-same','redirect-cross','downgrade'):
        destination='/final' if mode=='redirect-same' else 'http://other.test:443/final'
        code=b'302 Found';extra+=b'Location: '+destination.encode()+b'\r\n';body=b''
    if mode=='bad-yaml':body=b'proxies: ['
    if mode=='oversize':body=b'X'*4096
    if mode=='gzip-bomb':body=b'X'*8192
    if mode in ('gzip','chunk-gzip','bad-gzip','gzip-bomb'):
        body=gzip.compress(body);extra+=b'Content-Encoding: gzip\r\n'
        if mode=='bad-gzip':body=body[:-3]
    if mode=='deflate':body=zlib.compress(body);extra+=b'Content-Encoding: deflate\r\n'
    if mode=='ambiguous':extra+=b'Transfer-Encoding: chunked\r\n'
    if mode in ('chunked','chunk-gzip','bad-chunk'):
        extra+=b'Transfer-Encoding: chunked\r\n';encoded=b''
        for i in range(0,len(body),37):
            part=body[i:i+37];encoded+=format(len(part),'x').encode()+b';fixture=yes\r\n'+part+b'\r\n'
        body=encoded+b'0\r\nX-Trailer: complete\r\n\r\n'
        if mode=='bad-chunk':body=b'ZZ\r\n'+body
    elif mode not in ('eof','eof-truncated-tls'):extra+=b'Content-Length: '+str(len(body)+(10 if mode=='truncated' else 0)).encode()+b'\r\n'
    response=b'HTTP/1.1 '+code+b'\r\n'+extra+b'Connection: close\r\n\r\n'+body
    if mode=='interim':response=b'HTTP/1.1 103 Early Hints\r\nLink: </fixture>\r\n\r\n'+response
    try:
        send(response)
        if secure and mode!='eof-truncated-tls':
            try:tls.unwrap()
            except ssl.SSLWantReadError:pass
            try:flush()
            except (BrokenPipeError,ConnectionResetError,ssl.SSLError):pass
        if mode=='eof' and kind.startswith('vmess'):
            padding=tunnel.mask.next()%64;nonce=tunnel.send_count.to_bytes(2,'big')+tunnel.iv[2:12]
            encrypted=tunnel.writer.encrypt(nonce,b'',None)
            wire.send(((len(encrypted)+padding)^tunnel.mask.next()).to_bytes(2,'big')+encrypted+b'P'*padding)
    except (BrokenPipeError,ConnectionResetError,ssl.SSLError):
        if mode not in ('oversize','gzip-bomb','ambiguous','bad-chunk','untrusted','status'):raise
    conn.close()
if __name__=='__main__':main()
