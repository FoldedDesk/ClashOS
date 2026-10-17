#!/usr/bin/env python3
"""OpenSSL HTTPS endpoint inside an independently encoded DIRECT/SS/VMess tunnel."""
import sys, socket, ssl, os, hashlib, time
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from vmess_reference_peer import Wire, decode_header, Mask, kdf
from trojan_reference_peer import read_header, address as socks_address
from vless_reference_peer import read_header as read_vless_header
from forward_reference_peer import read_forward_header

class Tunnel:
    def __init__(self, wire, kind, alter, fault):
        self.wire,self.kind,self.send_count,self.read_count=wire,kind,0,0
        self.response_header=False
        target_host='192.0.2.9' if fault=='hosts' else 'wrong.test' if fault=='wronghost' else 'vmess.test'
        if kind.startswith('ss2022-'):
            from ss2022_reference_peer import Ss2022Tunnel
            self.ss2022 = Ss2022Tunnel(wire, kind[len('ss2022-'):], alter, target_host)
        elif kind.startswith('ss'):
            size=16 if kind=='ss-aes128' else 32
            algorithm=ChaCha20Poly1305 if kind=='ss-chacha' else AESGCM
            master=b''; previous=b''
            while len(master)<size:
                previous=hashlib.md5(previous+b'probe-password').digest();master+=previous
            salt=wire.exact(size)
            self.reader=algorithm(HKDF(algorithm=hashes.SHA1(),length=size,salt=salt,info=b'ss-subkey').derive(master[:size]))
            self.salt=bytes(range(size));self.writer=algorithm(HKDF(algorithm=hashes.SHA1(),length=size,salt=self.salt,info=b'ss-subkey').derive(master[:size]))
            address=self.receive()
            assert address==socks_address(target_host,443)
        elif kind.startswith('vmess'):
            self.command=decode_header(wire,alter,target_host)
            self.reader=AESGCM(self.command[17:33]);self.read_iv=self.command[1:17];self.read_mask=Mask(self.read_iv)
            digest=hashlib.sha256 if alter==0 else hashlib.md5
            self.key=digest(self.command[17:33]).digest()[:16];self.iv=digest(self.read_iv).digest()[:16]
            self.writer=AESGCM(self.key);self.mask=Mask(self.iv);self.alter=alter
        elif kind.startswith('trojan'):
            read_header(wire,target_host,password='probe-password')
        elif kind.startswith('vless'):
            read_vless_header(wire,target_host)
        elif kind.startswith('forward-'):
            assert read_forward_header(wire,kind.split('-')[1],target_host)
    def receive(self):
        if self.kind.startswith('ss2022-'):return self.ss2022.receive()
        if self.kind=='direct' or self.kind.startswith(('trojan', 'vless', 'forward-')):
            if self.wire.buffer:
                data,self.wire.buffer=self.wire.buffer,b''
                return data
            if self.wire.ws:
                opcode,data=self.wire.read_frame()
                if opcode==8:raise EOFError()
                assert opcode==2
                return data
            data=self.wire.conn.recv(16384)
            if not data:raise EOFError()
            return data
        if self.kind.startswith('ss'):
            nonce=self.read_count.to_bytes(12,'little');self.read_count+=1
            size=int.from_bytes(self.reader.decrypt(nonce,self.wire.exact(18),None),'big')
            nonce=self.read_count.to_bytes(12,'little');self.read_count+=1
            return self.reader.decrypt(nonce,self.wire.exact(size+16),None)
        encoded=int.from_bytes(self.wire.exact(2),'big');padding=self.read_mask.next()%64
        size=encoded^self.read_mask.next();data=self.wire.exact(size);data=data[:-padding] if padding else data
        nonce=self.read_count.to_bytes(2,'big')+self.read_iv[2:12];self.read_count+=1
        return self.reader.decrypt(nonce,data,None)
    def send(self,data):
        if self.kind.startswith('ss2022-'):self.ss2022.send(data);return
        if self.kind.startswith('vless'):
            if not self.response_header:self.wire.send(b'\0\0');self.response_header=True
            self.wire.send(data);return
        if self.kind=='direct' or self.kind.startswith(('trojan', 'forward-')):self.wire.send(data);return
        if self.kind.startswith('ss'):
            if not self.response_header:self.wire.send(self.salt);self.response_header=True
            for i in range(0,len(data),1500):
                part=data[i:i+1500];nonce=self.send_count.to_bytes(12,'little');self.send_count+=1
                packet=self.writer.encrypt(nonce,len(part).to_bytes(2,'big'),None)
                nonce=self.send_count.to_bytes(12,'little');self.send_count+=1
                packet+=self.writer.encrypt(nonce,part,None);self.wire.send(packet)
            return
        if not self.response_header:
            header=bytes([self.command[33],0,0,0])
            if self.alter==0:
                prefix=AESGCM(kdf(self.key,b'AEAD Resp Header Len Key')[:16]).encrypt(kdf(self.iv,b'AEAD Resp Header Len IV')[:12],b'\0\4',None)
                prefix+=AESGCM(kdf(self.key,b'AEAD Resp Header Key')[:16]).encrypt(kdf(self.iv,b'AEAD Resp Header IV')[:12],header,None)
            else:
                from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
                prefix=Cipher(algorithms.AES(self.key),modes.CFB(self.iv)).encryptor().update(header)
            self.wire.send(prefix);self.response_header=True
        for i in range(0,len(data),1500):
            part=data[i:i+1500];padding=self.mask.next()%64
            nonce=self.send_count.to_bytes(2,'big')+self.iv[2:12];self.send_count+=1
            encrypted=self.writer.encrypt(nonce,part,None)
            self.wire.send(((len(encrypted)+padding)^self.mask.next()).to_bytes(2,'big')+encrypted+b'P'*padding)

def context():
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.set_alpn_protocols(['http/1.1'])
    fixtures=Path(__file__).parent/'fixtures/vmess';ctx.load_cert_chain(fixtures/'server.pem',fixtures/'server-key.pem')
    return ctx

def main():
    fd,alter,kind,fault=int(sys.argv[1]),int(sys.argv[2]),sys.argv[3],sys.argv[4]
    conn=socket.socket(fileno=fd);conn.settimeout(5)
    if kind.endswith('-tls'):conn=context().wrap_socket(conn,server_side=True)
    wire=Wire(conn)
    if '-ws' in kind:wire.upgrade(path='/vless?test=1' if kind.startswith('vless') else '/trojan?test=1' if kind.startswith('trojan') else '/vmess?test=1')
    tunnel=Tunnel(wire,kind,alter,fault)
    incoming,outgoing=ssl.MemoryBIO(),ssl.MemoryBIO();ctx=context();names=[]
    ctx.sni_callback=lambda connection,name,selected:names.append(name)
    endpoint=ctx.wrap_bio(incoming,outgoing,server_side=True)
    def flush():
        data=outgoing.read()
        if data:tunnel.send(data)
    def drive(action):
        while True:
            try:result=action();flush();return result
            except ssl.SSLWantReadError:
                flush();data=tunnel.receive()
                if not data:raise EOFError()
                incoming.write(data)
    try:
        drive(endpoint.do_handshake)
        assert names==['wrong.test' if fault=='wronghost' else 'vmess.test']
        request=b''
        while b'\r\n\r\n' not in request:request+=drive(lambda:endpoint.read(4096))
        assert request.startswith(b'GET /probe?ok=1 HTTP/1.1\r\n')
        if fault=='hosts':assert b'\r\nHost: vmess.test:443\r\n' in request
        code=b'503 Service Unavailable' if fault=='status' else b'204 No Content'
        response=b'HTTP/1.1 '+code+b'\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'
        if fault=='slow':
            for byte in response:
                endpoint.write(bytes([byte]));flush();time.sleep(.025)
        else:
            endpoint.write(response);flush()
    except (ssl.SSLError,EOFError,BrokenPipeError,ConnectionResetError):
        if fault not in ('wronghost','untrusted','slow'):raise
    conn.close()
if __name__=='__main__':main()
