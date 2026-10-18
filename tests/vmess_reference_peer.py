#!/usr/bin/env python3
"""Independent VMess peer using Python cryptography/OpenSSL, not the production codec.
Only an inherited AF_UNIX socket is used. No listener, network access or real profile secret.
"""
import hashlib, hmac, struct, zlib, time, socket, ssl, sys, base64, uuid, errno
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

ID = uuid.UUID('11111111-2222-4333-8444-555555555555').bytes
PAYLOAD = bytes((i * 17 + 3) % 256 for i in range(6000))
RESPONSE = b'vmess-response:' + PAYLOAD[::-1]

def kdf(key, *paths):
    factory = hashlib.sha256
    for path in (b'VMess AEAD KDF', *paths):
        previous = factory
        # HMAC's hash factory must support .copy(), .digest(), .update(), block_size and digest_size.
        factory = lambda data=b'', previous=previous, path=path: hmac.new(path, data, previous)
    return factory(key).digest()

def alt_id(value):
    source = value + b'16167dc8-16b6-4e6d-b8bb-65dd68113a81'
    while True:
        result = hashlib.md5(source).digest()
        if result != value: return result
        source += b'533eff8a-4113-4b10-b5ce-0f5d76b98cd2'

def fnv(data):
    value = 2166136261
    for byte in data: value = ((value ^ byte) * 16777619) & 0xffffffff
    return value

class Mask:
    def __init__(self, iv): self.shake, self.offset = hashlib.shake_128(iv), 0
    def next(self):
        result = self.shake.digest(self.offset + 2)[self.offset:]; self.offset += 2
        return int.from_bytes(result, 'big')

class Wire:
    def __init__(self, conn): self.conn, self.ws, self.buffer = conn, False, b''
    def raw_exact(self, size):
        result = b''
        while len(result) < size:
            data = self.conn.recv(size - len(result))
            if not data: raise EOFError('Truncated peer data')
            result += data
        return result
    def frame(self, payload, opcode=2, final=True):
        length = len(payload)
        prefix = bytes([(0x80 if final else 0) | opcode])
        prefix += bytes([length]) if length < 126 else b'\x7e'+struct.pack('!H',length) if length < 65536 else b'\x7f'+struct.pack('!Q',length)
        self.conn.sendall(prefix + payload)
    def read_frame(self):
        a,b=self.raw_exact(2); assert a & 0x70 == 0 and b & 0x80, 'Client WebSocket frame must be masked'
        length=b & 127
        if length==126: length=int.from_bytes(self.raw_exact(2),'big')
        elif length==127: length=int.from_bytes(self.raw_exact(8),'big')
        assert length <= 8 * 1024 * 1024
        mask=self.raw_exact(4); data=self.raw_exact(length)
        return a&15,bytes(byte ^ mask[i%4] for i,byte in enumerate(data))
    def exact(self,size):
        if not self.ws: return self.raw_exact(size)
        while len(self.buffer)<size:
            opcode,data=self.read_frame()
            if opcode==8: raise EOFError('WebSocket closed')
            assert opcode==2, 'Expected binary client frame'
            self.buffer+=data
        result,self.buffer=self.buffer[:size],self.buffer[size:];return result
    def send(self,data):
        if self.ws: self.frame(data)
        else: self.conn.sendall(data)
    def upgrade(self, bad=False, path='/vmess?test=1'):
        request=b''
        while not request.endswith(b'\r\n\r\n'): request+=self.raw_exact(1)
        lines=request.decode().split('\r\n'); assert lines[0]=='GET '+path+' HTTP/1.1'
        headers=dict(line.split(': ',1) for line in lines[1:] if ': ' in line)
        assert headers['Host']=='cdn.test' and headers['X-Test']=='native-peer'
        accept=base64.b64encode(hashlib.sha1((headers['Sec-WebSocket-Key']+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest())
        if bad: accept=b'invalid'
        self.conn.sendall(b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Accept: '+accept+b'\r\n\r\n')
        self.ws=True

def decode_header(wire, alter, target_host="target.test", target_port=443, mux=False):
    auth=wire.exact(16); command_key=hashlib.md5(ID+b'c48619fe-8f02-49e0-b9e9-edf763e17e21').digest()
    if alter==0:
        auth_plain=Cipher(algorithms.AES(kdf(command_key,b'AES Auth ID Encryption')[:16]),modes.ECB()).decryptor().update(auth)
        assert int.from_bytes(auth_plain[12:],'big')==zlib.crc32(auth_plain[:12])
        assert abs(int.from_bytes(auth_plain[:8],'big')-time.time())<120
        encrypted_length=wire.exact(18); nonce=wire.exact(8)
        size=int.from_bytes(AESGCM(kdf(command_key,b'VMess Header AEAD Key_Length',auth,nonce)[:16]).decrypt(kdf(command_key,b'VMess Header AEAD Nonce_Length',auth,nonce)[:12],encrypted_length,auth),'big')
        command=AESGCM(kdf(command_key,b'VMess Header AEAD Key',auth,nonce)[:16]).decrypt(kdf(command_key,b'VMess Header AEAD Nonce',auth,nonce)[:12],wire.exact(size+16),auth)
    else:
        ids=[];prev=ID
        for _ in range(alter): prev=alt_id(prev);ids.append(prev)
        found=None
        for stamp in range(int(time.time())-65,int(time.time())+66):
            raw=stamp.to_bytes(8,'big')
            if any(hmac.digest(value,raw,'md5')==auth for value in ids):found=raw;break
        assert found is not None, 'Legacy auth must use configured alternate IDs'
        decryptor=Cipher(algorithms.AES(command_key),modes.CFB(hashlib.md5(found*4).digest())).decryptor()
        command=decryptor.update(wire.exact(38));count=0
        if command[37]!=3:
            command+=decryptor.update(wire.exact(3));kind=command[40]
            if kind==1: count=4
            elif kind==3: count=16
            else:
                assert kind==2;command+=decryptor.update(wire.exact(1));count=command[-1]
        command+=decryptor.update(wire.exact(count+(command[35]>>4)+4))
    assert command[0]==1 and command[36]==0 and (command[37]==3 if mux else command[37] in (1,2))
    if mux:
        assert len(command)==38+(command[35]>>4)+4, 'VMess Mux must not include a destination'
        assert int.from_bytes(command[-4:],'big')==fnv(command[:-4])
        return command
    assert int.from_bytes(command[38:40], 'big') == target_port
    if command[40] == 2:
        assert command[41]==len(target_host) and command[42:42+len(target_host)]==target_host.encode()
    else:
        import ipaddress
        address = ipaddress.ip_address(target_host)
        assert command[40] == (1 if address.version == 4 else 3)
        assert command[41:41 + len(address.packed)] == address.packed
    assert int.from_bytes(command[-4:],'big')==fnv(command[:-4])
    return command

def body_aead(key, security):
    if security==3:return AESGCM(key)
    if security==4:
        first=hashlib.md5(key).digest();return ChaCha20Poly1305(first+hashlib.md5(first).digest())
    return None

def read_request(wire, command, datagram_count=2, byte_limit=None):
    iv,key=command[1:17],command[17:33];options=command[34]; security=command[35]&15
    if not options&1:
        assert security==5
        return wire.exact(len(PAYLOAD))
    cipher=body_aead(key,security);mask=Mask(iv);counter=0;result=b'';packets=[]
    while True:
        encoded=int.from_bytes(wire.exact(2),'big')
        padding=mask.next()%64 if options&8 else 0
        size=encoded ^ mask.next() if options&4 else encoded
        assert size<=2048
        packet=wire.exact(size);packet=packet[:-padding] if padding else packet
        data=cipher.decrypt(counter.to_bytes(2,'big')+iv[2:12],packet,None) if cipher else packet
        counter+=1
        if not data:break
        if command[37]==2:
            packets.append(data)
            if len(packets)==datagram_count:return packets
        else:
            result+=data
            if byte_limit is not None and len(result)>=byte_limit:
                assert len(result)==byte_limit, 'Initial request crossed its expected application boundary'
                return result
    return result

def response_packet(command, alter, failure, data_chunks=None):
    digest=hashlib.sha256 if alter==0 else hashlib.md5
    key,iv=digest(command[17:33]).digest()[:16],digest(command[1:17]).digest()[:16]
    auth=command[33] ^ (1 if failure=='auth' else 0)
    header=bytes([auth,0,0,0])
    if alter==0:
        prefix=AESGCM(kdf(key,b'AEAD Resp Header Len Key')[:16]).encrypt(kdf(iv,b'AEAD Resp Header Len IV')[:12],len(header).to_bytes(2,'big'),None)
        prefix+=AESGCM(kdf(key,b'AEAD Resp Header Key')[:16]).encrypt(kdf(iv,b'AEAD Resp Header IV')[:12],header,None)
    else:prefix=Cipher(algorithms.AES(key),modes.CFB(iv)).encryptor().update(header)
    options=command[34];security=command[35]&15
    if not options&1:return prefix+(b''.join(data_chunks) if data_chunks is not None else RESPONSE)
    mask=Mask(iv);counter=0;cipher=body_aead(key,security)
    chunks=data_chunks if data_chunks is not None else [b'udp-response:0'+PAYLOAD[:512],b'udp-response:1'+PAYLOAD[-1024:],b''] if command[37]==2 else [RESPONSE[:37],RESPONSE[37:1500],RESPONSE[1500:],b'']
    for data in chunks:
        padding=mask.next()%64 if options&8 else 0
        encrypted=cipher.encrypt(counter.to_bytes(2,'big')+iv[2:12],data,None) if cipher else data
        if counter==0 and failure=='tag':encrypted=encrypted[:-1]+bytes([encrypted[-1]^1])
        size=len(encrypted)+padding
        if options&4:size^=mask.next()
        prefix+=size.to_bytes(2,'big')+encrypted+b'P'*padding;counter+=1
    if failure=='length':prefix=bytes([prefix[0]^1])+prefix[1:]
    return prefix

def main():
    fd,alter,transport,failure=int(sys.argv[1]),int(sys.argv[2]),sys.argv[3],sys.argv[4]
    conn=socket.socket(fileno=fd);conn.settimeout(8)
    if 'tls' in transport:
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        directory=Path(__file__).parent/'fixtures/vmess'
        context.load_cert_chain(directory/'server.pem',directory/'server-key.pem')
        context.set_alpn_protocols(['http/1.1'])
        names=[];context.sni_callback=lambda connection,name,ctx:names.append(name)
        try:conn=context.wrap_socket(conn,server_side=True)
        except ssl.SSLError:
            if failure.startswith('tls-reject-'):return
            raise
        assert names==['vmess.test']
    wire=Wire(conn)
    if 'ws' in transport:
        wire.upgrade(failure=='ws-accept')
        if failure=='ws-accept':return
    command=decode_header(wire,alter)
    request=read_request(wire,command)
    expected=[PAYLOAD[:512],PAYLOAD[-1024:]] if command[37]==2 else PAYLOAD
    assert request==expected, 'VMess request payload or datagram boundaries were not preserved'
    packet=response_packet(command,alter,failure)
    if wire.ws:
        wire.frame(b'ping-payload',9)
        wire.frame(packet[:11],2,False);wire.frame(packet[11:89],0,False);wire.frame(packet[89:],0,True)
        opcode,pong=wire.read_frame();assert opcode==10 and pong==b'ping-payload'
    else:
        # Cross TCP/TLS read boundaries; no production helper is used by this peer.
        try:
            for i in range(0,len(packet),23):conn.sendall(packet[i:i+23])
        except OSError as error:
            # macOS may report ENOTCONN when the client has already rejected the deliberately bad frame.
            if failure not in ('length','auth','tag') or error.errno not in (errno.EPIPE,errno.ECONNRESET,errno.ENOTCONN):raise
    conn.close()

if __name__=='__main__':main()
