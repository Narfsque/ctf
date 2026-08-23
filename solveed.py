from pathlib import Path
import re
raw=bytes.fromhex('53514e437f42f66f47454d415354494b31397b6d3474685f31355f66756e5f756e74316c5f6c3376336c5f313030303030307d')
stored=int.from_bytes(raw[4:8],'little')
c=0xffffffff
for b in raw[8:]:
 c ^= b
 for _ in range(8):
  c=(c>>1)^ (0xedb88320 if c&1 else 0)
calc=c ^ 0xffffffff
calc_no_final=c
print('stored_native_le',hex(stored))
print('crc_loop_raw',hex(calc_no_final))
print('crc32_standard',hex(calc))
print('payload',raw[8:].decode())
print('match_native',c ^ stored == 0xffffffff)
