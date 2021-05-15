from pwn import *

elf = ELF("./login")
REMOTE = 0
DEBUG = 1
if REMOTE:
    r = remote('pwnable.kr', 9003)
elif DEBUG:
    gs = """
    continue
    """
    r = gdb.debug(elf.path, gdbscript=gs)
else:
    r = process(elf.path)

