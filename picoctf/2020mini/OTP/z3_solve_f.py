from z3 import *

xor = "a5d47ae6ffa911de9d2b1b7611c47a1c43202a32f0042246f822c82345328becd5b8ec4118660f9b8cdc98bd1a41141943a9"

def jumble(a1):
    v2 = If(a1 > 96, a1 + 9, a1)
    v3 = 2 * (v2%16)
    v3 = If(v3 > 15, v3 + 1, v3)
    return v3

desired = "lfmhjmnahapkechbanheabbfjladhbplbnfaijdajpnljecghmoafbljlaamhpaheonlmnpmaddhngbgbhobgnofjgeaomadbidl"
flag_len = 0x64
solver = Solver()

flag = [BitVec(f'flag_char{i}',8) for i in range(flag_len)]
solved = [""]*100

for k in flag:
    solver.add(Or(And(k >= ord("0"), k <= ord("9")),And(k >= ord("a"), k<=ord("f"))))

for i in range(flag_len):
    if i == 0:
        solved[i] = jumble(flag[i]) % 16
    else:
        v4 = jumble(flag[i])
        v5 = solved[i-1] + v4
        v6 = solved[i-1] + v4
        v6 = v6 >> 31
        v6 = v6 >> 28
        solved[i] = (v6 + v5) & 0xf
        solved[i] = solved[i] - v6

for i in range(len(solved)):
    solved[i] += 97
    
for x,y in zip(desired,solved):
    solver.add(ord(x)==(y))

solver.check()
model = solver.model()
flag_s =  "".join(chr(model.evaluate(x).as_long())for x in flag)
print(f"key = {flag_s}\n")
print("flag",end=": ")
for x,y in zip(bytes.fromhex(xor),bytes.fromhex(flag_s)):
    print(chr(x^y),end="")
print("\n\nbruh")

