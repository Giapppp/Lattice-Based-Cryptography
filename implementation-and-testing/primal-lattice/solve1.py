from pwn import *
import json
from tqdm import tqdm
from sage.all import *
from sage.modules.free_module_integer import IntegerLattice
import ast

# dimension
n = 64
# plaintext modulus
p = 257
# ciphertext modulus
q = 1048583
delta = int(round(q/p))

flen = len(b"crypto{????????????????????????}")
target = process(["python3", "example.py"])
target.recvline()

def oracle_1(idx:int):
    payload = json.dumps({"option":"get_flag","index":idx})
    target.sendline(payload.encode())
    data = ast.literal_eval(target.recvline().decode())
    return data

def oracle_2(message:int):
    payload = json.dumps({"option":"encrypt","message":message})
    target.sendline(payload.encode())
    data = ast.literal_eval(target.recvline().decode())
    return data

flag_As = []
flag_bs = []
for idx in tqdm(range(flen)):
    data = oracle_1(idx)
    flag_As += [json.loads(data["A"])]
    flag_bs += [int(data["b"])]

As = []
bs = []
sample = 90
for _ in tqdm(range(sample)):
    data = oracle_2(0)
    As += [json.loads(data["A"])]
    bs += [int(data["b"])]

A = Matrix(ZZ, n + 1 + sample, sample + 1)

for i in range(sample):
    A[0, i] = bs[i]

A[0, sample] = q

for i in range(n):
    for j in range(sample):
        A[i+1, j] = (As[j][i]) % q

for i in range(sample):
    A[i + n + 1, i] = q

Ard = A.LLL()
err = Ard[-1]
if err[-1] < 0:
    err = [e * -1 for e in err]

assert err[-1] == q
assert all([abs(e) <= 1 for e in err[:-1]])

for i in range(n):
    for j in range(sample):
        As[j][i] = (As[j][i])%q

A = Matrix(GF(q), As)
v = [b - e for b, e in zip(bs, err)]
v = vector(GF(q), v)
print("solving for S")
S = A.solve_right(v)
print("S", S)

K = GF(q)
flag = []
for idx in range(flen):
    A_ = vector(K, flag_As[idx])
    b_ = K(flag_bs[idx])
    x = int(b_ - S * A_)
    flag += [int(round(x/delta))]

print(bytes(flag))
