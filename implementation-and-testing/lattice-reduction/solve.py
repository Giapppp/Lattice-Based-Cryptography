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

flen = 32
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

def Babai_closest_vector(M, G, target):
    small = target
    for _ in range(1):
        for i in reversed(range(M.nrows())):
            c = ((small * G[i]) / (G[i] * G[i])).round()
            small -= M[i] * c
    return target - small

flag_As = []
flag_bs = []
for idx in tqdm(range(flen)):
    data = oracle_1(int(idx))
    flag_As += [json.loads(data["A"])]
    flag_bs += [int(data["b"])]

As = []
bs = []
sample = 90
for _ in tqdm(range(sample)):
    data = oracle_2(int(0))
    As += [json.loads(data["A"])]
    bs += [int(data["b"])]

p_ = pow(p, -1, q)
bs = [(b*p_)%q for b in bs]

A = Matrix(ZZ, n + sample, sample)
for i in range(sample):
  A[i, i] = q
for x in range(sample):
  for y in range(n):
    A[sample + y, x] = (As[x][y] * p_) % q
lattice = IntegerLattice(A, lll_reduce=True)
print("LLL done")
gram = lattice.reduced_basis.gram_schmidt()[0]
target = vector(ZZ, bs)
res = Babai_closest_vector(lattice.reduced_basis, gram, target)
print("Closest Vector: {}".format(res))

for x in range(sample):
  for y in range(n):
    As[x][y] = (As[x][y] * p_) % q

R = IntegerModRing(q)
M = Matrix(R, As)
S = M.solve_right(res)

K = GF(q)
flag = []
for idx in range(flen):
    A_ = vector(K, flag_As[idx])
    b_ = K(flag_bs[idx])
    x = int(b_ - S * A_) % q
    x = x if x < q//2 else x - q
    flag += [x%p]

print(bytes(flag))
