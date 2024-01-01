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

mat = []
As = []
bs = []
samples = 120
for _ in tqdm(range(samples)):
    data = oracle_2(0)
    A = json.loads(data["A"])
    As.append(A)
    b = int(data["b"])
    bs.append(b)
    mat.append([b] + A)

#Build embedding matrix
Mat = Matrix(mat)
Mat = Mat.T

Mat = Mat.stack(diagonal_matrix(samples, [q] * samples))

Mat0 = zero_matrix(1, n)
Mat0 = Mat0.stack(diagonal_matrix(n, [1] * n))
Mat0 = Mat0.stack(zero_matrix(samples, n))

v = Matrix([q] + [0] * (n + samples))

B = Mat.T
B = B.stack(Mat0.T)
B = B.stack(v)

B = B.T
B = B.dense_matrix().change_ring(ZZ)
#LLL

Q = diagonal_matrix([2**24] * samples + [1] * (n + 1))

B *= Q
B = B.LLL()
B /= Q

for row in B:
    if abs(row[-1]) == q:
        small_vector = row
        break

SS = [-c for c in small_vector[samples:-1]]

K = GF(q)
S = vector(K, SS)

flag = []
for idx in range(flen):
    A_ = vector(K, flag_As[idx])
    b_ = K(flag_bs[idx])
    x = int(b_ - S * A_)
    flag += [int(round(x/delta))]

print(bytes(flag))
