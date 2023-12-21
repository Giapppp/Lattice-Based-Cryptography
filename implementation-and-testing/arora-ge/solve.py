#Source: https://11dimensions.moe/archives/267

from sage.all import *
from tqdm import tqdm
import pwn

server = 'some_ip_addr'

def get_new_batch(n):
    n = n // 12 + 1

    conn = pwn.remote(server, 30010)

    l = []

    for i in range(n):
        conn.sendline(b'Q')
    for i in range(n):
        conn.recvuntil(b'it\n')
        for i in range(12):
            s = conn.recvline().decode()
            l.append(s)

    conn.sendline(b'E')
    conn.close()
    return l

def enc(z):
    for con, mon in z:
        return (con, mon.degrees())

def dec(p, l):
    cons, degs = p
    for i, j in zip(degs, l):
        if i != 0:
            cons *= F(j)**i
    return cons

q = 127
n = 20
r = 3

F = GF(q)
Q = F[','.join([f'a{i}' for i in range(n)] + ['b'])]
aas = vector(Q.gens()[:-1])
bb = Q.gens()[-1]
T = Q[','.join([f'x{i}' for i in range(n)] + ['e'])]
g = vector(T.gens()[:-1])
ee = T.gens()[-1]
y = prod(1 + sum(g) + ee for _ in range(r)).monomials()
ff = prod(bb - aas * g - ee for _ in range(r))
pat = [ff.monomial_coefficient(z) for z in y]
ppat = [enc(p) for p in pat]
test = set(deg for _, deg in ppat)

print(len(y))
m = len(y)

count = 0
while True:
    print(f'Round {count}')
    count += 1

    inss = []
    for line in get_new_batch(m):
        _, ins = line.split(':')
        ins = eval(ins)
        inss.append(ins)

    cs = []

    for i in tqdm(range(m)):
        a, b = inss[i]
        a.append(b)
        cs.append([dec(p, a) for p in ppat])


    cs = matrix(cs)
    print(cs.rank())
    if (cs.rank() == m - 1):
        A = cs.right_kernel_matrix()

        v = vector(A)
        v /= v[-1]

        print(''.join(chr(i) for i in v[-2 - n:-2]))
        break
