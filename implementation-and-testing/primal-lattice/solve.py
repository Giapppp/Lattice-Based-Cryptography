#Source: https://blog.maple3142.net/2023/11/05/tsg-ctf-2023-writeups/#learning-with-exploitation

from sage.stats.distributions.discrete_gaussian_integer import (
    DiscreteGaussianDistributionIntegerSampler,
)
from sage.crypto.lwe import LWE, samples
from sage.misc.prandom import randrange
from subprocess import check_output
from re import findall
from output import public_key, ciphertext


def flatter(M):
    # compile https://github.com/keeganryan/flatter and put it in $PATH
    z = "[[" + "]\n[".join(" ".join(map(str, row)) for row in M) + "]]"
    ret = check_output(["flatter"], input=z.encode())
    return matrix(M.nrows(), M.ncols(), map(int, findall(b"-?\\d+", ret)))


p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF
F = GF(p)
d = 100
n = 10
q = p // (2**64)
errsz = (q // d // 6).bit_length()


A, T = public_key
L = block_matrix(
    [
        [matrix(Zmod(p), A).T.echelon_form().change_ring(ZZ), 0],
        [matrix.zero(d - n, n).augment(matrix.identity(d - n) * p), 0],
        [matrix(ZZ, T), 1],
    ]
)
# for row in L:
#     print("".join(["*" if x else " " for x in row]))
bounds = [2**errsz] * d + [1]
K = p**2
Q = diagonal_matrix([K // x for x in bounds])
L *= Q
L = flatter(L)
L /= Q
err = vector(F, next(v[-1] * v for v in L if abs(v[-1]) == 1)[:-1])
private_key = matrix(F, A).solve_right(vector(F, T) - err)
print(private_key)


def decrypt(c, private_key):
    U, v = c
    return int(v - vector(F, U) * private_key + q // 2) // q

flag = b""
for ct in ciphertext:
    pt = decrypt(ct, private_key)
    flag += int(pt).to_bytes(8, "big")
print(flag)
