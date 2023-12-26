#Source: https://hackmd.io/@hakatashi/B1OM7HFVI

#Just lattice part! 
from sage.all import *
from sage.modules.free_module_integer import IntegerLattice
from random import randint
import sys
from itertools import starmap
from operator import mul
from pwn import *
import re

# Babai's Nearest Plane algorithm
# from: http://mslc.ctf.su/wp/plaidctf-2016-sexec-crypto-300/
def Babai_closest_vector(M, G, target):
  small = target
  for _ in range(1):
    for i in reversed(range(M.nrows())):
      c = ((small * G[i]) / (G[i] * G[i])).round()
      small -= M[i] * c
  return target - small

m = 100
n = 12
q = 1046961993706256953070441

target = process(["python3", "example.py"])
target.recvline()
A_values = []
b_values = []

A_pattern = re.compile(r'\[.*?\]')
b_pattern = re.compile(r'\d+ ')
for _ in range(100):
  recv = target.recvline().decode()
  A_value = eval(A_pattern.search(recv).group())
  b_value = int(b_pattern.search(recv).group())
  A_values.append(A_value)
  b_values.append(b_value)
  target.sendlineafter(b"Would you like to create another potion? (y/n):", b"y")

print(len(A_values))

A = matrix(ZZ, m + n, m)
for i in range(m):
  A[i, i] = q
for x in range(m):
  for y in range(n):
    A[m + y, x] = A_values[x][y]
lattice = IntegerLattice(A, lll_reduce=True)
print("LLL done")
gram = lattice.reduced_basis.gram_schmidt()[0]
target = vector(ZZ, b_values)
res = Babai_closest_vector(lattice.reduced_basis, gram, target)
print("Closest Vector: {}".format(res))

R = IntegerModRing(q)
M = Matrix(R, A_values)
ingredients = M.solve_right(res)

print("Ingredients: {}".format(ingredients))


