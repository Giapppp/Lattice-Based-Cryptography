#From TSGCTF 2022 - Learning with Exploitation

from sage.stats.distributions.discrete_gaussian_integer import DiscreteGaussianDistributionIntegerSampler
from sage.crypto.lwe import LWE, samples
from sage.misc.prandom import randrange

p = 0xfffffffffffffffffffffffffffffffeffffffffffffffff
F = GF(p)
d = 100
n = 10
q = p // (2 ** 64)
D = DiscreteGaussianDistributionIntegerSampler(q // d // 6) # six sigma

lwe = LWE(n=n, q=p, D=D)

public_key = list(zip(*samples(m=d, n=n, lwe=lwe)))
private_key = lwe._LWE__s

def encrypt(m, public_key):
  A, T = public_key
  r = vector([F(randrange(2)) for _ in range(d)])
  U = r * matrix(A)
  v = r * vector(T) + m * q
  return U, v

def decrypt(c, private_key):
  U, v = c
  return int(v - U * private_key + q // 2) // q

with open('flag.txt', 'rb') as f:
  flag = f.read()
assert(len(flag) == 64)

print(f'{public_key = }')

ciphertext = []
for i in range(0, 64, 8):
  m = int.from_bytes(flag[i:i+8], 'big')
  c = encrypt(m, public_key)

  assert(decrypt(c, private_key) == m)

  ciphertext.append(c)

print(f'{ciphertext = }')
