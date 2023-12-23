from pwn import *
from arorage import attack

target = process(["python3", "example.py"])
for _ in range(4):
    target.recvline()

def get_sample():
    for _ in range(3):
        target.recvline()
    target.sendline(b"Q")
    samples = []
    for _ in range(12):
        recv = target.recvline().decode().split(": ")[1]
        samples.append(eval(recv))
    return samples

A = []
b = []
while len(b) < 2002:
    for sample in get_sample():
        A.append(sample[0])
        b.append(sample[1])

E = list(range(5))
s = attack(127, A, b, E)
print("CCTF{" + bytes(s).decode() + "}")
