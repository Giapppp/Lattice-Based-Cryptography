from sage.all import *
import json

FLAG = b"crypto{Lattice-Reduction-Attack}"
assert len(FLAG) == 32
# dimension
n = 64
# plaintext modulus
p = 257
# ciphertext modulus
q = 1048583
delta = int(round(q/p))

V = VectorSpace(GF(q), n)
S = V.random_element()


def encrypt(m):
    A = V.random_element()
    e = randint(-1, 1)
    b = A * S + delta * m + e
    return A, b

def challenge(your_input):
    if 'option' not in your_input:
        return {"error": "You must specify an option"}

    if your_input["option"] == "get_flag":
        if "index" not in your_input:
            return {"error": "You must provide an index"}
            

        index = int(your_input["index"])
        if index < 0 or index >= len(FLAG) :
            return {"error": f"index must be between 0 and {len(FLAG) - 1}"}

        A, b = encrypt(FLAG[index])
        return {"A": str(list(A)), "b": str(int(b))}

    elif your_input["option"] == "encrypt":
        if "message" not in your_input:
            return {"error": "You must provide a message"}

        message = int(your_input["message"])
        if message < 0 or message >= p:
            return {"error": f"message must be between 0 and {p - 1}"}

        A, b = encrypt(message)
        return {"A": str(list(A)), "b": str(int(b))}

    return {"error": "Unknown action"}

print("Would you like to encrypt your own message, or see an encryption of a character in the flag?")
while True:
    action = json.loads(input())
    print(challenge(action))
