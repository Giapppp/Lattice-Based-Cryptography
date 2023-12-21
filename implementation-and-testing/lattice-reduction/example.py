#From Aero CTF 2020 - Magic II
#!/usr/bin/env python3.7

from typing import List
from random import getrandbits
from operator import ior, mul
from functools import reduce
from itertools import starmap


class Random(object):
    def __init__(self, seed: int, size: int=None):
        self._size = size or seed.bit_length()
        self._state = seed
        return

    def randint(self, bitsize: int) -> int:
        return reduce(ior, (self._getbit() << i for i in range(bitsize)))

    @classmethod
    def create(cls, size: int) -> 'Random':
        seed = getrandbits(size)
        return cls(seed, size)
        
    def _getbit(self) -> int:
        buffer = 2 * self._state | self._state >> (self._size - 1) | self._state << (self._size + 1)
        self._state = reduce(ior, ((buffer >> i & 7 in [1, 2, 3, 4]) << i for i in range(self._size)))
        return self._state & 1


def create_potion(ingredients: List[int], amounts: List[int]) -> int:
    magic_constant = 1046961993706256953070441
    effect = sum(starmap(mul, zip(ingredients, amounts)))
    side_effect = getrandbits(13) ^ getrandbits(37)
    return (effect + side_effect) % magic_constant


def main():
    from secret import FLAG
    security_level = 64
    ingredients_count = 12
    random = Random.create(security_level)
    potions_count = int.from_bytes(FLAG, 'big') ^ random.randint(512)
    print(f'There are {potions_count} famous potions in the world. We are trying to create something new!')
    ingredients = [random.randint(security_level) for _ in range(ingredients_count)]
    while True:
        amounts = [getrandbits(41) for _ in range(len(ingredients))]
        effect = create_potion(ingredients, amounts)
        print(f'A potion with {amounts} amounts of ingregients has {effect} value of effect.')
        choice = input('Would you like to create another potion? (y/n): ')
        if not choice.lower().startswith('y'):
            break
    return


if __name__ == '__main__':
    main()
