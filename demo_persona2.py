"""Ejecutar:demo_persona2.py para funcionar jeje"""
from pathlib import Path
from tempfile import TemporaryDirectory
from hashlib import sha256
from src.binary_io import write_binary, read_binary, xor_file
from src.rsa_core import gcd, extended_gcd, modular_inverse, square_multiply, crt
from src.fermat_attack import fermat_decrypt


class DemoBits:
    def __init__(self):
        self.bits = [1, 0, 1, 1, 0, 0, 1, 0]
        self.i = 0

    def clock(self):
        bit = self.bits[self.i % len(self.bits)]
        self.i += 1
        return bit


print('=== T-03: manejo binario y XOR reversible ===')
with TemporaryDirectory() as folder:
    plain, encrypted, restored = [Path(folder) / name for name in ['plain.bin', 'cipher.bin', 'restored.bin']]
    write_binary(plain, b'\x00\xffCabecera de prueba\x00')
    xor_file(plain, encrypted, DemoBits(), chunk_size=3)
    xor_file(encrypted, restored, DemoBits(), chunk_size=5)
    print('SHA-256 original  :', sha256(read_binary(plain)).hexdigest())
    print('SHA-256 recuperado:', sha256(read_binary(restored)).hexdigest())
    print('Son identicos     :', read_binary(plain) == read_binary(restored))

print('\n=== T-07: Euclides e inverso modular ===')
print('gcd(240,46) =', gcd(240, 46))
print('extended_gcd(240,46) =', extended_gcd(240, 46))
print('17^-1 mod 3120 =', modular_inverse(17, 3120))

print('\n=== T-08: Square-and-Multiply + CRT ===')
print('4^13 mod 497 =', square_multiply(4, 13, 497))
print('CRT([2,3,2], [3,5,7]) =', crt([2, 3, 2], [3, 5, 7]))

print('\n=== T-10: Fermat y recuperacion de RSA de prueba ===')
p, q, e = 1000000007, 1000000009, 65537
n = p * q
plaintext = b'HOLA'
c = square_multiply(int.from_bytes(plaintext, 'big'), e, n)
result = fermat_decrypt(n, e, c, original_size=len(plaintext))
for name in ('p', 'q', 'd', 'steps', 'message_bytes'):
    print(f'{name}: {result[name]}')
