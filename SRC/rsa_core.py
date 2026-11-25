"""T-07 y T-08: matematica de RSA para un laboratorio educativo.

"""
from __future__ import annotations
from collections.abc import Sequence


def gcd(a: int, b: int) -> int:
    """T-07. Maximo comun divisor por Euclides."""
    while b:
        a, b = b, a % b
    return abs(a)


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """T-07. Retorna (g,x,y) tales que a*x + b*y = g = gcd(a,b)."""
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    if old_r < 0:
        return -old_r, -old_s, -old_t
    return old_r, old_s, old_t


def modular_inverse(a: int, modulus: int) -> int:
    """T-07. Retorna x tal que a*x ≡ 1 (mod modulus)."""
    if modulus <= 1:
        raise ValueError('El modulo debe ser > 1')
    g, x, _ = extended_gcd(a, modulus)
    if g != 1:
        raise ValueError('No existe inverso modular: gcd != 1')
    return x % modulus


def rsa_private_from_factors(n: int, e: int, p: int, q: int) -> int:
    """T-07. Deriva d a partir de factores primos DISTINTOS p y q."""
    if p <= 1 or q <= 1 or p == q or p * q != n:
        raise ValueError('Factores distintos >1 deben satisfacer n=p*q')
    phi = (p - 1) * (q - 1)
    return modular_inverse(e, phi)


def square_multiply(base: int, exponent: int, modulus: int) -> int:
    """T-08. Calcula base^exponent mod modulus sin formar base^exponent."""
    if exponent < 0 or modulus <= 0:
        raise ValueError('Se requiere exponente >=0 y modulo >0')
    base %= modulus
    result = 1 % modulus
    while exponent:
        if exponent & 1:
            result = (result * base) % modulus
        base = (base * base) % modulus
        exponent >>= 1
    return result


def crt(residues: Sequence[int], moduli: Sequence[int]) -> tuple[int, int]:
    """T-08. CRT para modulos coprimos por pares; devuelve (x, producto)."""
    if not residues or len(residues) != len(moduli):
        raise ValueError('Las listas deben ser no vacias y del mismo tamaño')
    x, product = 0, 1
    for r, n in zip(residues, moduli):
        if n <= 1 or gcd(product, n) != 1:
            raise ValueError('Los modulos deben ser coprimos por pares y >1')
        delta = ((r - x) * modular_inverse(product, n)) % n
        x = (x + delta * product) % (product * n)
        product *= n
    return x, product


def decrypt_crt(ciphertext: int, p: int, q: int, d: int) -> int:
    """T-08. Descifrado RSA CRT, suponiendo p y q primos distintos."""
    if p <= 1 or q <= 1 or p == q or gcd(p, q) != 1:
        raise ValueError('p y q deben ser primos distintos (supuesto del llamador)')
    mp = square_multiply(ciphertext, d % (p - 1), p)
    mq = square_multiply(ciphertext, d % (q - 1), q)
    x, _ = crt([mp, mq], [p, q])
    return x


def int_to_bytes(value: int, length: int | None = None) -> bytes:
    """Convierte texto plano RSA a bytes; la longitud evita perder ceros iniciales."""
    if value < 0 or (length is not None and length < 0):
        raise ValueError('Entero y longitud no negativos requeridos')
    count = length if length is not None else max(1, (value.bit_length() + 7) // 8)
    return value.to_bytes(count, 'big')
