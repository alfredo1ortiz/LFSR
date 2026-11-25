"""T-10: factorizacion de Fermat para RSA con factores primos cercanos.

Solo para modulos de laboratorio donde p y q se escogen deliberadamente cerca.
El limite de intentos evita bloqueos ante llaves que no son vulnerables.
"""
from __future__ import annotations
from math import isqrt
from .rsa_core import decrypt_crt, int_to_bytes, rsa_private_from_factors


def fermat_factor(n: int, max_steps: int = 100_000) -> tuple[int, int, int]:
    """Busca n=a²-b², retorna (p,q,iteraciones) si lo consigue."""
    if n < 9 or n % 2 == 0 or max_steps < 0:
        raise ValueError('Se requiere n impar >=9 y max_steps >=0')
    a = isqrt(n)
    if a * a < n:
        a += 1
    for steps in range(max_steps + 1):
        b2 = a * a - n
        b = isqrt(b2)
        if b * b == b2:
            p, q = a - b, a + b
            if p > 1 and p * q == n:
                return p, q, steps
        a += 1
    raise ValueError(f'No se encontraron factores en {max_steps} incrementos')


def fermat_decrypt(
    n: int, e: int, ciphertext: int, max_steps: int = 100_000,
    original_size: int | None = None,
) -> dict[str, int | bytes]:
    """Recupera factores, d y mensaje sin padding de un reto RSA vulnerable."""
    if not 0 <= ciphertext < n:
        raise ValueError('El criptograma debe pertenecer al intervalo [0, n)')
    p, q, steps = fermat_factor(n, max_steps)
    d = rsa_private_from_factors(n, e, p, q)
    message = decrypt_crt(ciphertext, p, q, d)
    return {
        'p': p, 'q': q, 'd': d, 'steps': steps,
        'message_integer': message,
        'message_bytes': int_to_bytes(message, original_size),
    }
