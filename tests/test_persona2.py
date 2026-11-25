"""Pruebas automatizadas para T-03, T-07, T-08 y T-10."""
import tempfile
import unittest
from pathlib import Path
from src.binary_io import read_binary, write_binary, xor_bytes, xor_file
from src.rsa_core import (
    gcd, extended_gcd, modular_inverse, rsa_private_from_factors,
    square_multiply, crt, decrypt_crt, int_to_bytes,
)
from src.fermat_attack import fermat_factor, fermat_decrypt


class CyclicBitStream:
    """Un flujo de prueba independiente de la clase LFSR de Persona 1."""
    def __init__(self, bits):
        self.bits = list(bits)
        self.cursor = 0

    def clock(self):
        bit = self.bits[self.cursor % len(self.bits)]
        self.cursor += 1
        return bit


class TestBinaryIO(unittest.TestCase):
    def test_xor_single_byte_msb_first(self):
        source = CyclicBitStream([1, 0, 1, 0, 1, 0, 1, 0])
        self.assertEqual(xor_bytes(b'\xff', source), b'\x55')

    def test_xor_twice_recovers_original(self):
        data = bytes(range(256))
        bits = [1, 1, 0, 0, 1, 0, 1, 0, 0, 1]
        encrypted = xor_bytes(data, CyclicBitStream(bits))
        self.assertEqual(xor_bytes(encrypted, CyclicBitStream(bits)), data)

    def test_file_round_trip_and_preserves_null_bytes(self):
        data = (b'\x00\xff\x00HOLA\x80' + bytes(range(256))) * 3
        with tempfile.TemporaryDirectory() as folder:
            paths = [Path(folder) / name for name in ('plain.bin', 'cipher.bin', 'restored.bin')]
            write_binary(paths[0], data)
            self.assertEqual(xor_file(paths[0], paths[1], CyclicBitStream([1, 0, 1]), 7), len(data))
            self.assertEqual(xor_file(paths[1], paths[2], CyclicBitStream([1, 0, 1]), 13), len(data))
            self.assertEqual(read_binary(paths[2]), data)

    def test_cannot_overwrite_input(self):
        with tempfile.TemporaryDirectory() as folder:
            f = Path(folder) / 'a.bin'
            write_binary(f, b'Hola')
            with self.assertRaises(ValueError):
                xor_file(f, f, CyclicBitStream([0]))

    def test_invalid_bit_rejected(self):
        with self.assertRaises(ValueError):
            xor_bytes(b'X', CyclicBitStream([2]))


class TestRSAMath(unittest.TestCase):
    def test_euclid(self):
        self.assertEqual(gcd(240, 46), 2)
        self.assertEqual(gcd(-240, 46), 2)

    def test_extended_euclid_bezout(self):
        a, b = 240, 46
        g, x, y = extended_gcd(a, b)
        self.assertEqual(g, 2)
        self.assertEqual(a*x + b*y, g)

    def test_mod_inverse(self):
        self.assertEqual(modular_inverse(17, 3120), 2753)

    def test_inverse_does_not_exist(self):
        with self.assertRaises(ValueError):
            modular_inverse(6, 12)

    def test_modular_power(self):
        self.assertEqual(square_multiply(4, 13, 497), 445)
        self.assertEqual(square_multiply(123456789, 987654321, 1000000007),
                         pow(123456789, 987654321, 1000000007))

    def test_crt(self):
        self.assertEqual(crt([2, 3, 2], [3, 5, 7]), (23, 105))

    def test_crt_rejects_common_factors(self):
        with self.assertRaises(ValueError):
            crt([1, 1], [6, 9])

    def test_rsa_small_example(self):
        p, q, e, m = 61, 53, 17, 65
        n = p*q
        d = rsa_private_from_factors(n, e, p, q)
        self.assertEqual(d, 2753)
        c = square_multiply(m, e, n)
        self.assertEqual(c, 2790)
        self.assertEqual(decrypt_crt(c, p, q, d), m)

    def test_int_to_bytes_with_leading_zeros(self):
        self.assertEqual(int_to_bytes(65, length=3), b'\x00\x00A')


class TestFermat(unittest.TestCase):
    def test_factor_close_primes(self):
        p, q = 1000000007, 1000000009
        a, b, steps = fermat_factor(p*q)
        self.assertEqual((a, b, steps), (p, q, 0))

    def test_factor_fails_at_zero_step_limit(self):
        with self.assertRaises(ValueError):
            fermat_factor(101 * 149, max_steps=0)

    def test_end_to_end_decrypt(self):
        p, q, e = 1000000007, 1000000009, 65537
        n = p*q
        msg = b'HOLA'
        encrypted = square_multiply(int.from_bytes(msg, 'big'), e, n)
        out = fermat_decrypt(n, e, encrypted, original_size=len(msg))
        self.assertEqual(out['message_bytes'], msg)
        self.assertEqual(out['p'] * out['q'], n)


if __name__ == '__main__':
    unittest.main()
