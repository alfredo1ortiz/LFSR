"""T-03: lectura/escritura binaria y XOR por bits, sin librerias externas.

Contrato con T-02: ``generator.clock()`` devuelve un bit (0 o 1) por invocacion.
Los bytes se procesan MSB-first. Para descifrar, usar OTRO generador con
exactamente el mismo estado inicial/taps (no reutilizar el generador avanzado).
"""
from __future__ import annotations
from pathlib import Path
from typing import Protocol


class BitGenerator(Protocol):
    def clock(self) -> int: ...


def read_binary(path: str | Path) -> bytes:
    """Lee archivo completo; para archivos grandes, preferir xor_file."""
    return Path(path).read_bytes()


def write_binary(path: str | Path, data: bytes) -> None:
    Path(path).write_bytes(data)


def xor_bytes(data: bytes, generator: BitGenerator) -> bytes:
    """Cifra/descifra bytes con un bit del flujo por bit del mensaje."""
    output = bytearray(len(data))
    for position, original_byte in enumerate(data):
        mask = 0
        for shift in range(7, -1, -1):
            bit = generator.clock()
            if bit not in (0, 1):
                raise ValueError('El generador debe devolver solo bits 0 o 1')
            mask |= bit << shift
        output[position] = original_byte ^ mask
    return bytes(output)


def xor_file(
    input_path: str | Path,
    output_path: str | Path,
    generator: BitGenerator,
    chunk_size: int = 65536,
) -> int:
    """Procesa .bin por bloques; devuelve cuantos bytes se transformaron."""
    source = Path(input_path)
    target = Path(output_path)
    if chunk_size < 1:
        raise ValueError('chunk_size debe ser positivo')
    if source.resolve() == target.resolve():
        raise ValueError('Las rutas de entrada y salida no pueden coincidir')
    total = 0
    with source.open('rb') as fin, target.open('wb') as fout:
        while True:
            block = fin.read(chunk_size)
            if not block:
                break
            fout.write(xor_bytes(block, generator))
            total += len(block)
    return total
