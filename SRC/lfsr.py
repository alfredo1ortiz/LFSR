class LFSR:
    def __init__(self, taps: list, initial_state: list):
        self.taps = taps
        self.state = list(initial_state)
        self.L = len(initial_state)

        if all(bit == 0 for bit in self.state):
            raise ValueError("Error: El estado inicial no puede ser todo ceros (LFSR congelado).")

    def clock(self) -> int:
        feedback = 0
        for tap in self.taps:
            feedback ^= self.state[tap]

        out = self.state[-1]
        self.state = [feedback] + self.state[:-1]
        return out

    def generate_keystream(self, length: int) -> list:
        return [self.clock() for _ in range(length)]

    def validate_max_period(self) -> int:
        initial = list(self.state)
        period = 0
        max_limit = (1 << self.L) - 1
        while True:
            self.clock()
            period += 1
            if self.state == initial or period > max_limit:
                break
        return period


def build_hankel_matrix(keystream_sample: list, L: int):
    if len(keystream_sample) < 2 * L:
        raise ValueError(f"Se requieren al menos {2*L} bits de keystream.")

    M = []
    for i in range(L):
        M.append([keystream_sample[i + j] for j in range(L)])

    v = [keystream_sample[L + i] for i in range(L)]
    return M, v


def gaussian_elimination_gf2(M: list, v: list) -> list:
    rows = len(M)
    cols = len(M[0])

    A = [M[i][:] + [v[i]] for i in range(rows)]

    r = 0
    for c in range(cols):
        pivot = -1
        for i in range(r, rows):
            if A[i][c] == 1:
                pivot = i
                break
        if pivot == -1:
            continue

        A[r], A[pivot] = A[pivot], A[r]

        for i in range(rows):
            if i != r and A[i][c] == 1:
                for j in range(cols + 1):
                    A[i][j] ^= A[r][j]
        r += 1
        if r == rows:
            break

    return [A[i][-1] for i in range(cols)]


def break_lfsr(keystream_sample: list, L: int):
    M, v = build_hankel_matrix(keystream_sample, L)
    c_vec = gaussian_elimination_gf2(M, v)
    taps = [i for i, val in enumerate(c_vec) if val == 1]
    return taps, c_vec

def bytes_to_bits(data: bytes) -> list:
    return [(b>>i) & 1 for b in data  for i in range(7,-1,-1)]

def bits_to_bytes(bits:list) -> bytes:
    r= bytearray()
    for i in range (0,len(bits),8):
        byte = 0
        for bit in bits[i:i+8]:
            byte = (byte<< 1) | bit
        r.append(byte)
    return bytes(r)

def attack_lfsr(cipher_path: str, outh_path: str, know_header: bytes, L: int):
    with open (cipher_path, "rb") as f:
        cipher_bits= bytes_to_bits(f.read())

        know_bits = bytes_to_bits(know_header)
        if len(know_bits)<2 * L:
            raise ValueError(f"se ocupan {2*L} bits conocidos")

        keystream_muestra=[c^p for c, p in zip(cipher_bits[:2*L], know_bits[:2*L])]
        taps, c_vec = break_lfsr(keystream_muestra, L)
        print (f"Taps: {taps} y Vector c:{c_vec}")

        init_state= keystream_muestra[:L][::-1]
        cloned = LFSR(taps, init_state)

        full_ks = cloned.generate_keystream(len(cipher_bits))
        plain_bits=[c^k for c, k in zip(cipher_bits, full_ks)]

        with open(outh_path, "wb") as f:
            f.write(bits_to_bytes(plain_bits))

            
if __name__ == "__main__":
    # 1. Creamos un archivo cifrado de prueba automáticamente
    lfsr_emisor = LFSR([0, 2, 3, 4], [1, 0, 1, 1, 0, 0, 1, 0])
    mensaje = b"CABECERA_SECRETA: Todo el ataque LFSR funciona perfecto."
    bits_msg = bytes_to_bits(mensaje)
    ks = lfsr_emisor.generate_keystream(len(bits_msg))
    
    with open("archivo_cifrado.bin", "wb") as f:
        f.write(bits_to_bytes([m ^ k for m, k in zip(bits_msg, ks)]))

    # 2. Ejecutamos tu ataque para clonarlo y descifrarlo
    attack_lfsr("archivo_cifrado.bin", "archivo_descifrado.txt", b"CABECERA", L=8)
    print("Listo! Revisa el archivo 'archivo_descifrado.txt' en tu carpeta SRC.")
