            
import base64
def parse_pem_public_key(pem_path: str) -> tuple:
    with open (pem_path, "r") as f:
        b64 = "".join(line.strip() for line in f if not line.startswith("-----"))

        der= base64.b64decode(b64)
        idx, ints =0, []

        while idx < len (der):
            tag = der[idx]
            first= der[idx+1]
            if first<0x80:
                length, next_idx = first, idx + 2
            else:
                nb= first & 0x7f
                length = int.from_bytes(der[idx+2:idx + 2 + nb], "big")
                next_idx=idx +2+nb
            if tag in (0x30, 0x03):
                idx = next_idx + (1 if tag == 0x03 else 0)
            elif tag == 0x02:
                ints.append(int.from_bytes(der[next_idx: next_idx + length], "big"))
                idx = next_idx + length
            else:
                idx= next_idx + length
                
        if len(ints) < 2:
            raise ValueError("no se encuentra N y E en el archivo")

        return ints[0], ints [1]
