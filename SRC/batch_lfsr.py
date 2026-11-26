import math
import glob
import os
from rsa_parser import parse_pem_public_key

def recover_private_key(N: int, e: int, p:int)-> dict:
    q=N//p
    phi=(p-1) * (q-1)
    d=pow(e, -1, phi)
    return {"N":N, "e": e, "p":p, "q":q, "d": d}

def batch_dgc_attack(folder_path:str) -> list:
    pem_files = sorted(glob.glob(os.path.join(folder_path, "*.pem")))
    keys=[]

    for path in pem_files:
        try:
            N, e = parse_pem_public_key(path)
            keys.append((os.path.basename(path),N,e))
        except Exception as err:
            print(f"[i] omitiendo {os.path.basename(path)}: {err}")
    

    compromised=[]
    n_keys= len (keys)

    for i in range(n_keys):
        for j in range (i+1, n_keys):
            name_i, N_i, e_i= keys[i]
            name_j, N_j, e_j = keys[j]

            if N_i == N_j:
                continue

            p = math.gcd(N_i, N_j)
            if p > 1:
                compromised.append({
                    "par": (name_i, name_j),
                    "primo_compartido": p,
                    name_i: recover_private_key(N_i, e_i, p),
                    name_j: recover_private_key(N_j, e_j, p),
                    })
        return compromised
