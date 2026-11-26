def egcd (a,b):
    if a== 0:
        return b, 0, 1
    gcd, x1, y1 = egcd(b % a,a)
    x= y1 - (b//a) * x1
    y = x1
    return gcd, x, y

def modinv (a,m):
    gcd, x, _ = egcd(a,m)
    if gcd != 1:
        raise ValueError("no existe inverso modular(los modulos no son coprimos)")
    return x % m

def crt(n1,n2,n3,c1,c2,c3):
    N=n1 * n2 * n3
    N1,N2,N3= n2 * n3, n1 * n3, n1 * n2

    u1= modinv(N1,n1)
    u2= modinv(N2,n2)
    u3 = modinv(N3,n3)

    return (c1 * N1 * u1 + c2 * N2 * u2 + c3 * N3 * u3) % N


def raiz_cubica_exacta(n):
    bajo, alto = 0,1
    while alto ** 3 <= n:
        alto *= 2
    while bajo<= alto:
        medio = (bajo + alto) // 2
        cubo = medio ** 3
        if cubo == n:
            return medio
        elif cubo < n:
            bajo = medio +1
        else:
            alto = medio -1
    raise ValueError("el numero no tiene una raiz cubica entera exacta")

def hastad_attack(n1, n2, n3, c1,c2,c3):
    m_cubo= crt (n1, n2, n3, c1, c2, c3)

    m= raiz_cubica_exacta(m_cubo)
    return m


if __name__ == "__main__":

    n1, n2, n3 = 1927, 187, 667
    c1, c2, c3 = 292, 146, 663

    mensaje_recuperado = hastad_attack(n1, n2, n3, c1, c2, c3)
    print(f"Mensaje entero (m): {mensaje_recuperado}")
    
    texto = mensaje_recuperado.to_bytes((mensaje_recuperado.bit_length() + 7) // 8, 'big').decode(errors='ignore')
    print(f"Mensaje en texto: {texto}")
