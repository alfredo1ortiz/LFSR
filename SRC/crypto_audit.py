#!/usr/bin/env python3

import argparse
import sys

from lfsr import attack_lfsr
from hastad_lfsr import hastad_attack

def imprimir_resultado_rsa(m):
    print("resultado encontrado:")
    print(" valor entero (m)", m)

    longitud_bytes= (m.bit_length() + 7 ) // 8
    texto = m.to_bytes(longitud_bytes,"big").decode("utf-8", errors="ignore")
    print("texto decodificado", texto)

def menu_principal():
    while True:
        print("proyecto criptografia")
        print ("1. Ataque a LFSR")
        print ("2. Ataque RSA hastad")
        print("3. Salir")

        opcion = input("seleccione una opcion:")

        if opcion == "1":
            try:
                archivo_in = input("archivo cifrado:" )
                archivo_out = input ("archivo de salida:")
                cabecera = input ("cabecera conocida en hex (ej.89504e47): ")
                longitud = int(input("Longitud L del registro:"))

                cabecera_bytes = bytes.fromhex(cabecera)
                attack_lfsr(archivo_in, archivo_out, cabecera_bytes, longitud)
                print("archivo descifrado en: ", archivo_out)
            except Exception as e:
                print("error en LFSR:", e)
        elif opcion == "2":
            try:
                print("ingresa los valores(enteros o hexadecimal con 0x):")
                n1= int (input("n1: "), 0)
                n2= int (input("n2: "), 0)
                n3 = int (input("n3: "), 0)
                c1= int(input("c1: "),0)
                c2 = int (input("c2: "), 0)
                c3 = int (input("c3: "),0)

                m=hastad_attack(n1,n2,n3,c1,c2,c3)
                imprimir_resultado_rsa(m)
            except Exception as e:
                print("error en RSA",e)
        elif opcion == "3":
            print("saliendo del programa")
            break
        else:
            print("opcion no valida")



def main():
    if len(sys.argv) == 1:
        menu_principal()
        return

    parser = argparse.ArgumentParser(description="Herramienta de criptografia (LFSR y RSA)")
    subparsers= parser.add_subparsers(dest="ataque", required=True)

    parser_lfsr = subparsers.add_parser("lfsr", help="ataque cifrado de flujo LFSR")
    parser_lfsr.add_argument("-c", "--cipher", required= True, help="archivo de cifrado")
    parser_lfsr.add_argument("-o", "--out",required=True, help="archivo de salida")
    parser_lfsr.add_argument("-k","--key", required=True, help="cabecera conocida en hex")
    parser_lfsr.add_argument("-l", "--length", type = int, required= True, help= "longitud L")

    parser_rsa = subparsers.add_parser("hastad", help ="ataque de hastad con e=3")
    parser_rsa.add_argument("-n", nargs=3, required=True, help="los 3 modulos: n1, n2 y n3")
    parser_rsa.add_argument("-c", nargs=3, required=True, help="los 3 criptogramas: c1, c2 y c3")
    args= parser.parse_args()

    if args.ataque == "lfsr":
        cabecera_bytes = bytes.fromhex(args.key)
        attack_lfsr(args.cipher, args.out, cabecera_bytes, args.length)
        print("archivo descifrado guardado en:", args.out)
    elif args.ataque == "hastad":
        n1= int (args.n[0],0)
        n2= int (args.n[1],0)
        n3= int(args.n[2], 0)
        c1=int(args.c[0],0)
        c2=int(args.c[1],0)
        c3=int(args.c[2],0)

        m=hastad_attack(n1,n2,n3,c1,c2,c3)
        imprimir_resultado_rsa(m)


if __name__ == "__main__":
    main()
