
class simuladorLFSR:
    def __init__(self, semilla: int, mascara:int):
        self.semilla=0
        self.mascara=0
        self.estado=0
        self.grado=0
        self.periodoM=0

        if mascara >=2 and semilla >= 0:
            self.mascara = mascara
            self.grado = mascara.bit_length()-1
            self.periodoM=(1<<self.grado) -1
            self.semilla=self._reducir_modulo(semilla)
            self.estado = self.semilla
        else:
            print("esta mal en algo")


    def _reducir_modulo(self, polinomio: int) -> int:
        while polinomio > 0 and (polinomio.bit_length() -1 )>= self.grado:
            desplazamiento = (polinomio.bit_length() -1) - self.grado
            polinomio ^= (self.mascara << desplazamiento)
        return polinomio
    def reiniciar(self) -> None:
        self.estado = self.semilla

    def paso(self) -> int:
        self.estado = self.estado<<1
        bit_s= (self.estado >> self.grado) & 1
        if bit_s == 1:
            self.estado = self.estado ^ self.mascara
        return bit_s

    def validar_periodo_maximo(self)-> bool:
        self. reiniciar()
        if self.estado == 0:
            print("alertaaa: El LFSR esta congelado en 0 desde el inicio")
            return False
        estados_vistos= {self.estado:0}
        limite_pasos = (1 << self.grado)+1

        for i in range(1,limite_pasos):
            self.paso()

            if self.estado==0:
                print(f"Alerta:el LFSR se congelo con puros ceros en el paso {i}")
                return False
            if self.estado in estados_vistos:
                periodo_real = i- estados_vistos[self.estado]
                if periodo_real == self.periodoM:
                    print(f"Alcanzo el periodo maximo({periodo_real} de {self.periodoM})")
                    return True
                else:
                    print(f"No alcanzo el periodo maximo, solo se logro {periodo_real} de {self.periodoM}")
                    return False
        estados_vistos[self.estado]=i

        return False



if __name__ == "__main__":
    lfsr1= simuladorLFSR(0b0001, 0b10011)
    print("grado L:" ,lfsr1.grado)
    print("Periodo maximo esperado:", lfsr1.periodoM)
    print("estado inicial:", bin(lfsr1.estado))

    if lfsr1.validar_periodo_maximo():
        print ("LFSR valido de periodo maximo")

    lfsr2 = simuladorLFSR(0b0001, 0b11111)
    lfsr2.validar_periodo_maximo()
    print()

    lfsr3= simuladorLFSR(0b0001, 0b10000)
    lfsr3.validar_periodo_maximo()
