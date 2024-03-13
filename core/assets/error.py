from core.assets.colors import red,green,blue,yellow


#error 
def ERROR(E):
    print(red(f"[-] {E}"))
    exit(1)

#alerta de print
def WARN(W):
    print(yellow(f"[!] {W}"))


# mensasggem
def MSG(M):
    print(green(f"[+] {M}"))


# info
def INFO(I):
    print(blue(f"[*] {I}"))
