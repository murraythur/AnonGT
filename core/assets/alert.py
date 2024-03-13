from core.assets.colors import red,green,blue,yellow


#error
def ERROR(E):
    print(red(f"[-] {E}"))
    exit(1)

# alert
def WARN(W):
    print(yellow(f"[!] {W}"))


# menssage
def MSG(M):
    print(green(f"[+] {M}"))


# info
def INFO(I):
    print(blue(f"[*] {I}"))
