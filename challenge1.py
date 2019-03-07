
# Brute force approch, i.e., try all possible keys

from caesar import CHSET, decrypt

C = ":òhìv..rxxzùhtzw'r,ùhtùòhzéhtzw'r'zùhuzhtv.r'v"

for k in range(len(CHSET)):
    print(k, decrypt(C,k))

