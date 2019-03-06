#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys

CHSET = " '.,:;!?()abcdefghijklmnopqrstuvwxyzàèéìòù\n"

class NotSupportedSymbol(Exception):
    pass

ciphertext = ":òhìv..rxxzùhtzw'r,ùhtùòhzéhtzw'r'zùhuzhtv.r'v"

def encrypt(plaintext,key):
    '''Encryption simply works by "rotating" the alphabet key
       positions to right'''
    n = len(CHSET)
    key = key%n
    cyphertext = []
    for p in plaintext:
        if p in CHSET:
            i = CHSET.find(p)
            j = (i+key)%n   # Right-rotation
            c = CHSET[j]
            cyphertext.append(c)
        else:
            raise NotSupportedSymbol
    return ''.join(cyphertext)

def decrypt(cyphertext, key):
    '''Decryption is a corresponding "left-rotation" '''
    return encrypt(cyphertext,-key)

def main():
    ''' To be used from a shell '''
    if len(sys.argv) < 3:
        print("Usage: {} text key [decrypt_flag]".format(sys.argv[0]))
        sys.exit()

    try:
        key = int(sys.argv[2])
    except:
        raise ValueError(sys.argv[2]+" not an integer value")
    if len(sys.argv) == 4:
        plaintext = decrypt(sys.argv[1],key)
        return plaintext
    else:
        cyphertext = encrypt(sys.argv[1],key)
        return cyphertext
      

if __name__ == '__main__':
    print(main())