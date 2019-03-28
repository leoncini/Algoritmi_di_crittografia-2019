#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from datetime import datetime
from Crypto.Cipher import DES3
from Crypto import Random
from Crypto.Util.strxor import strxor

class ANSIX917:
    '''
    Class that implements the ANSI X9.17 cryptographic PRNG
    '''
    def __init__(self, keylen=24):  
        if keylen != 16 and keylen != 24:
            keylen = 16 # Either keying 1 or 2, resp.
        IV = Random.new().read(DES3.block_size) #Init vector 
        key = Random.new().read(keylen)
        self.__state = Random.new().read(8)
        # 8 bytes is DES block size and corresponds to the length of the
        # string with current time seconds and microseconds: format '%S%f'
        # A longer (but with much less entropy) time string has format
        # '%y-%m-%d %H:%M:%S.%f'. With the latter the block length would be 24                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             
        self.cipher = DES3.new(key, DES3.MODE_CBC, IV)

    def __iter__(self):
        return self
    
    def __next__(self):
        ts = datetime.now().strftime('%S%f')
        T = self.cipher.encrypt(ts)
        out = self.cipher.encrypt(strxor(T, self.__state))
        self.__state = self.cipher.encrypt(strxor(T, out))
        return out.hex()

def ANSIX9_17(keylen=16):
    '''Generator for the ANSI X9.17 cryptographic PRNG'''
    #try:
    #    assert(keylen == 24 or keylen == 16) # Either keying 1 or 2, resp.
    #except AssertionError:
    #    keylen=16
    if keylen != 16 and keylen != 24:
        keylen = 16 
    IV = Random.new().read(DES3.block_size) #Init vector 
    key = Random.new().read(keylen)
    S = Random.new().read(8)
    # 8 bytes is DES block size and corresponds to the length of the
    # string with current time seconds and microseconds: format '%S%f'
    # A longer (but with much less entropy) time string has format
    # '%y-%m-%d %H:%M:%S.%f'. With the latter the block length would be 24
    cipher = DES3.new(key, DES3.MODE_CBC, IV)
    while True:
        ts = datetime.now().strftime('%S%f')
        T = cipher.encrypt(ts)
        out = cipher.encrypt(strxor(T,S))
        S = cipher.encrypt(strxor(T,out))
        yield out.hex()
        
def series(x):
    s = 1
    while True:
        yield s
        s = 1+s*x
        

