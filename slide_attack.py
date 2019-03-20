#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Mar 12 2019

@author: Mauro Leoncini
"""

def sanity_test(RandomTests = 10):
    ''' Simple sanity test for the encryption/decryption 
        algorithms of the ToyBC class '''
    from random import randint # We do not need crypto generators here
    for _ in range(RandomTests):
        cipher = ToyBC()
        # Generate a random string of random length 
        # from a subset of ascii chars
        plaintext = ''
        for __ in range(randint(8,32)):
            plaintext += chr(randint(32,90))
        ciphertext = cipher.encrypt(plaintext)
        cleartext = cipher.decrypt(ciphertext)
        if plaintext != cleartext:
            print(plaintext, ciphertext, cleartext, cipher._ToyBC__key,\
                  cipher._ToyBC__P)

def SlideAttack(encrypt, P, blksize=4, attempts=2**16):
    ''' Applies the slide attack to our simple block cipher 
        See: A. Biryukuv and D. Wagner, Slide Attacks, LNCS 1636 (1999).
        The attack scheme can be applied to other ciphers based 
        on Feistel blocks if the specific "solver" is provided '''

    from bisect import bisect_right
    
    def solve(X,Y,Z,P):
        ''' Solve for K the equation: X xor T = P(Z xor K) 
            X, Y, Z are assumed to by bytes, not bitarrays
        '''
        from utils.math import perm, InversePerm
        from bitarray import bitarray
        invP = InversePerm(P)
        bX = bitarray()
        bY = bitarray()
        bZ = bitarray()
        bX.frombytes(X)
        bY.frombytes(Y)
        bZ.frombytes(Z)
        K = perm(bX^bY,invP)^bZ
        return K.tobytes()
    
    def randompair(bytesize):
        ''' Generates a plaintext/ciphertext pair for randomly
            chosen plaintext
        '''
        from os import urandom
        PL = urandom(bytesize)
        PR = urandom(bytesize)
        C = encrypt(PL+PR)
        CL = C[:bytesize]
        CR = C[bytesize:2*bytesize]
        return PL,PR,CL,CR
    
    semiblksize = int(blksize/2)
    bitsize = semiblksize*8
    if not attempts:
        attempts = 2**bitsize   # By the birthday paradox
    # We are going to insert all the slid pair candidates
    keys = []
    others = []
    for _ in range(attempts):
        PL,PR,CL,CR = randompair(semiblksize)
        index = bisect_right(keys,PR+CL)
        keys = keys[:index]+[PR+CL]+keys[index:]
        others = others[:index]+[PL+CR]+others[index:]
    # Now we actually check whether among the random "plaintexts",
    # There is one that gave rise to a slid pair.
    for i, PC in enumerate(others):
        index = bisect_right(keys,PC)
        if index>0 and keys[index-1]==PC: # We've got a candidate slid pair
            Rprime0,LprimeN = keys[i][:semiblksize],keys[i][semiblksize:]
            R0,LN = PC[:semiblksize],PC[semiblksize:]
            L0,RN = others[index-1][:semiblksize],others[index-1][semiblksize:]
            K = solve(Rprime0,L0,R0,P)
            return K
            
class ToyBC:
    '''Class that implements a simple (i.e. toy) block
       cipher with ECB mode of operation. The very simple design allows
    '''
    blksize = 4
    expfactor = 1/2 #
    
    def __init__(self, key=None, P = None, rounds = 16):
        from utils.math import derangement
        from os import urandom
        from bitarray import bitarray
        if not key or \
            len(key) != int(ToyBC.expfactor*ToyBC.blksize*8): 
            self.__key = bitarray(endian='big')
            self.__key.frombytes(urandom(int(ToyBC.expfactor*ToyBC.blksize)))
        else:
            self.__key = key
        if not P:
            self.P = derangement(ToyBC.blksize*4) # 4 = 8/2...
        else:
            self.P = P
        self.rounds = rounds

    def __BCRound(self, L, R):
        ''' Implements a single round of our toy block cipher '''
        from utils.math import perm
        from copy import copy  
        T = copy(R)^self.__key         
        T = perm(T,self.P)
        L ^= T
        return L, R
    
    def __BlockCipher(self, block):
        '''
            Implements our toy block cipher.
            The algorithm both encrypts and decrypts using the same key.
        '''
        from copy import copy
        blksize = int(ToyBC.blksize*8/2)
        L = copy(block[:blksize])
        R = copy(block[blksize:])
        for _ in range(self.rounds):
            R, L = self.__BCRound(L,R)
        R.extend(L)
        return R  

    def encrypt(self, plaintext):
        from utils.padding import pad
        from bitarray import bitarray
        if type(plaintext)==type(''):
            plaintext = pad(plaintext.encode('ascii'), ToyBC.blksize)
        else:
            plaintext = pad(plaintext, ToyBC.blksize)
        ciphertext = bytes()
        for i in range(0,len(plaintext),ToyBC.blksize):
            pt = bitarray(endian='big')
            pt.frombytes(plaintext[i:i+ToyBC.blksize])
            ciphertext += self.__BlockCipher(pt).tobytes()
        return ciphertext
    
    def decrypt(self, ciphertext):
        from utils.padding import unpad
        from bitarray import bitarray
        ptb = bytes()
        for i in range(0,len(ciphertext),ToyBC.blksize):
            ct = bitarray(endian='big')
            ct.frombytes(ciphertext[i:i+ToyBC.blksize])
            ptb += self.__BlockCipher(ct).tobytes()
        ptb = unpad(ptb,ToyBC.blksize)
        try:
            plaintext = ptb.decode('ascii')
        except UnicodeDecodeError:
            plaintext = ptb
        return plaintext