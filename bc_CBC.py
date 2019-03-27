#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Feb  5 13:59:54 2019

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

class ToyBC:
    '''Class that implements a simple block cipher to play with.
       The cipher encrypts and decrypts utf-8 strings of arbitrary length
       using the CBC mode of operation.
       Block size is 32 bits and key size is 48 bits
       If no key size is provided (or if the key length is
       different from 48) a random key is generated using 
       os.urandom device.
       CBC mode requires a 32-bit Initialization Vector (IV)
       which is randomly generated at each encryption and
       then placed in front of the  ciphertext.
       Key schedule generates N block keys from the general
       key, where N=48/gcd(48,rot). By default rot=3 and hence
       the number of different block keys is 16. By design, the 
       block cipher (encryption and decryption) performs as many
       rounds as the number of block keys.
       Besides the key, our simple cipher makes use of a substitution
       table organized as 4 permutations of the set {0,1,...,15}
       Indexing works as in DES. With a six bit index, the first and
       last bits pick the permutation while the middle four bits index
       that permutation 
    '''
    blksize = 4 #Block size is 32 bits, key size is 48 bits
    expfactor = 3/2 # Key size is blksize*expfactor
    
    def __init__(self, key=None, IV=None, rot=3):
        from utils.math import RandPerm
        from utils.math import derangement
        from os import urandom
        from bitarray import bitarray
        assert rot>0
        if not key or \
            len(key) != int(ToyBC.expfactor*ToyBC.blksize*8): 
            self.__key = bitarray(endian='big')
            self.__key.frombytes(urandom(int(ToyBC.expfactor*ToyBC.blksize)))
        else:
            self.__key = key
        self.__rot = rot%(ToyBC.blksize*8)
        self.__P = derangement(ToyBC.blksize*4) # 4 = 8/2...
        self.__Sbox = []
        for i in range(4):
             self.__Sbox.append(RandPerm(16,self.__Sbox))
            
    def __expand(self, semiblock):
        ''' Expand the semiblock (from 16 to 24 bits)
            by reusing half the bits '''
        from bitarray import bitarray
        e = bitarray()
        for i in range(1,len(semiblock),2):
            e.append(semiblock[i])
            e.append(semiblock[(i+1)%len(semiblock)])
            e.append(semiblock[i]) 
        return e

    def __SBoxLookUp(self,bits):
        ''' S-Box lookup. The first and last input bits are treated
            as a binary number, which is then used to access the
            corrisponding table (a python dict) using the other four
            bits as the key
        '''
        index = int((bits[:1]+bits[5:]).to01(),2)
        return self.__Sbox[index][int(bits[1:5].to01(),2)]

    def __BCRound(self, L, R, rk):
        ''' Implements a single round of our toy (yet a little more serious)
           block cipher 
        '''
        from bitarray import bitarray
        from utils.math import perm
        T = self.__expand(R)
        T ^= rk
        S = bitarray()
        for i in range(0,len(T),6):
            S.extend(bitarray("{0:04b}".format(self.__SBoxLookUp(T[i:i+6]))))
        S = perm(S,self.__P)
        L ^= S
        return L, R   
    
    def __BlockCipher(self, block, blockkey):
        '''
            Implements our toy block cipher.
            len(block) must be equal to the length of round keys.
            The latter are given by blockkey, which is suppoded to be a
            generator (lists or other iterable work as well).
            Applies a series of rounds to block using the round keys and
            permutation P. The number of rounds is exactly the number of round
            keys eturned by the generator.
            Whether the algorithm encrypts or decrypts depends on the blockkey.
        '''
        from copy import copy
        blksize = int(ToyBC.blksize*8/2)
        L = copy(block[:blksize])
        R = copy(block[blksize:])
        for rk in blockkey:
            R, L = self.__BCRound(L,R,rk)
        R.extend(L)
        return R
    
    def __enc_keys(self):
        ''' Length of block key (a bitarray structure) must be equal to the length 
            of data blocks. The number of different round keys (hence of rounds) 
            is given by the quantity len(blockkey)/gcd(len(blockkey),rot). It 
            follows that the maximum number of different round keys is achieved
            when rot and length of blockkey are co-prime.
            The round keys are then simmply obtained by rotating the
            blockkey rot positions towards right at each request
        '''
        from copy import copy
        from math import gcd
        keysize = len(self.__key)
        bk = copy(self.__key)
        s = self.__rot
        for j in range(int(keysize/gcd(keysize,s))):
            bk[:s],bk[s:] = bk[keysize-s:],bk[:keysize-s]
            yield bk[:int(keysize/2)]

    def __dec_keys(self):
        ''' The only difference with enc_keys() is that the round keys
            are obtained by rotating the blockkey rot positions towards left 
            at each request. This gives the same keys but in reverse order.
        '''
        from copy import copy
        from math import gcd
        keysize = len(self.__key)
        bk = copy(self.__key)
        s = self.__rot
        yield bk[:int(keysize/2)]
        for j in range(int(keysize/gcd(keysize,s))-1):
            bk[keysize-s:],bk[:keysize-s] = bk[:s],bk[s:]
            yield bk[:int(keysize/2)]   
  
    def encrypt(self, plaintext):
        from utils.padding import pad
        from bitarray import bitarray
        from os import urandom
        IV = bitarray(endian='big')
        IV.frombytes(urandom(int(ToyBC.blksize)))
        plaintext = pad(plaintext.encode('utf-8'), ToyBC.blksize)
        ciphertext = bytes()
        C = IV
        for i in range(0,len(plaintext),ToyBC.blksize):
            pt = bitarray(endian='big')
            pt.frombytes(plaintext[i:i+ToyBC.blksize])
            f = self.__enc_keys()
            C = self.__BlockCipher(pt^C,f)
            ciphertext += C.tobytes()
        return (IV.tobytes()+ciphertext).hex()
    
    def decrypt(self, ciphertext):
        from utils.padding import unpad
        from bitarray import bitarray
        ptb = bytes()
        ciphertext = bytes.fromhex(ciphertext)
        C = bitarray(endian='big')
        C.frombytes(ciphertext[:ToyBC.blksize])
        for i in range(ToyBC.blksize,len(ciphertext),ToyBC.blksize):
            ct = bitarray(endian='big')
            ct.frombytes(ciphertext[i:i+ToyBC.blksize])
            g = self.__dec_keys()
            P = self.__BlockCipher(ct,g)^C
            C = ct
            ptb += P.tobytes()
        plaintext = unpad(ptb,ToyBC.blksize).decode('utf-8')
        return plaintext