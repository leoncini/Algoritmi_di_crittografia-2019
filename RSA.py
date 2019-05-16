#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue May 14 17:06:23 2019

@author: mauro
"""

from Crypto.Util import number

def div(x,n):
    '''
    Works as follows on the example case div(25,0)
    First computes the binary repr. of 25, B = [1,1,0,0,1]
    Then, starting from q,r=0,0 and scanning B from left to right, 
    computes:
        (0,0) x 2 --> (0,0) --> (0,1) {since B[0]=1}
        (0,1) x 2 --> (0,2) --> (0,3) {since B[1]=1}
        (0,3) x 2 --> (0,6)           {since B[2]=0}
                  --> (1,1)           {since 6 exceeds 5}
        (1,1) x 2 --> (2,2)           {since B[3]=0,
        (2,2) x 2 --> (4,4) --> (4,5) {since B[4]=1}
                            --> (5,0) {since 5 equals 5}
        
    '''
    B = []
    # We need the bits of x from left to right
    while x > 0:
        B.insert(0,x&1)
        x = x >> 1
    q,r = 0,0
    for b in B:
        q = q << 1
        r = r << 1
        if b:
            r += 1
        if r>=n:
            r = r-n
            q = q+1
    return q,r

def modprod(x,y,n):
    if y==0:
        return 0
    q, x = div(x,n) # We are interested in the remainder only
    q, y = div(y,n)
    s = 0
    while y>0:
      if y&1:
          q, s = div(s+x,n)
      q, x = div(x<<1,n)
      y = y >> 1
    return s

def modexp(x,y,n,progress=False):
    '''
    Implementa l'algoritmo di esponenziazione 
    modulare: calcola cioe' x^y mod n (dove il
    simbolo ^ indica l'elevamento a potenza)
    '''
    from math import log2
    p = 1
    q, z = div(x,n)
    while y>0:
        if progress:
            print('Approx {} bits of y remains to be processed'.\
                  format(int(log2(y))))
        if y&1:
            p = modprod(p,z,n)
        y = y >> 1
        z = modprod(z,z,n)
    return p

def rsakeys(numberofbits=30):
    p = number.getPrime(numberofbits)
    q = number.getPrime(numberofbits)
    n = p*q
    phi = (p-1)*(q-1)
    e = 3
    while number.GCD(e,phi)>1:
        e+=2
    d = number.inverse(e,phi)
    print(p,q)
    return e,d,n

def rsaencrypt(M,e,n,progress=False):
    if number.GCD(M,n)>1:
        raise ValueError('Not encryptable message')
    return modexp(M,e,n,progress)

def rsadecrypt(C,d,n,progress=False):
    return modexp(C,d,n,progress)

def commonModAttack(e,d,n):
    ''' Algorithm (explained in class) to recover the primes p and q
        given the key pair
    '''
    from math import log2
    r = e*d-1
    t = 0
    while not r&1:
        t += 1
        r = r >> 1
    numberOfAttempts = 1
    while True:
        g = number.getRandomInteger(int(log2(n)))
        p = number.GCD(g,n)
        if p>1:
            print("Hurry up to Vegas? It's your lucky day!")
            return p,div(n,p)[0]
        x = modexp(g,r,n)
        x2 = modprod(x,x,n)
        while x2 != 1:
            x = x2
            x2 = modprod(x,x,n)
        p = number.GCD(x-1,n)
        if p>1:
            print("Success after {} attempts".format(numberOfAttempts))
            return p,div(n,p)[0]
        numberOfAttempts += 1
        
        


'''
(Somewhat simplified) example of Key generation and message
exchange using the RSA implementation under Crypto modules
'''

'''
# Bob's (receiver's) protocol: Key generation
# Generate the private and public keys
from Crypto.PublicKey import RSA
key = RSA.generate(2048)
# Export the public key to a file
publicKey = key.publickey().exportKey()
f = open('BobKey.pem','wb')
f.write(publicKey)
f.close()
# Export the private key to a password protected file
privateKey = key.exportKey(passphrase='_A.V3ry.5tr0ng.Pa55w0rd_')
f = open('rsakey.pem','wb')
f.write(privateKey)
f.close()

# Alice's (sender's) protocol: encryption
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP 
#OAEP stands for Optimal Asymmetric Encryption Padding

# Prepare the message and import the receiver public key
message = 'Questo è un messaggio di prova'.encode('utf-8')
BobKey = RSA.importKey(open("BobKey.pem").read())
# Generate a symmetric key
symmetricKey = get_random_bytes(16)
# Create an object to encrypt under known standard
rsa = PKCS1_OAEP.new(BobKey)
# Encrypt the symmetric key using RSA
rsaEncryptedSymmKey = rsa.encrypt(symmetricKey)
# Encrypt the message using AES and the symmetric key 
IV = get_random_bytes(16)
aes = AES.new(symmetricKey, AES.MODE_CFB, IV)
encMessage = IV+aes.encrypt(message)
# Send the pair formed by the encrypted symmetric key and the
# encrypted message
toBob = (rsaEncryptedSymmKey,encMessage)

# Bob's (receiver's) protocol: decryption
rsaEncryptedSymmKey,encMessage=toBob
g = open('rsakey.pem','r')
key = g.read()
privateKey = RSA.importKey(key,passphrase='_A.V3ry.5tr0ng.Pa55w0rd_')
g.close()
rsa = PKCS1_OAEP.new(privateKey)
symmetricKey = rsa.decrypt(rsaEncryptedSymmKey)
IV = encMessage[:16]
aes = AES.new(symmetricKey, AES.MODE_CFB, IV)
decryptedMessage = aes.decrypt(encMessage)[16:]
'''