#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue May  7 12:00:26 2019

@author: mauro
"""

def extended_euclid(x,y):
    '''
    Implementa l'algoritmo di Euclide esteso
    '''
    if y==0:
        return x,1,0
    d,a,b = extended_euclid(y, x%y)
    return d,b,a-int(x/y)*b

def modexp(x,y,n):
    '''
    Implementa l'algoritmo di esponenziazione modulare: 
    calcola cioe' x^y mod n (dove il simbolo ^ indica l'elevamento a potenza)
    '''
    p = 1
    z = x%n
    while y>0:
        if y%2==1:
            p = (p*z)%n
        y = y >> 1
        z = (z*z)%n
    return p

def isprime(n):
    '''
    Usa il piccolo teorema di Fermat. Restituisce un risultato errato 
    (con bassa probabilita') se e solo se n e' pseudoprimo base 2,3 e 5
    '''
    for a in [2,3,5]:
        if modexp(a,n-1,n)>1:
            return False
    return True

def genprime(N):
    '''
    Genera un numero pseudocasuale e verifica se e' primo; 
    in caso contrario ripete il processo.
    '''
    from random import randint
    while True:
        n = randint(3,N-1)
        if n%2 == 1 and isprime(n):
            return n


def test(bitlen):
    '''
    Funzione di prova per "testare" le varie routine che
    formano il sistema RSA dimostrativo
    '''
    from random import randint
    maxN = 2**bitlen
    p = genprime(maxN)
    q = genprime(maxN)
    while q == p:           # Si vuole evitare il caso p=q
        q = genprime(maxN)
    N = p*q
    phi = (p-1)*(q-1)
    # Viene calcolato il primo valore "tentativo" per la chiave pubblica e
    # Tuttavia se MCD(e,phi)>1 allora bisogna provare un altro valore perche' e 
    # non ha inverso moltiplicativo modulo phi
    e = randint(1,(phi-2)/2)*2+1  # e deve essere dispari
    while True:
        m,d,c = extended_euclid(e,phi)
        if m==1:   # OK
            break
        e = randint(1,(phi-2)/2)*2+1 # riproviamo
    if d<0:
        d += phi  #Se d è negativo, dobiamo sommare phi per avere l'inverso
                  # nella forma "giusta"
    
    print("Prime factors: p="+str(p)+", q=",str(q))
    print("Public key: ("+str(e)+","+str(N)+")")
    print("Secret key: ("+str(d)+","+str(N)+")")

    msg = input("Enter message (number) to be encrypted (return to exit): ")
    while msg:
        M = int(msg)%N
        C = modexp(M,e,N)
        print("Cyphertext: "+str(C))
        msg = input("Enter next message (number) to be encrypted (return to exit): ")

