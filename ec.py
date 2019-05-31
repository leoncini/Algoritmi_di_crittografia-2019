#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue May 21 11:59:27 2019

@author: Mauro Leoncini

For teaching purposes only. Uses the simplest algorithms

Example usage:
    E = EllipticCurve(-4,0,227)
    P = pointsOnEC(E)
    print(len(P)) # Number of points of the curve y^2 = x^3-4x over Z_227
    228
    O = point(E)  # Point at infinity and group neutral element
    print(O)
    ∞
    SG, generators = primeOrderCyclicSubgroups(E) # Subgroups with prime orders
                                                  # and corresp. generators
    for C in SG:
        print(len(G))
    2
    2
    19
    3
    2
    n = len(SG[2])   # The largest prime order cyclic subgroup has order 19
    G = generator[2] # We get a corresponding generator 
    print(G)
    (27, 31)
    M = "A message"
    from Crypto.Random.random import randint
    d = randint(1,n-1)  # We pick the secret key at random
    P = G.scalarMult(d)  # Compute P = dG
    keys = {'password': d} 
    h, r, s = EC_sign(M,E,n,G,P,keys,'password')
    if EC_verify((r,s),h,E,n,G,P):
        print("Valid signature")
    else:
        print("Signature not valid")
    # To determine a modulus at least as large as 30000 with a prime order
    # subgroups at least as large as 1000, for the curve with a = -4 and b = 0,
    # you can use the following command
    p, primeOrder, numberOfPointsOnE = findModulus(30000,1000,-4, 0)
    # Then, after actually defining E, you can find a generator of the largest
    # prime order subgroup using
    G = findGenerator(E)
"""

from Crypto.Util.number import inverse 

class EllipticCurve:
    def __init__(self,a,b,p):
        self._a = a
        self._b = b
        self._p = p
    
    def includes(self, p):
        ''' Returns True if and only if point p lies on the curve '''
        if p.neutral():  
            return True  # The point at inifinity belongs to any curve
        x = p[0]%self._p
        y = p[1]%self._p
        x3 = (((x*x)%self._p)*x)%self._p
        y2 = (y*y)%self._p
        ax = (self._a*x)%self._p
        return (y2-x3-ax-self._b)%self._p == 0
    
    def getMod(self):
        ''' Returns the modulus of the underlying finite field Z_p '''
        return self._p
    
    def getParams(self):
        ''' Returns the parameters defining the curve '''
        return self._a,self._b,self._p
    
    def tangent(self,p):
        ''' Returns the slope of the tangent line to the
            curve at p
        '''
        z = inverse(2*p[1],self._p)
        return ((((3*p[0]*p[0])+self._a)%self._p)*z)%self._p
    
    def lineThrough(self,p,q):
        ''' Returns the slope of the line intersecting the curve
            at points p and q
        '''
        z = inverse(q[0]-p[0],self._p)
        return ((q[1]-p[1])*z)%self._p
            
class point(tuple):
    ''' Points of elliptic curves are 2-tuple of integers in the underlying
        field that satisfy the curve equation
    '''
    def __new__(cls, ec, x=-1, y=-1):
        ''' The point at infinity is represented as the pair (-1,-1) '''
        self = super().__new__(cls, (x, y))
        self._ec = ec
        if ec.includes(self):
            return self
        raise ValueError("Point does not belong to the curve")
            
    def neutral(self):
        ''' Point at infinity is the group neutral element '''
        return self[0]==-1 or self[1]==-1
    
    def __str__(self):
        ''' The point at infinity is printed as "∞" '''
        if self.neutral():
            return u"\u221E"
        return str(super().__str__())
        
    def __neg__(self):
        ''' -X returns the reflected point on the curve '''
        if self.neutral():
            return self
        p = self._ec.getMod()
        return(point(self._ec,self[0],(-self[1])%p))
        
    def __add__(self, other):
        ''' Implements point addition '''
        if self==other:
            if self.neutral():
                return self
            elif self==-other:   # Point is (0,0)
                return point(self._ec)
            else:
                m = self._ec.tangent(self)
        elif self.neutral():
            return other
        elif other.neutral():
            return self
        elif self == -other:
            return point(self._ec,-1,-1)
        else:
            m = self._ec.lineThrough(self,other)
        p = self._ec.getMod()
        x = ((m*m)%p -self[0]-other[0])%p
        y = (-((m*(x-self[0]))%p+self[1]))%p
        return point(self._ec,x,y)
    
    def scalarMult(self, k):
        ''' Computes k*self = self+self+...+self (k times)
        '''
        P = self
        while k>0 and not k&1:
            P = P+P
            k = k >> 1
        Q = P
        k = k >> 1
        while k>0:
            Q = Q+Q
            if k&1:
                P = P+Q
            k = k >> 1
        return P
    
def xf(x,a,b,m):
    ''' Right hand side of the curve equation '''
    z = ((x*x)%m*x)%m
    z = ((z+(a*x)%m)+b)%m
    return z

def index(a, x):
    ''' Utility function to locate the leftmost value equal to x
        in a sorted list
    '''
    from bisect import bisect_left
    i = bisect_left(a, x)
    if i != len(a) and a[i] == x:
        return i
    raise ValueError

def pointsOnEC(E):
    ''' Returns the list of the points on the curve. 
        Suitable only for very small values of the modulus
    '''
    from bisect import insort_left
    a,b,m = E.getParams() 
    squares = {0:0}
    squareindices = [0]
    for i in range(1,int((m+1)/2)):
        im = i**2%m
        insort_left(squareindices,im)
        squares[im]=i
    P = [point(E,-1,-1)]
    for x in range(m):
        p = xf(x,a,b,m)
        if p==0:
            P.append(point(E,x,0))
        else:
            try:
                i = index(squareindices,p)
                P.append(point(E,x,squares[p]))
                P.append(point(E,x,m-squares[p]))
            except ValueError:
                pass
    return P

def primeFactors(n):
    ''' Returns a list with the prime factors of n 
        in increasing order ''' 
    from Crypto.Util.number import isPrime
    from math import sqrt
    factors = []
    while not isPrime(n):
        found = False
        for d in range(2,int(sqrt(n))+1):
            if isPrime(d) and n%d == 0:
                if not d in factors:
                    factors.append(d)
                n = int(n/d)
                found = True
                break
        if not found:
            break
    if not n in factors:
        factors.append(n)
    return factors

def findModulus(nmin,pmin,a=4,b=0,checkEvery=50):
    ''' Find a suitable modulus n for the curve
        with the given parameters a and b. The modulus must be
        at least nmin with largest prime factor p>=pmin.
        Returns n, p, and the number np of point on the curve
    '''
    from Crypto.Util.number import isPrime
    check = nmin+checkEvery
    if not nmin&1:
        n = nmin+1
    else:
        n = nmin
    while True:
        if not isPrime(n):
            n += 2
            continue
        E = EllipticCurve(a,b,n)
        np = len(pointsOnEC(E))
        p = primeFactors(np)[-1]
        if p>=pmin:
            return n, p, np
        elif n>check:
            print("Attempting n >",check)
            check = n+checkEvery
        n += 2

def findGenerator(E):
    ''' Finds a generator for the largest prime subgroup of the
        group of all points on the curve. To do this, we pick a 
        random point P on the curve and check whether mP = O (the
        point at infinity), where m is the largest prime factor of
        n (the order of the group of curve points). If this happens,
        since m is prime, <P> must be the desired group.
        Otherwise we pick another random point P and repeat the
        same process
    '''
    from Crypto.Random.random import randint
    L = pointsOnEC(E)
    n = len(L)
    f = primeFactors(n)
    if len(f) == 1:                  # If n is prime (can this ever happen?)
                                     # then any element is a generator.
        return L[randint(0,n-1)]     # Pick one at random
    O = point(E)
    m = max(f)
    while True:
        g = L[randint(0,n-1)]
        if g.scalarMult(m) == O:
            return g

def primeOrderCyclicSubgroups(E):
    ''' Returns the different cyclic subgroups of points on E
        whose order is a prime number. Also returns the
        corresponding generators
    '''
    from Crypto.Util.number import isPrime
    L = pointsOnEC(E)
    S = []
    generators = []
    O = point(E)
    for p in L:
        x = point(E,p[0],p[1])
        order = 1
        y = O
        G = {O}
        while not (y+x == O):
            y = y+x
            G.add(y)
            order += 1
        if isPrime(order) and not G in S:
            S.append(G)
            generators.append(x)
    return S,generators

def cyclicSubgroup(x,E):
    ''' Returns the subgroup generated by x '''
    O = point(E)
    y = O
    G = [y]
    while not (y+x == O):
        y = y+x
        G.append(y)
    return G

def EC_sign(M,E,n,G,P,keys,password):
    ''' Must be called with G a generator of a prime order subgroup
        of the group of points on E, and n the corrseponding order
        Simple access to a dictionary (keyed with passwords) simulates
        retrieval of the secret key
    '''
    from Crypto.Random.random import randint
    from Crypto.Hash import SHA256
    h = int.from_bytes(SHA256.new(M.encode('utf-8')).digest(),'big')%n
    d = keys[password]
    while True: # Failures occurs only if the randomly chosen value of
                # k gives rise to a value of r such that r mod n = 0 or
                # s mod n = 0
        k = randint(1,n-1)
        kG = G.scalarMult(k)
        r = kG[0]%n
        if r == 0:
            continue
        k1 = inverse(k,n)
        s = ((h+r*d)*k1)%n
        if s != 0:
            break
    return h, r, s

def EC_verify(S,h,E,n,G,P):
    ''' Check the signature of the hashed message (h) '''
    r, s = S
    w = inverse(s,n)
    u = w*h
    v = w*r
    Q = G.scalarMult(u)+P.scalarMult(v)
    if Q[0]%n == r:
        return True
    else:
        return False
    




    