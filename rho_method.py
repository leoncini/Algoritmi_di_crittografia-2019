#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Apr  5 23:52:26 2019

@author: mauro
"""

def kMD5(x,k=6):
    '''
        Restricted version of MD5 hash function,
        to be used to illustrate (without incurring
        in too high running times) the Rho method for finding
        collisions
    '''
        
    from Crypto.Hash import MD5
    h = MD5.new()
    h.update(x)
    y = h.digest()[:k]
    return y

def FindTail(x0, H):
    '''
        Finds the tail of the rho.
        First finds the index i such that H^i(x0)=H^2i(x0)
        Since i = 2i-i, it follows that i is a multiple of the
        cycle length. But then, two sequences starting at x0 and
        at y = H^i(x0) will necessarily meet at first point of the cycle
        Counting the number of iterations gives precisely the tail length.
    '''
    i = 1
    x1 = H(x0)
    x2 = H(H(x0))
    while x1 != x2:
        x1 = H(x1)
        x2 = H(H(x2))
        i += 1
    x1 = x0
    i = 0
    while x1 != x2:
        x1 = H(x1)
        x2 = H(x2)
        i += 1
    return i,x1

def FindCycle(start, H):
    '''
        Start is any point already within the cycle
        Not used (and not useful...) to find a collision
    '''
    i = 1
    x = H(start)
    while x != start:
        x = H(x)
        i += 1
    return i
    
def FindCollision(x0, H):
    ''' "Structured" algorithm to find a collision for the
         function H. First find the "junction" point (i.e., the 
         point in the tail that is also in the cycle), and then
         find the two different predecessors. Less efficient
         than GetCollision
    '''
    l,xjoin = FindTail(x0, H)
    xcurr = x0
    xnext = H(x0)
    while xnext != xjoin:
        xcurr = xnext
        xnext = H(xcurr)
    x1 = xcurr
    xcurr = xnext
    xnext = H(xcurr)
    while xnext != xjoin:
        xcurr = xnext
        xnext = H(xcurr)
    x2 = xcurr
    return x1,x2

def GetCollision(x0, H):
    ''' Finds a collision for the hash function H.
        With respect to FindCollision is more efficient since
        it finds the collision while detecting the junction point
    '''
    i = 1
    x1 = H(x0)
    x2 = H(H(x0))
    while x1 != x2:
        x1 = H(x1)
        x2 = H(H(x2))
        i += 1
    # The final value of index i is an integer multiple of the cycle length.
    # It follows that two iterations starting one at xi and one again at x0
    # will meet precisely at the junction point
    # To detect the colliding values it is clearly crucial to always
    # keep the predecessors of the values being compared
    x1prec = x0
    x1 = H(x1prec)
    x2prec = x2
    x2 = H(x2prec)
    while x1 != x2:
        x1prec = x1
        x1 = H(x1prec)
        x2prec = x2
        x2 = H(x2prec)
    return x1prec, x2prec