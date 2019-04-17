#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Apr 15 15:19:25 2019

@author: mauro
"""

def md5sum(m):
    ''' md5 w/out update 
         Internal block size is 64 bytes
         Output size id 16 bytes
    '''
    from hashlib import md5
    h = md5(m)
    return h.digest()

def sha1sum(m):
    ''' sha1 w/out update
        Internal block size is 64 bytes
        Output size id 20 bytes
    '''
    from hashlib import sha1
    h = sha1(m)
    return h.digest()

def sha256sum(m):
    ''' sha256 w/out update
        Internal block size is 64 bytes
        Output size id 32 bytes
    '''
    from hashlib import sha256
    h = sha256(m)
    return h.digest()

def hmac(key,m,H,bs,os):
    ''' Simple HMAC implementation.
        Requires:
            a secret key k (of arbitrary size),
            the hash function H to be used as a 'black box',
            the internal block size (in bytes) bs adopted by H,
            the output size (in bytes) of H
    '''
    from Crypto.Util.strxor import strxor
    opad = b'\x5c'*bs
    ipad = b'\x36'*bs
    if (len(key)>bs):
        key = H(bs) 
    if (len(key)<bs):
        key += b'\x00'*(bs-len(key))
    okey = strxor(key,opad)
    ikey = strxor(key,ipad)
    ihash = H(ikey+m)
    return H(okey+ihash)