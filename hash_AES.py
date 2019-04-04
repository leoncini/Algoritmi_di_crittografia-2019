#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Apr  3 18:57:17 2019

@author: mauro
"""



def ISO_IEC_9797_padding(M):
    UnpaddedBlocks = int(len(M)/16)
    if len(M)%16 == 0:
        PaddingZeroes = 0
    else:
        PaddingZeroes = 16-(len(M)%16)
    PaddedMessage = [int.to_bytes(len(M)*8,16,'big')]
    for i in range(UnpaddedBlocks):
        PaddedMessage.append(M[16*i:16*(i+1)])
    if PaddingZeroes > 0:
        PaddedMessage.append(M[16*UnpaddedBlocks:]+b'\x00'*PaddingZeroes)
    return PaddedMessage

def AES_Insecure_Hash(M,key=b'\x00'*32,H=b'\x00'*16):
    from Crypto.Cipher import AES
    from Crypto.Util.strxor import strxor
    cipher = AES.AESCipher(key)
    PM = ISO_IEC_9797_padding(M)
    for i in range(len(PM)):
        H = cipher.encrypt(strxor(H,PM[i]))
    return H

