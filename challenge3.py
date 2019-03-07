#!/usr/bin/env python3
#-*-coding:utf-8-*-
"""
CreatedonTueMar518:10:482019

@author:Mauro Leoncini
"""

from challenge2 import sortfreq

alphabet = 'abcdefghijklmnopqrstuvwxyz'

ciphertext = "53‡‡†305))6∗;4826)4‡.)4‡);806∗;48†8"+\
             "¶60))85;;]8∗;:‡∗8†83(88)5∗†;46(;88∗96"+\
             "∗?;8)∗‡(;485);5∗†2:∗‡(;4956∗2(5∗−4)8"+\
             "¶8∗;4069285);)6†8)4‡‡;1(‡9;48081;8:8‡"+\
             "1;48†85;4)485†528806∗81(‡9;48;(88;4"+\
             "(‡?34;48)4‡;161;:188;‡?;"

ctalphabet = '‡†305)6∗;482.¶]:(9?−1'

def GroupFreq(text, alphabet, g=2):
    '''Returns a dictionary with the frequencies of all the
       groups of g letters belonging to the alphabet
    '''
    D = {}
    l = len(text)
    i = 0
    while i < l-g+1:
        j = 0
        while j<g and text[i+j] in alphabet:
            j += 1
        if j == g:
            if not D.get(text[i:i+g],False):
                D[text[i:i+g]] = 1
            else:
                D[text[i:i+g]] += 1
            i += 1
        else:
            i = i+j+1
    return D

def LangStatistics(alphabet, RefText):
    '''Returns sorted lists of all the occurrences in the RefText
       of single letters, and groups of three and four letters.
       RefText must be a string. Symbols not in alphabet
       will be ignored.
    '''
    OneFreq = sortfreq(GroupFreq(RefText, alphabet, g=1))
    ThreeFreq = sortfreq(GroupFreq(RefText, alphabet, g=3))
    FourFreq = sortfreq(GroupFreq(RefText, alphabet, g=4))
    return OneFreq,ThreeFreq,FourFreq
    
