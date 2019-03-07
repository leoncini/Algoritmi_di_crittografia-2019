#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Mar  4 20:09:07 2019

@author: Mauro Leoncini
"""

from caesar import CHSET, decrypt

ciphertext = "\nxàtvvtésìfwp\n\n!fòì''t\nfrìéfxàf tééìfsxfòìxifxàf tééìfsxfrwxf pfsì,tf xfpééìst\n(ifpààpfuxétifìvé.éìfstxfuxàxfrwtfyhzhf\nì:àxévfwpfxérìèxérxp'ìfpf't  t\ntfspààpfò\nxèpfòpvxépfstàfò\nxèìf,ìà.ètifxàfrìèx'p'ìf xf)f'\nì,p'ìfsxfu\nìé'tifrìètfétààtfuxpqtftfétxfàpqx\nxé'xif'\ntf,xtjfèpé'tét\ntfàpf rtà'pfup''pfétàf'\nps.\n\ntféìèxfsxfà.ìvwxftfòt\n ìépvvxkf\nx'ì\nép\ntfpàféìètfì\nxvxépàtfìfòt\nrì\n\nt\ntf.épf't\n?pf,xpf rtvàxtésìf.éféìètfstàf'.''ìfé.ì,ìhfpàr.éxft tèòxjeeétàfrp ìfsxfpàq. f xàté'tf)fòp\n ìf .qx'ìfrwxp\nìfrwtfpfò\nxì\nxfét  .épfstààtf'\ntf '\npstft\npfsxfòt\nf afù.tààpfvx. 'phfpàfèìèté'ìfsxf rtvàxt\ntfxàfrìvéìètfx'pàxpéìifrwtft\npfòp\n ìfpstv.p'ìfòt\nf.éfèpvìfqx??p\n\nìfèpfpérwtf ìàtéétftfrpòprtfsxf'tét\ntfxéf ìvvt?xìétfxf .ìxfétèxrxiféìéf xf pòt,pfù.tààìfrwtfyhzhf\nì:àxévfp,\ntqqtfòìxfsxrwxp\np'ìjfgàìfxèèpvxép,ìfrìètf.éfèpvìfqtét,ìàìif tèò\ntfxéfèì,xèté'ìifrwtfèì\nèì\npfrìé'xé.pèté'tf'\npf aftf agkfs.èqàtsì\ntifxéfxévàt tif)fxàféìètfp\nrpxrìfsxfq.èqàtqttifxàfrpàpq\nìéthfpà'\nìfrwtfg xàté'tglftòò.\ntifàpf 'ì\nxpfsxèì '\nt\n(frwtfò\nìò\nxìfxf xàté?xfsxfpàq. fwpééìfp,.'ìf.éf\n.ìàìfst't\nèxépé'tiftfpérwtfétvp'x,ìifétààtfp,,té'.\ntfsxfwp\n\n!fòì''t\nftfétààpfàì''pfrìé'\nìfàpfèpvxpfì r.\npheeàpf rtà'pfsxf\nx'ì\nép\ntfpàféìètfì\nxvxépàtfsxf.éìfstxfò\nì'pvìéx 'xfò\nxérxòpàxfstààpf pvpf)f 'p'pfup''pfétàfrp ìfsxfèxét\n,pfèrvìépvpààifàpfr.xfpàètéìfpòòp\nté'tf t,t\nx'(f,ìàt,pft  t\ntft ò\nt  pifétààgtsx?xìétfx'pàxpépifspàf\nìrrxì ìfpsp''pèté'ìfèrv\npééx'heeàpf't\n?pf,xpf)fù.tààpfrwtf)f 'p'pfètéìfu\ntù.té'p'phfù.tààtfòìrwtf,ìà'tifòt\ncif xf)f\nx,tàp'pfò\nt?xì phf)f 'p'pfòt\nrì\n pfétààpf rtà'pfstàféìètfstààtfù.p''\nìfrp tfxéfr.xf xfsx,xsìéìfvàxf '.sté'xfsxfwìv:p\n' jfxfàì\nìféìèxfx'pàxpéxf tv.x,péìf ìàìfxéfòp\n'tfxfrì\n\nx òìésté'xfxévàt xjfpvvx.évt,péìifòt\nft tèòxìifxésxrp?xìéxfsxfrìàì\ntfstàf'.''ìfp  té'xfétààgì\nxvxépàthf xf)frì bfstrx ìfòt\nfv\nxuìésì\nìif'p  ìu\np  ìifrì\n,ìét\nìftf t\nòt,t\nstheeìvéxf rtà'pf)f 'p'pfpfà.évìfòìést\np'pif'ì\nèté'p'pif ìuut\n'phfàpfrìéì rté?pfstààgxé't\npfìòt\npfwpf\nxrwxt 'ìfsxf\nx'ìrrp\ntfpérwtfxàfàt  xrìfg'tréxrìgfstvàxfxérpé't xèxfxé,té'p'ìfspfyhzhf\nì:àxévkfàpf'p  ìéìèt'\nxpfstààtfr\ntp'.\ntfupé'p 'xrwtfnxfguìààt''xgf ìéìf'ì\nép'xfpft  t\ntfxfgvìqàxégfrìètfétààgì\nxvxépàtokfrt\n'tf. pé?tifrìètfxféìèxftfxfrìvéìèxfrwtfxérìèxérxpéìfrìéfàpf 't  pfxéx?xpàtheeìvéxfst''pvàxìf)f 'p'ìf\nx,x 'ìftfrìé xst\np'ìfrìéfp''té?xìétfòt\nrwafàpfé.ì,pftsx?xìétfuì  tfòxdf,xrxépfpààìf òx\nx'ìfstààgì\nxvxépàtifétàf\nx òt''ìfsxfù.tààìfrwtf)fì\nèpxfsx,té'p'ìf.éfv\npéstfràp  xrìfstxféì '\nxf'tèòxhe"

def frequencies(text, alphabet):
    '''Given some text, computes the frequencies
       of the characters included in the alphabet.
       Returns a dictionary.
    '''
    D = {}
    for c in text:
        if c not in alphabet:
            continue
        if not D.get(c,False):
            D[c] = 1
        else:
            D[c] += 1
    return D

def sortfreq(D):
    '''Return a list of character/frequency pairs sorted by
       decreasing frequency.
    '''
    return sorted([x for x in D.items()],key=lambda x: x[1],\
                   reverse=True)

def FreqAttack(ciphertext, RefText, NumGuess=5):
    '''Given a ciphertext and a reference text for the language
       (the one used for the plaintext, supposedly....), 
       returns a list of possible keys. Uses frequency analysis.
    '''
    global CHSET
    with open(RefText,'r') as f:
        text = f.read().lower()
    ReferenceFreq = sortfreq(frequencies(text, CHSET))
    counter = sortfreq(\
                       frequencies(ciphertext,\
                       "".join([x[0] for x in ReferenceFreq]))\
                       )
    ic = CHSET.find(counter[0][0])
    # ic is the index, in the reference alphabet, of the most
    # frequent symbol occurring on the ciphertext
    for i, c in enumerate(ReferenceFreq[:NumGuess]):
        # The working hypothesis here is that the hidden identity 
        # of the most frequent symbol in the ciphertext corresponds
        # to one of the top NumGuesses in the reference text
        ir = CHSET.find(c[0])
        key = (ic-ir)%len(CHSET) # Compute the shift 
        print("Guess {}: {}".format(i+1,key))
        