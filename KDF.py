# Key Derivation functions from ISO 18033 
# Author: Peio Popov <peio@peio.org>
# License: Public Domain

from hashlib import *
from math import ceil
import random

'Try to use  Data Primitives conversions class according to ISO 18033 and PKCS#1 '
try: from DataPrimitives import DataPrimitives
except: 
    class DataPrimitives():
        def __init__(self, explain=False):
            self.explain = explain
        
        def Explain(self,explanation, *vars):
            'Print an explanation message'
            if self.explain:
                print explanation%vars
        
        def I2OSP(self, longint, length):
            from binascii import a2b_hex, b2a_hex
            ''' I2OSP(longint, length) -> bytes
        
            I2OSP converts a long integer into a string of bytes (an Octet String). 
            It is defined in the  PKCS #1 v2.1: RSA Cryptography Standard (June 14, 2002)
            '''
            hex_string = '%X' % longint
            if len( hex_string ) > 2 * length:
                    raise ValueError( 'integer %i too large to encode in %i octets' % ( longint, length ) )
            return a2b_hex(  hex_string.zfill( 2 * length ) )

cp = DataPrimitives(0)
ex = DataPrimitives(0)

'Hash function output lenght '
Hash_len = {md5:16, sha1:20, sha224:28, sha256:32,sha512:64}

def KDF1(x,l, hashfunct=sha1):
    '''KDF (x, l) that takes as input an octet string x and
    an integer l >= 0, and outputs an octet string of length l '''
    assert l >= 0, 'l should be positive integer' 
    
    k = l / float(Hash_len[hashfunct])
    ex.Explain( 'l=%d Hash_len=%d k=%f [k]=%d',l,Hash_len[hashfunct],k, int(ceil(k)) )
    k = int(ceil(k))

    l_str = ''
    for i in range(0,k):        
        l_str = l_str+hashfunct(x+cp.I2OSP(i,4)).hexdigest()
        ex.Explain('i = %d len = %d str(hex) = %s', i, len(l_str),l_str)       
    
    return l_str[:l*2]

'''Same as KDF1 
Defined in B.2.1 section of PKCS#1
IEEE P1363 Standard Specifications for Public Key Cryptography'''
def MGF1(mgfSeed, maskLen, hashfunct=sha1):
    ''' MGF1 is a Mask Generation Function based on a hash function.
    MGF1 (mgfSeed, maskLen)
    Options: Hash hash function (hLen denotes the length in octets of the hash
                 function output)
    Input: mgfSeed seed from which mask is generated, an octet string
    maskLen intended length in octets of the mask, at most 2*32 hLen
    Output: mask mask, an octet string of length maskLen
    Error: "mask too long"
    Steps:
    1. If maskLen > 2**32 hLen, output "mask too long" and stop.
    2. Let T be the empty octet string.
    3. For counter from 0 to (ceil maskLen / hLen ) - 1, do the following:
    a. Convert counter to an octet string C of length 4 octets (see Section 4.1):
    C = I2OSP (counter, 4) .
    b. Concatenate the hash of the seed mgfSeed and C to the octet string T:
    T = T || Hash (mgfSeed || C) .
    4. Output the leading maskLen octets of T as the octet string mask.
    '''
    assert len(mgfSeed) < 2**32*Hash_len[hashfunct], "mask too long"
    
    T = ''
    counter = ceil( maskLen / float(Hash_len[hashfunct]) )
        
    try: rsa = RSAPrimitives()
    except: 
        rsa = DataPrimitives()
        
    for i in range( 0, int(counter) ):
        C = rsa.I2OSP (i, 4)
        T = T + hashfunct(mgfSeed+C).hexdigest()
    
    return T[:maskLen*2]

def KDF2(x,l, hashfunct=sha1):
    '''KDF (x, l) that takes as input an octet string x and
    an integer l >= 0, and outputs an octet string of length l '''
    assert l >= 0, 'l should be positive integer'   
   
    k = l / float(Hash_len[hashfunct])
    ex.Explain( 'l=%d Hash_len=%d k=%f [k]=%d',l,Hash_len[hashfunct],k, int(ceil(k)) )
    k = int(ceil(k))

    l_str = ''
    for i in range(1,k+1):        
        l_str = l_str+hashfunct(x+cp.I2OSP(i,4)).hexdigest()
        ex.Explain('i = %d len = %d str(hex) = %s', i, len(l_str),l_str)       
    
    return l_str[:l*2]

def KDF3(x,l, hashfunct=sha1, pamt=64):
    '''KDF (x, l) that takes as input an octet string x and
    an integer l >= 0, and outputs an octet string of length l 
    pamt padding amount  >= 4'''
    assert l >= 0, 'l should be positive integer'   
    
    k = l / float(Hash_len[hashfunct])
    ex.Explain( 'l=%d Hash_len=%d k=%f [k]=%d',l,Hash_len[hashfunct],k, int(ceil(k)) )
    k = int(ceil(k))

    l_str = ''
    for i in range(0,k):        
        l_str = l_str+hashfunct(cp.I2OSP(i,pamt)+x).hexdigest()
        '''Having the counter value as the first input to the Hash function 
        removes a possible security issue compared to KDF1 and KDF2. '''
        ex.Explain('i = %d len = %d str(hex) = %s', i, len(l_str),l_str)       
    
    return l_str[:l*2]

def KDF4(x,l, hashfunct=sha1):
    
    seed = hashfunct(x).digest()
    random.seed(seed)
    
    str = ''
    for _ in range(0,l):
        str = str+chr(random.randint(0,256))
    
    return str.encode('hex')

def KDFTestVectors():

    shared = 'deadbeeffeebdaed'
    shared = shared.decode('hex')
    l = 32
    hashfunct = sha1    
    
    kdf1test = 'b0ad565b14b478cad4763856ff3016b1a93d840f87261bede7ddf0f9305a6e44'
    kdf2test = '87261bede7ddf0f9305a6e44a74e6a0846dede27f48205c6b141888742b0ce2c'
    kdf3test = '60cef67059af33f6aebce1e10188f434f80306ac0360470aeb41f81bafb35790'

    result = KDF1(shared,l, hashfunct)
    
    if result == kdf1test:
        print 'KDF1 test passed'
    else:
        print 'KDF1 test failed'
    
    result = KDF2(shared,l, hashfunct)
    
    if result == kdf2test:
        print 'KDF2 test passed'
    else:
        print 'KDF2 test failed'

    result = KDF3(shared,l, hashfunct,4)

    if result == kdf3test:
        print 'KDF3 test passed'
    else:
        print 'KDF3 test failed'

if __name__ == '__main__':
    KDFTestVectors()