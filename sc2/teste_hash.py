from ctypes import sizeof
from hashlib import sha3_256
from math import ceil, floor, sqrt
import os
import random
import sys 
import base64

from numpy import int64

def extend_gcd(n, m):
    #"""https://www.youtube.com/watch?v=0oP6XLTI2tY
    #    https://pt.wikipedia.org/wiki/Algoritmo_de_Euclides_estendido
    # #https://www.geeksforgeeks.org/euclidean-algorithms-basic-and-extended/"""
    if(m == 0):
        return n, 1, 0
    value_gcd, y0, x0 = extend_gcd(m, n%m)
    y1 = x0
    x1 = y0 - n // m * x0
    return value_gcd, y1, x1

def inver_mut_mod(n, mod):
    value_gcd, y0, x0 = extend_gcd(n, mod)
    if value_gcd != 1:
        return (False, None)
    return (True, y0 % mod)

# Pre generated primes
first_primes_list = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
                     31, 37, 41, 43, 47, 53, 59, 61, 67,
                     71, 73, 79, 83, 89, 97, 101, 103,
                     107, 109, 113, 127, 131, 137, 139,
                     149, 151, 157, 163, 167, 173, 179,
                     181, 191, 193, 197, 199, 211, 223,
                     227, 229, 233, 239, 241, 251, 257,
                     263, 269, 271, 277, 281, 283, 293,
                     307, 311, 313, 317, 331, 337, 347, 349]
 
 
def nBitRandom(n):
    return random.randrange(2**(n-1)+1, 2**n - 1)
 
 
def getLowLevelPrime(n):
    '''Generate a prime candidate divisible
    by first primes'''
    while True:
        # Obtain a random number
        pc = nBitRandom(n)
 
        for i in range(2, floor(sqrt(n))):
            if pc % i == 0:
                break
            else:
                return pc
 
 
def isMillerRabinPassed(mrc):
    '''Run 20 iterations of Rabin Miller Primality test'''
    maxDivisionsByTwo = 0
    ec = mrc-1
    while ec % 2 == 0:
        ec >>= 1
        maxDivisionsByTwo += 1
    if (2**maxDivisionsByTwo * ec != mrc-1):
        return False
 
    def trialComposite(round_tester):
        if pow(round_tester, ec, mrc) == 1:
            return False
        for i in range(maxDivisionsByTwo):
            if pow(round_tester, 2**i * ec, mrc) == mrc-1:
                return False
        return True
 
    # Set number of trials here
    numberOfRabinTrials = 20
    for i in range(numberOfRabinTrials):
        round_tester = random.randrange(2, mrc)
        if pow(round_tester, ec, mrc) == 1:
            return True
        for i in range(maxDivisionsByTwo):
            if pow(round_tester, 2**i * ec, mrc) == mrc-1:
                return True
        return False
        #if trialComposite(round_tester):
        #    return False
    return True

def rsaEncrypt(texto, publicKey):
    key = publicKey[0]
    pq = publicKey[1]
    print(publicKey)
    cifrado = [pow(texto, key, pq)]
    # Return the array of bytes
    return cifrado

def rsaDecrypt(ciphertext, privateKey):
    k=len("% s" % privateKey[0])
    n=privateKey[1]
    teste = decode_oaep(i2osp(pow(c, k, n), k), k)
    return teste


def os2ip(x: bytes) -> int:
    '''Converts an octet string to a nonnegative integer'''
    return int.from_bytes(x, byteorder='big')


def i2osp(x: int, xlen: int) -> bytes:
    '''Converts a nonnegative integer to an octet string of a specified length'''
    print(x)
    return x.to_bytes(xlen, byteorder='big')


def sha_3 (m: bytes) -> bytes:
    hash = sha3_256()
    hash.update(m)
    return hash.digest()

def mgf1(seed: bytes, length: int) :
    t = b''
    hLen = 32
    if length > (hLen << 32):
        raise ValueError("mask too long")

    for i in range (0, (ceil(length/hLen))):
        c = i.to_bytes(4, 'big')
        t += sha_3(seed + c)
    
    return t[:length]

def xor (data: bytes, mask: bytes) :
    masked = b''
    ldata = len(data)
    lmask = len(mask)
    for i in range(max(ldata, lmask)):
        if i < ldata and i < lmask:
            masked += (data[i] ^ mask[i]).to_bytes(1, byteorder='big')
        elif i < ldata:
            masked += data[i].to_bytes(1, byteorder='big')
        else:
            break
    return masked

def encode_oaep (m: bytes, p: int):
    t = b''
    hLen = 32
    print(hLen)
    mLen = sys.getsizeof(m)
    print("mLen:",mLen)
    emLen = p-hLen

    PS = b'\x00' * (p - mLen - 2 * hLen - 2)
    print(PS)
    print(hLen)
    test2 = sha_3(m) + PS
    test = test2 + b'\x01'
    print(test)
    print(m)
    DB =  test + m

    seed = os.urandom(hLen)
    dbMask = mgf1(seed, k - hLen -1)
    maskedDB = xor(DB, dbMask)
    seedMask = mgf1(maskedDB, hLen)
    maskedSeed = xor(seed,seedMask)
    
    return (b'\x01'+maskedSeed + maskedDB)


def decode_oaep (em: bytes, p: int):
    print(em)
    hLen = 32
    emLen=len(em)
    lHash = sha_3(b'')
    print("em:",emLen)
    print((2*(len("% s" % 32)))-1)
    print(emLen)

    maskedSeed = em[1:hLen+1]
    maskedDB = em[hLen+1:]

    seedMask = mgf1(maskedDB, hLen)
    seed = xor(maskedSeed, seedMask)
    dbMask = mgf1(seed, p-hLen-1)
    DB=xor(maskedDB, dbMask)  
    i = hLen
    _lhash = DB[:hLen]
    print(hLen)
    print(_lhash)
    print(lHash)
    #assert lHash == _lhash
    print("len:",len(DB))
    print(DB)
    while i < len(DB):
        if DB[i] == 0:
            i += 1
            continue
        elif DB[i] == 1:
            i += 1
            break
        else:
            raise Exception()
    m = DB[i:]
    print(m)
    return m

if __name__ == '__main__':    
    print(2, "bit prime is: \n", 2)
    while True:
        n = 1024
        prime_candidate = nBitRandom(n)
        if not isMillerRabinPassed(prime_candidate):
            continue
        else:
            print(n, "bit prime is: \n", prime_candidate)
            p = prime_candidate;
            break

    while True:
        n=1024
        #n = 33333333333333333
        prime_candidate = nBitRandom(n)
        if not isMillerRabinPassed(prime_candidate):   
            continue
        else:
            print(n, "bit prime is: \n", prime_candidate)
            q = prime_candidate;
            break
    
    total = p*q
    print(p)
    print(q)
    print("total: \n", total)

    phi = (p-1)*(q-1)

    e=0
    d=0
    pode = 0

    while (True):
        e = random.randrange(10,10000000)
        d = inver_mut_mod(e,phi)
        if (d != (False, None)):
            break

    privateKey = (d[1], total)
    publicKey = (e, total)

    print("d: ", privateKey)
    print("e: ", publicKey)

    #test = rsaEncrypt("hello", publicKey)

    #print(test)

    #test2 = rsaDecrypt(rsaEncrypt("hello", publicKey),privateKey)

    #print(test2)

    print("1")
    str="hello"
    m=str.encode('ascii')
    print(m)
    print("2")
    hLen = 32
    print("3")
    print(publicKey[1])
    k=256
    print(k)
    print("4")
    print(m)
    m=encode_oaep(m, k)
    print(m)
    m=decode_oaep(m, k)
    print(m)
    print(m.decode('ascii'))
    #if(len(m) <= (k-hLen-2)):
        #print("5")
        #m=os2ip(encode_oaep(os2ip(m), k))
        #print(m)
        #print("6")
        #print(publicKey)
        #c=rsaEncrypt(m, publicKey)
        #print("7")
        #print("c:                           ", c)
        #C_big=i2osp(c[0], k)
        #print("8")
        #print(C_big)

    #if (k >= 2 * hLen + 2):
        #c=os2ip(C_big)
        #print("c:                                                  ", c)
        #print(privateKey)
        #m=rsaDecrypt(c, privateKey)
        #EM=i2osp(os2ip(m),k-1)
        #M=decode_oaep(m, k)
        #print(M)
        #print(m)









