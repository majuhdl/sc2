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
    lTexto = len(texto)
    cifrado = pow(os2ip(texto), key, pq)
    cifradoByte = (cifrado.to_bytes(publicKey[1].bit_length()//8, "big"))
    print("cifradoByte:", cifradoByte)
    # Return the array of bytes
    return cifradoByte

def rsaDecrypt(ciphertext, privateKey):
    k=privateKey[0]
    n=privateKey[1]
    decriptado = pow(os2ip(ciphertext), k, n)
    decriptadoByte = int.to_bytes(decriptado, (privateKey[1].bit_length()//8), "big")
    return decriptadoByte

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
            print(i)
            break
    #        raise Exception()
    m = DB[34:]
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
    n=rsaEncrypt(m, publicKey)
    o=rsaDecrypt(n, privateKey)
    p=decode_oaep(o, k)
    print(p)
    print(p.decode('ascii'))
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




b'\x01\xff\xab\xb4\xda\x86JT\r\x19\xe0\x85w\x00\xa4\r\x9a\xea/\x07\xc9\xf0\xca\x1bT\xbf\x8e_"\t\xb8\xb2\xd5\xa0\x11\x1c\xcd\xbcn\xa7\xba\xed,\xbd4\xcd\'|If\x94\xce\x13|\xdd\xc4Y\xcd\xeea\x88\r\x8fx@\xb0\x9cp\x97\n\x8c\xf7\xddf\xa8\xf3!$\x7fU\xea\x07\x13\t~\xef7W?"~\x1dfr&\xa7Q#\xa8\x1cN4\xcc\'\xc0\xfcHH\xee\x99t[2-\xf1g\xb9\xcc\xdfJy\xe2\xac\x17:\x8a\xd1Y(4l\xc6\x01\xe6\r"\xc4FC\xde!h-\xa6\xb4>\xe0\xc0\xb9\x9dP\xbe|\xccXZ~P\xac<`\x19\x08\x93\x9c\x9e\xda\xc6Z9\xd4m\xfb\xa5\xe5\xbb$2\\y\x7f\xd8\xf1,\x01O\x91\xa9\xe9\xca\n=\xbcI:&\x1b\xd5\x1d<\xb4FK\x9e\xb3_\x96\xf7V\xca\x9e\'\xd9\xb7$g\r\xa2 c\x91\xfe\xdf'
b"\x0c'[\xcb\xf3\xcb=tf\xd1D\x9axG\x07\x87\xa9\xa1o\xf7.x\xbcO\xe2J\x98\xf3{^==\xf2A\xb5\xb5\xd9.\xbe,\xc7\xc7\xe9\xdb\x9d\xf2 S\xb6\xd0\xba\xd4\x1c\xb4\xa5\xb6\x0e\x82=\xb3\xe17\x05\x14\xfd&\xb9\x8dH\n\xc2\xa9\x8b\x8e\x0b\x0c\xff|u\x08\x0f\x951\x96\xd7\xfb<>}\xdf\xbd?\xcd\xf1A\xfe\xc7\xb1\x80\xe2\xf54m&l\x9dWF\x9c~\x96\xd3\xa7\x13a\xbe\xd3\x19\x8e0P\xc3\xfd\x15\x07\xf8\x15f\xbfn}k}1\xe3\xec=\x1e\xd7\x97\xc7~m\x16\xa0x\xa8\x19\x81\xab\xa8O\xa6z\xc7\x954\xb6M\x9d\xac\xc8\xc3\xb1\r\xe7\xfe\x10\x99E,\xe3ZB\xa3\xdb\x83@\xa6J;\x8b\x12rh|\x88\x98\x9a\x08\xb13"
b"\x12\xd9\x046\xc7\xd5\x8c\x88\x83\xf5\xee\xcd\x01D\x10V\xc5\\'\xaaz\x86\xd0\x1c'\x9a\xf1-\xfe\x10\x8f\x03T\x98\xb5Z\xf56)T\x07)\x0bM\x877\x85\xdc\xab\x15\xce\x1f\\\xf1u\xf6\x81\x102>\x1aJ\xc7\xea\x84\x92\x1c\xd64\x1e\x83$\xf1\xa7\x05\xeb5\x9a\xfd?g\xb8L\xadd\xf5\xc1kV\x01M\xdbf\xf5\xae/\xbc\xc5i\xe5\x91w\xe5\xfd\xb5x\x08Y\x05\xb9\x0b\x0ef\x8e\xe3\x98jt\xc3\x9d\x8b\x15\xb1\xadd\xec\xec\x07h\xe7a\xfa\x8e\xfc6;\xbf8\xb9\xff\xc9\xa5\x02jDp\x16\xe2\x1c?\xbc\xe7RH\x9erL\xe6\xe1=\xbeKR\xefx=\xbc>n\xd9\xd4~\x02[\x1a`\x83\x1bh\x84!\xb4\x15,Db\xf4Qam\xf5\x99+>\xb4B\xbe\xbcL)\xd1\x8c%U\xda\x0f\xc9@\xf6\xf4\xc7\x1a\x0b,0\x80J\xfc\xdf\xd2\x87\xef_"
b'_\x8fS\x1a\x17"\xb2\xe8\t\xbd\xe6\xa4\x07D\x96\x1b\x9a5\x10o\x9f\x07 \x8b\x81!6\x03\xb1\t\xc7\xef\xb9\xa9G\xdf\x0cs>\xf7O\xb8#>\xc3_:\xcdr}\xc6\xaaB\x16\x19\t\x08<l\xc19\xfe\xbf\xb2\x82\xb6\xbe\xeb\xeb-\t\x8bXi^l\xea\\K\x1c\x9f\xba\xc8\xd7.;\xaer\xbazw0\x11\xbe~\xd1X\x1aSQ\x02PP\x89\x8a>\x0e\xd0P\xe0\x83-\xfd\xbc\x9ap\xdb\xcb\x81\x8a.\xda\tfZm\x1f\xd5\x86\x8d$\xf9\x83\r\xff\x9e\xc6\x1b\xc1\x0c\x8a\xee{\xeel\xf0\xc5\xeb\x0b\x94\x19\r\xdd \xaa\x02\xc1\x19\xc2M)\xbe=\xa9R\xb8u\x00f40\x87+\xda\x0b\xa7,\xb3\xda\xfe?\xfaNd\x8c\xf0\xa1w\x87\xe9'