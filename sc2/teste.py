from math import floor, sqrt
import random 

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
    k=privateKey[0][1]
    n=privateKey[1]
    decriptado = pow(os2ip(ciphertext), k, n)
    decriptadoByte = int.to_bytes(decriptado, (privateKey[1].bit_length()//8), "big")
    return decriptadoByte

def os2ip(x: bytes) -> int:
    '''Converts an octet string to a nonnegative integer'''
    return int.from_bytes(x, byteorder='big')

 
 
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

    privateKey = (d, total)
    publicKey = (e, total)

    print("d: ", privateKey)
    print("e: ", publicKey)

    test = rsaEncrypt('hello'.encode('ascii'), publicKey)

    print("tesy:",test)

    test2 = rsaDecrypt(test,privateKey)

    print(test2.decode('ascii'))