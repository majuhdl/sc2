def extend_gcd(n, m):
    #"""https://www.youtube.com/watch?v=0oP6XLTI2tY
    #    https://pt.wikipedia.org/wiki/Algoritmo_de_Euclides_estendido
    # #https://www.geeksforgeeks.org/euclidean-algorithms-basic-and-extended/"""
    if(n == 0):
        return m, 1, 0
    gcd, x0, y0 = extend_gcd(m%n, n)
    y1 = x0
    x1 = y0 - m // n * x0
    return gcd, y1, x1

def inver_mut_mod(n, mod):
    value_gcd, y0, x0 = extend_gcd(n, mod)
    if value_gcd != 1:
        return (False, None)
    return (True, y0 % mod)
