from Crypto.Util.number import inverse
from hashlib import sha256
from math import ceil, log
from random import randint
from telnetlib import ENCRYPT
import random
import binascii
import hashlib

# assert b == 0

def int2bytes(x, k):
    assert 2 ** (8 * k) > x
    m = b''
    for i in range(k):
        m += (x % 256).to_bytes(1, 'big')
        x = x // 256
    
    return m

def bytes2int(m, k):
    x = 0
    for i in range(k):
        x += 2 ** (8 * i) * m[i]
    return x

def fq2bytes(a, q):
    assert 0 <= a <= q-1
    t = ceil(log(q, 2))
    l = ceil(t / 8)
    return int2bytes(a, l)

def bytes2fq(s, q):
    t = ceil(log(q, 2))
    l = ceil(t / 8)
    assert l == len(s)
    return bytes2int(s, l)

def node2bytes(xp, yp, q):
    assert (xp, yp) != (0, 0)
    l = ceil(log(q, 2) / 8)
    x1 = fq2bytes(xp, q)
    y1 = fq2bytes(yp, q)
    pc = b'\x04'
    return pc + x1 + y1

def bytes2node(s, a, b, q):
    l = ceil(log(q, 2) / 8)
    assert len(s) == 2 * l + 1
    assert s[0] == 0x04
    x1 = s[1: l + 1]
    y1 = s[l + 1:]
    xp = bytes2fq(x1, q)
    yp = bytes2fq(y1, q)
    assert yp ** 2 % q == (xp ** 3 + a * xp + b) % q
    return xp, yp

def add(x1, y1, x2, y2, p):
    if (x1, y1) == (0, 0):
        return x2, y2
    if (x2, y2) == (0, 0):
        return x1, y1
    if (x1, y1) == (x2, -y2):
        return 0, 0
    assert x1 != x2 or y1 == y2
    
    l = (y2 - y1) * inverse(x2 - x1, p) % p
    x3 = (l * l - x1 - x2) % p
    y3 = (l * (x1 - x3) - y1) % p
    return x3, y3

def double(x1, y1, a, p):
    l = (3 * x1 * x1 + a) * inverse(2 * y1, p) % p
    x3 = (l * l - 2 * x1) % p
    y3 = (l * (x1 - x3) - y1) % p
    return x3, y3

def times(x1, y1, k, a, p):
    x3, y3 = 0, 0
    while k > 0:
        if k & 1:
            x3, y3 = add(x3, y3, x1, y1, p)
        x1, y1 = double(x1, y1, a, p)
        k = k >> 1
    
    return x3, y3

def kdf(z, klen):
    v = 256
    assert klen < (2 ** 32 - 1) * v
    ct = 0x00000001
    k = b''
    for i in range(1, ceil(klen / v)):
        # hai = sm3(z + ct.to_bytes(32, 'big'))
        hai = sha256(z + ct.to_bytes(32, 'big')).digest()
        k += hai
        ct = ct + 1
    
    hai = sha256(z + ct.to_bytes(32, 'big')).digest()
    if klen % v != 0:
        hai = hai[:klen % v]
    k += hai
    return k

def dec(c, a, b, db, p):
    len1 = ceil(log(p, 2) / 8) * 2 + 1
    #print("len1:",len1)
    #print("lenc",len(c))
    #klen = len(c) - len1 - 32
    #print("klen:",klen)
    c1 = c[:len1]
    c2 = c[len1: -32]
    c3 = c[-32:]
    x1, y1 = bytes2node(c1, a, b, p)
    # xs, ys = times(x1, y1, h, a, p)
    x2, y2 = times(x1, y1, db, a, p)
    x2 = fq2bytes(x2, p)
    y2 = fq2bytes(y2, p)

    klen = len(c2)
    t = kdf(x2 + y2, klen)
    # if t == 0
    #c2 = c[len1: -32]
    m = bytes(i ^ j for (i, j) in zip(c2, t))
    #print("m1 : " ,m)
    # u = sm3(x2 + m + y2)
    u = sha256(x2 + m + y2).digest()
    #assert u == c[-32:]
    m_str = ''.join([chr(i) for i in m])
    #print("u:", u)
    #print("c[-32:]", c[-32:])
    #print("message:",m_str)
    #assert u == c[-32:]
    return m_str[::-1]
    #assert u == c3
    #return m.decode('utf-8', errors='ignore') 

def read_file_with_conversion(filename):
    with open(filename, 'rb') as f:
        content=f.read()
        ascii_content = [byte for byte in content]
        return ascii_content 

def main():
    p = 0xbdb6f4fe3e8b1d9e0da8c0d46f4c318cefe4afe3b6b8551f
    a = 0xbb8e5e8fbc115e139fe6a814fe48aaa6f0ada1aa5df91985
    b = 0x1854bebdc31b21b7aefc80ab0ecd10d5b1b3308e6dbf11c1
    print('椭圆曲线参数')
    print('p:', p)
    print('a:', a)
    print('b:', b)
    # assert b == 0
    xg = 0x4ad5f7048de709ad51236de65e4d4b482c836dc6e4106640
    yg = 0x02bb3a02d4aaadacae24817a4ca3a1b014b5270432db27d2
    print('公钥')
    print('xg:', xg)
    print('yg:', yg)
    n = 0xbdb6f4fe3e8b1d9e0da8c0d40fc962195dfae76f56564677
    m = bytes(read_file_with_conversion('3.txt'))
    print("m:", m)

    klen = len(m)
    #print("bit length of m",klen)
    #m = int2bytes(m, klen)
    db = randint(1, n - 1)
    print('私钥')
    print('d:', db)
    xb, yb = times(xg, yg, db, a, p)
    # db = 0x58892b807074f53fbf67288a1dfaa1ac313455fe60355afd
    # xb = 0x79f0a9547ac6d100531508b30d30a56536bcfc8149f4af4a
    # yb = 0xae38f2d8890838df9c19935a65a8bcc8994bc7924672f912
    k = randint(1, n)
    # k = 0x384f30353073aeece7a1654330a96204d37982a3e15b2cb5
    x1, y1 = times(xg, yg, k, a, p)
    c1 = node2bytes(x1, y1, p)
    # xs, ys = times(xb, yb, h, a, p)
    # assert (xs, ys) == (0, 0)
    x2, y2 = times(xb, yb, k, a, p)
    x2 = fq2bytes(x2, p)
    y2 = fq2bytes(y2, p)
    t = kdf(x2 + y2, klen)
    c2 = bytes(i ^ j for (i, j) in zip(m, t))
    # c3 = sm3(x2 + m + y2)
    c3 = sha256(x2 + m + y2).digest()
    c = c1 + c2 + c3
    #print("C:", c)
    print(c.hex())

    #print("bit length of m",klen)
    
    print("m:", dec(c, a, b, db, p)[::-1])

    # 在 main 函数中调用加密和解密过程
    encrypted_message = dec(c, a, b, db, p)[::-1]
    print("加密结果为:", encrypted_message)

    if encrypted_message == m.decode('utf-8'):
        print("\n明文未被篡改")
    else:
        print("\n明文已被篡改")

    

main()
    
    
