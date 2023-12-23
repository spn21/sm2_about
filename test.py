from telnetlib import ENCRYPT
from Crypto.Util.number import inverse
import random
import binascii
import hashlib


# y^2=x^3+ax+b
class ECC():
    # 初始化生成Fp域椭圆曲线的相关的安全参数
    def _init_(self):
        #self.p = 0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3
        #self.a = 0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
        #self.b = 0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A
        self.h =    1           #基点倍数 
        #self.Gx = 0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D
        #self.Gy = 0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2
        #self.n = 0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7
        self.p=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF   
        self.a=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
        self.b=0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
        #系数
        self.n=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
        #基点的阶
        self.Gx=0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
        self.Gy=0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
        #基点坐标-> 生成公钥

        print("椭圆曲线参数如下:")
        print("p:%d" % self.p)
        print("a:%d" % self.a)
        print("b:%d" % self.b)
        print("Gx:%d" % self.Gx)
        print("Gy:%d" % self.Gy)

    # 生成私钥
    def pro_private(self):
        self.private_key = random.randint(1, self.n - 2)   
        return self.private_key

    # 二倍点计算
    def PP(self, x, y):
        lumda = ((3 * x**2 + self.a) * inverse(2 * y, self.p)) % self.p     #lumda 的计算使用了椭圆曲线上点 (x1, y1) 和 (x2, y2) 之间的斜率，其中 inverse(x2 - x1, self.p) 计算了 x2 - x1 在模 self.p 意义下的逆元素。
        x1 = (lumda**2 - 2 * x) % self.p    #计算点 (x1, y1) 和点 (x2, y2) 的和点 (x3, y3) 的 x y 坐标。
        y1 = (lumda * (x - x1) - y) % self.p   
        return x1, y1

    # 加法运算
    def add(self, x1, y1, x2, y2):
        if x1 == 0 and y1 == 0:         #判断是否为无穷远点
            return x2, y2
        elif x1 == x2 and y1 == y2:    #判断是否为同一点
            return self.PP(x1, y1)  
        elif x1 == x2 and y1 != y2:   #判断是否为互逆点
            return (0, 0)
        elif x1 != x2:
            lumda = ((y2 - y1) * inverse(x2 - x1, self.p)) % self.p  #lumda 的计算使用了椭圆曲线上点 (x1, y1) 和 (x2, y2) 之间的斜率，其中 inverse(x2 - x1, self.p) 计算了 x2 - x1 在模 self.p 意义下的逆元素。
            x3 = (lumda**2 - x1 - x2) % self.p  #计算点 (x1, y1) 和点 (x2, y2) 的和点 (x3, y3) 的 x 坐标。
            y3 = (lumda * (x1 - x3) - y1) % self.p  #计算点 (x1, y1) 和点 (x2, y2) 的和点 (x3, y3) 的 y 坐标。
            return x3, y3

    # k倍点计算
    def k_PP(self, x, y, k):
        k = bin(k)[2:]  #将 k 转换为二进制表示，并去除前缀 '0b'。
        x0 = 0
        y0 = 0
        for i in k:
            if y0 != 0:
                x0, y0 = self.PP(x0, y0)    #如果 y0 不等于 0，那么将点 (x0, y0) 进行二倍点计算。
            if i == '1':
                x0, y0 = self.add(x0, y0, x, y) #如果 k 的当前比特位为 1，那么将点 (x0, y0) 与点 (x, y) 进行加法运算。
        return (x0, y0)

    # 数字转16进制
    def long_to_byte(self, x):
        a = hex(x)[2:]
        if len(a) != 64:
            a = '0' * (64 - len(a)) + a
        return a

    def kdf(self, z, ml):
        t = ''
        ct = '00000001'
        if ml >= 64:  #如果目标密钥流的长度 `ml` 大于等于 64 字节，进入下面的循环。
            for i in range(ml // 64):   #128 / 64
                f = (z + ct).encode("utf8") #对输入字符串 z 进行编码，并与计数器 ct 拼接。
                s = hashlib.sha256(f).hexdigest()   #使用 SHA-256 哈希函数对拼接后的字符串进行哈希。
                t += str(s)     #将哈希值拼接到派生密钥 t 上。
                ct = hex(int(ct, 16) + 1)[2:]   #将计数器 `ct` 转换为十进制，加一后再转回十六进制，并去除前缀 '0x'。
                if len(ct) < 8:
                    ct = '0' * (8 - len(ct)) + ct   #如果计数器 `ct` 的长度小于 8，那么在前面补 0，使其长度为 8。
        if ml % 64 != 0:
            f = (z + str(ct)[2:]).encode("utf8") #如果目标密钥流的长度 `ml` 不是 64 的整数倍，那么在最后一轮循环中，我们只取前 `ml mod 64` 个字节。
            s = hashlib.sha256(f).hexdigest( )  #计算拼接字符串的哈希值+hex
            t += str(s)[2:2 + ml % 64]      #取前 ml mod 64个字节 拼接到密钥流 `t` 上。非64倍数取余
        return t
    #对输入字符串 z 进行编码，并与计数器 ct 拼接。
    #使用 SHA-256 哈希函数对拼接后的字符串进行哈希。
    #将哈希值拼接到派生密钥 t 上。
    #如果派生密钥的长度超过了哈希函数的输出长度，可以多次迭代哈希函数，以生成足够长度的密钥。


    # 加密
    def encrypt(self, M):
        k = random.randint(1, self.n - 1)
        m = binascii.b2a_hex(M.encode('utf-8')) #将消息m编码为 UTF-8 格式，然后将其转换为十六进制表示。
        m = hex(int(str(m)[2:-1], 16))[2:]
        C1 = self.k_PP(self.Gx, self.Gy, k)     #椭圆曲线点乘法
        C1 = '04' + self.long_to_byte(C1[0]) + self.long_to_byte(C1[1]) #将椭圆曲线点 C1 转换为压缩表示。
        public_key = self.k_PP(self.Gx, self.Gy, self.private_key)
        # 验证公钥是否为无穷远点
        if public_key[0] == 0 and public_key[1] == 0:   
            print("error")
            exit(0)
        x2, y2 = self.k_PP(public_key[0], public_key[1], k) #计算椭圆曲线点 (x2, y2) = [k]P。
        ml = len(m)
        print("\n输出公钥\nPx=%d" % public_key[0])
        print("Py=%d" % public_key[1])
        t = self.kdf(str(hex(x2)[2:]) + str(hex(y2)[2:]), ml)   #使用密钥派生函数kdf派生出长度为ml的密钥流t。
        if (int(t, 16) == 0):
            ENCRYPT()
        C2 = hex(int(m, 16) ^ int(t, 16))[2:]   #将消息m与密钥流t做异或运算，得到密文部分C2。
        s = (str(hex(x2)[2:]) + m + str(hex(y2)[2:])).encode("utf8")    #将点(x2, y2)、消息m及点的 y 坐标转换为 UTF-8 编码的字节串。
        C3 = hashlib.sha256(s).hexdigest()
        print("加密结果为:\n%s" % (C1 + C2 + C3))   #返回加密结果，即包含压缩表示的椭圆曲线点C1、异或运算结果C2以及哈希值C3的字符串。
        return C1 + C2 + C3

    def decrypt(self, C):
        C1 = C[2:130]   #从密文中截取出前130个字符，即椭圆曲线点的压缩表示C1
        C3 = C[-64:]    #`C3 = C[-64:]`：从密文末尾截取出最后64个字符，即哈希值C3
        lC2 = len(C) - len(C1) - len(C3) - 2
        C2 = C[130:130 + lC2]       #从密文中截取出异或运算结果C2
        x2, y2 = self.k_PP(int(C1[0:64], 16), int(C1[64:], 16), self.private_key)
        t = self.kdf(str(hex(x2)[2:]) + str(hex(y2)[2:]), lC2)  #使用密钥派生函数kdf派生出长度为lC2的密钥流t。
        m = hex(int(C2, 16) ^ int(t, 16))[2:]
        s = (str(hex(x2)[2:]) + m + str(hex(y2)[2:])).encode("utf8")
        CC3 = hashlib.sha256(s).hexdigest()
        print("解密结果为:\n04%s" % (C1 + C2 + CC3))    #使用 SHA-256 哈希函数计算上述字节串的哈希值，得到解密时计算的哈希值CC3
        if CC3 == C3:
            print("\n明文未被篡改")
            print(binascii.unhexlify(m))    #将解密得到的消息m转换为十六进制表示，并将其解码为 UTF-8 格式的字符串。
        else:
            print("\n明文已被篡改")


if __name__ == '__main__':
    print("SM2椭圆曲线加密:")
    m = ECC()
    m._init_()
    m.pro_private()    #生成私钥
    f = open("1.txt", "r")  
    M = f.read()    
    C = m.encrypt(M)    
    m.decrypt(C)
    f.close()
